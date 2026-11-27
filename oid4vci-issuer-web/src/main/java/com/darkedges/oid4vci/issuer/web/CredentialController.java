package com.darkedges.oid4vci.issuer.web;

import com.darkedges.oid4vci.issuer.CredentialIssuanceServiceResolver;
import com.darkedges.oid4vci.issuer.IssuerMetadataTemplates;
import com.darkedges.oid4vci.issuer.IssuerContext;
import com.darkedges.oid4vci.issuer.IssuanceConstraints;
import com.darkedges.oid4vci.issuer.IssuanceHook;
import com.darkedges.oid4vci.core.credential.CredentialRequest;
import com.darkedges.oid4vci.core.credential.CredentialRequestReader;
import com.darkedges.oid4vci.core.credential.CredentialResponse;
import com.darkedges.oid4vci.core.credential.CredentialResponseWriter;
import com.darkedges.oid4vci.core.credential.IssuedCredential;
import com.darkedges.oid4vci.core.credential.Proofs;
import com.darkedges.oid4vci.core.error.Oid4vciErrorCode;
import com.darkedges.oid4vci.core.error.Oid4vciException;
import com.darkedges.oid4vci.core.metadata.BatchCredentialIssuance;
import com.darkedges.oid4vci.core.metadata.CredentialConfiguration;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadata;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadataTemplate;
import com.darkedges.oid4vci.issuer.CredentialIssuanceService;
import com.darkedges.oid4vci.issuer.IssuedAccessTokenClaimsStore;
import com.darkedges.oid4vci.issuer.ProofOfPossessionValidator;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.Clock;
import com.nimbusds.jose.jwk.ECKey;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The Credential Endpoint (OID4VCI 1.0, Section 8) — the one endpoint in this project that's actually
 * behind {@code oauth2ResourceServer()}: the {@link Jwt} principal is Spring Security's own, already
 * signature/expiry-verified by the app's configured {@code JwtDecoder} before this method ever runs (see
 * the project README for why that's the right tool here rather than a custom {@code AuthenticationProvider}).
 * A DPoP-bound access token (one minted with a {@code cnf.jkt} claim — see {@code TokenController}) is
 * also fully handled before this method runs: Spring Security 7.1's native {@code .dPoP(...)}
 * resource-server support (wired in the consuming app's {@code SecurityConfig}) verifies the request's
 * {@code DPoP} proof against the token's {@code cnf.jkt} and rejects a mismatched/missing one itself —
 * confirmed live that a hand-rolled equivalent check in this controller never even ran, since
 * {@code BearerTokenAuthenticationFilter} already refuses a {@code cnf}-bearing JWT presented without a
 * matching DPoP proof before dispatch. This handler's own job starts one layer in: read the authorized
 * {@code credential_configuration_ids} off the token, verify each proof of possession the request
 * carries — more than one only if the Issuer Metadata advertises {@code batch_credential_issuance} (see
 * {@code BatchCredentialIssuance}), one Credential minted per proof, all against the same claim values —
 * look up the claim values persisted at token mint time ({@link TokenController}), and dispatch to the
 * matching {@link CredentialIssuanceService}. Returns a pre-serialized {@code String} — see
 * {@link IssuerMetadataController}'s Javadoc for why. The request body is read the same way, for the same
 * reason: a Jackson-2 {@code JsonNode} isn't something the Jackson-3 message converter Spring Boot 4.1
 * also registers knows how to construct, so the raw body is read as a {@code String} and parsed manually
 * with this module's own Jackson-2 {@link ObjectMapper} rather than via {@code @RequestBody JsonNode}
 * directly (confirmed live: this was the second half of the same Jackson 2/3 coexistence issue — the
 * write side failed first, then this).
 */
@RestController
public class CredentialController {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final IssuerMetadataTemplates templates;
    private final ProofOfPossessionValidator proofValidator;
    private final IssuedAccessTokenClaimsStore claimsStore;
    private final CredentialIssuanceServiceResolver issuanceServices;
    private final IssuerContextResolver issuers;
    private final Clock clock;
    private IssuanceHook issuanceHook = IssuanceHook.NONE;

    public CredentialController(
            CredentialIssuerMetadataTemplate template, ProofOfPossessionValidator proofValidator,
            IssuedAccessTokenClaimsStore claimsStore, Map<CredentialFormat, CredentialIssuanceService> issuanceServices) {
        this(template, proofValidator, claimsStore, issuanceServices, Clock.systemUTC());
    }

    public CredentialController(
            CredentialIssuerMetadataTemplate template, ProofOfPossessionValidator proofValidator,
            IssuedAccessTokenClaimsStore claimsStore, Map<CredentialFormat, CredentialIssuanceService> issuanceServices,
            Clock clock) {
        this(IssuerMetadataTemplates.fixed(template, null), proofValidator, claimsStore,
                CredentialIssuanceServiceResolver.of(issuanceServices), IssuerContextResolver.SINGLE_TENANT, clock);
    }

    public CredentialController(
            IssuerMetadataTemplates templates, ProofOfPossessionValidator proofValidator, IssuedAccessTokenClaimsStore claimsStore,
            CredentialIssuanceServiceResolver issuanceServices, IssuerContextResolver issuers, Clock clock) {
        this.templates = templates;
        this.proofValidator = proofValidator;
        this.claimsStore = claimsStore;
        this.issuanceServices = issuanceServices;
        this.issuers = issuers;
        this.clock = clock;
    }

    /** The tenant's say in issuing a credential of an offer that carries a reference ({@link IssuanceHook}). None by default. */
    public void setIssuanceHook(IssuanceHook issuanceHook) {
        this.issuanceHook = issuanceHook == null ? IssuanceHook.NONE : issuanceHook;
    }

    @PostMapping(value = "${oid4vci.issuer.credential-endpoint-path:/credential}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> credential(
            @AuthenticationPrincipal Jwt accessToken, @RequestBody String rawBody, HttpServletRequest servletRequest) {
        IssuerContext context = issuers.resolve(servletRequest);
        CredentialIssuerMetadata metadata = templates.credentialIssuer(context).resolve(context.issuerIdentifier());
        JsonNode body;
        try {
            body = MAPPER.readTree(rawBody);
        } catch (Exception e) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_REQUEST, "request body is not valid JSON", e);
        }
        CredentialRequest request;
        try {
            request = CredentialRequestReader.read(body);
        } catch (IllegalArgumentException e) {
            // Neither or both of credential_configuration_id / credential_identifier: the wallet's request is malformed
            // (OID4VCI 1.0, 8.3.1.2), not an issuer failure, so a 400, never a 500.
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_CREDENTIAL_REQUEST, e.getMessage(), e);
        }

        String configurationId = request.credentialConfigurationId()
                .orElseThrow(() -> new Oid4vciException(Oid4vciErrorCode.INVALID_REQUEST,
                        "credential_identifier is not supported in this phase; use credential_configuration_id"));

        List<String> authorizedConfigurationIds = accessToken.getClaimAsStringList("credential_configuration_ids");
        if (authorizedConfigurationIds == null || !authorizedConfigurationIds.contains(configurationId)) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_REQUEST,
                    "access token is not authorized for credential_configuration_id: " + configurationId);
        }

        CredentialConfiguration configuration = metadata.credentialConfigurationsSupported().get(configurationId);
        if (configuration == null) {
            throw new Oid4vciException(Oid4vciErrorCode.UNSUPPORTED_CREDENTIAL_TYPE,
                    "unknown credential_configuration_id: " + configurationId);
        }

        List<String> proofJwts = request.proofs().flatMap(Proofs::jwt).orElse(List.of());
        if (proofJwts.isEmpty()) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_PROOF, "proofs.jwt is required");
        }
        int maxBatchSize = metadata.batchCredentialIssuance().map(BatchCredentialIssuance::batchSize).orElse(1);
        if (proofJwts.size() > maxBatchSize) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_CREDENTIAL_REQUEST,
                    "proofs.jwt has " + proofJwts.size() + " entries, exceeding this issuer's batch_size of " + maxBatchSize);
        }

        // Expiry is enforced by the store, so an expired entry is indistinguishable from an absent
        // one here -- which is right: both mean this token authorizes nothing. The token's own exp is
        // checked by the resource server long before this point; this guards the claims themselves,
        // which for a real issuer are somebody's passport details and should not outlive their use.
        // Scoped to this tenant: a token's subject is only known to the tenant that issued it.
        Map<String, String> stored = context.scopeIfValid(accessToken.getSubject())
                .flatMap(subject -> claimsStore.find(subject, clock.instant()))
                .orElseThrow(() -> new Oid4vciException(Oid4vciErrorCode.INVALID_TOKEN, "no claims on file for this access token"));

        CredentialIssuanceService issuanceService = issuanceServices.resolve(context, configuration.format()).orElse(null);
        if (issuanceService == null) {
            throw new Oid4vciException(Oid4vciErrorCode.UNSUPPORTED_CREDENTIAL_FORMAT,
                    "no issuance service registered for format: " + configuration.format());
        }

        // The offer's constraints travel with its claims (IssuanceConstraints), and never reach the credential.
        Map<String, String> claims = IssuanceConstraints.credentialClaims(stored);
        java.util.Optional<String> reference = IssuanceConstraints.reference(stored);
        java.util.Optional<String> pinnedHolder = IssuanceConstraints.holderKeyThumbprint(stored);

        // Every proof is checked, and the tenant asked about each, before anything is signed: a batch is issued whole or not at all.
        List<ECKey> holderKeys = new ArrayList<>();
        List<IssuanceHook.Attempt> attempts = new ArrayList<>();
        for (String proofJwt : proofJwts) {
            ECKey holderKey = proofValidator.verify(context, proofJwt, metadata.credentialIssuer().toString());
            String thumbprint = thumbprint(holderKey);
            if (pinnedHolder.isPresent() && !pinnedHolder.get().equals(thumbprint)) {
                throw new Oid4vciException(Oid4vciErrorCode.INVALID_PROOF, "the proof's key is not the key this offer is bound to");
            }
            IssuanceHook.Attempt attempt = reference
                    .map(r -> new IssuanceHook.Attempt(r, configurationId, configuration.format().identifier(), thumbprint))
                    .orElse(null);
            if (attempt != null) issuanceHook.authorize(context, attempt);
            holderKeys.add(holderKey);
            attempts.add(attempt);
        }
        List<IssuedCredential> issued = new ArrayList<>();
        for (int i = 0; i < holderKeys.size(); i++) {
            String credential = issuanceService.issue(context, configuration, claims, holderKeys.get(i));
            issued.add(new IssuedCredential(credential));
            if (attempts.get(i) != null) issuanceHook.issued(context, attempts.get(i), credential);
        }

        CredentialResponse response = new CredentialResponse(Optional.of(issued), Optional.empty());
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(CredentialResponseWriter.write(response).toString());
    }

    private static String thumbprint(ECKey key) {
        try {
            return key.computeThumbprint().toString();
        } catch (com.nimbusds.jose.JOSEException e) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_PROOF, "the proof's key has no thumbprint", e);
        }
    }
}
