package com.darkedges.oid4vci.spring.boot.autoconfigure.tenancy;

import com.darkedges.oid4vc.tenancy.TenantContext;
import com.darkedges.oid4vc.tenancy.tenantapi.TenantCallers;
import com.darkedges.oid4vci.core.metadata.CredentialIssuerMetadata;
import com.darkedges.oid4vci.core.offer.CredentialOffer;
import com.darkedges.oid4vci.core.offer.CredentialOfferWriter;
import com.darkedges.oid4vci.core.offer.Grants;
import com.darkedges.oid4vci.core.offer.PreAuthorizedCodeGrant;
import com.darkedges.oid4vci.issuer.IssuanceConstraints;
import com.darkedges.oid4vci.issuer.IssuerContext;
import com.darkedges.oid4vci.issuer.IssuerMetadataTemplates;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeService;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeSession;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.darkedges.oid4vci.issuer.TenantOfferReferences;
import com.darkedges.oid4vci.issuer.web.IssuerContextResolver;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The tenant API for credential offers: the tenant's own backend creates a pre-authorized offer for one of its people, and can withdraw it.
 * <pre>
 * POST   /tenant-api/v1/offers                 { credentialConfigurationIds, claims, reference, holderKeyThumbprint?, expiresIn? }
 * DELETE /tenant-api/v1/offers/{reference}
 * </pre>
 * Called as the tenant, with a token from an application of the tenant's AuthStack environment that the tenant lists
 * ({@link TenantCallers}). An offer's {@code reference} is the tenant's own (a hire, say): creating an offer again for a live reference
 * returns the same offer, and the {@code IssuanceHook} is told it when the credentials are issued. {@code holderKeyThumbprint} pins the
 * key the wallet must prove (RFC 7638).
 */
@RestController
@RequestMapping(path = "/tenant-api/v1/offers", produces = MediaType.APPLICATION_JSON_VALUE)
public class TenantOfferController {

    private static final Logger audit = LoggerFactory.getLogger("oid4vci.tenant-api.audit");
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();
    static final Pattern REFERENCE = Pattern.compile("[A-Za-z0-9._:-]{1,128}");
    static final Pattern THUMBPRINT = Pattern.compile("[A-Za-z0-9_-]{43}");
    static final Pattern CLAIM_NAME = Pattern.compile("[A-Za-z0-9_.-]{1,64}");
    static final int MAX_CLAIMS = 50, MAX_CLAIM_LENGTH = 1024;
    static final Duration DEFAULT_LIFETIME = Duration.ofMinutes(10), MIN_LIFETIME = Duration.ofMinutes(1), MAX_LIFETIME = Duration.ofHours(1);

    private final TenantCallers callers;
    private final IssuerContextResolver issuers;
    private final IssuerMetadataTemplates templates;
    private final PreAuthorizedCodeService codes;
    private final PreAuthorizedCodeStore codeStore;
    private final TenantOfferReferences references;
    private final Clock clock;

    public TenantOfferController(TenantCallers callers, IssuerContextResolver issuers, IssuerMetadataTemplates templates,
                                 PreAuthorizedCodeService codes, PreAuthorizedCodeStore codeStore, TenantOfferReferences references, Clock clock) {
        this.callers = callers;
        this.issuers = issuers;
        this.templates = templates;
        this.codes = codes;
        this.codeStore = codeStore;
        this.references = references;
        this.clock = clock;
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> create(@RequestHeader(name = "Authorization", required = false) String authorization,
                                         @RequestBody String rawBody, HttpServletRequest request) {
        Optional<ResponseEntity<String>> refused = refuseCaller(authorization, request);
        if (refused.isPresent()) return refused.get();
        IssuerContext context = issuers.resolve(request);
        CredentialIssuerMetadata metadata = templates.credentialIssuer(context).resolve(context.issuerIdentifier());

        JsonNode body;
        try {
            body = MAPPER.readTree(rawBody);
        } catch (Exception e) {
            return error(400, "invalid_request", "The body is not JSON");
        }
        if (body == null || !body.isObject()) return error(400, "invalid_request", "The body must be a JSON object");

        String reference = body.path("reference").asText("");
        if (!REFERENCE.matcher(reference).matches()) return error(400, "invalid_request", "reference is 1 to 128 of A-Z a-z 0-9 . _ : -");

        List<String> configurationIds = new ArrayList<>();
        for (JsonNode id : body.path("credentialConfigurationIds")) configurationIds.add(id.asText());
        if (configurationIds.isEmpty()) return error(400, "invalid_request", "credentialConfigurationIds names at least one configuration");
        for (String id : configurationIds) {
            if (!metadata.credentialConfigurationsSupported().containsKey(id)) {
                return error(400, "invalid_request", "This issuer has no credential configuration \"" + id + "\"");
            }
        }

        Map<String, String> claims = new LinkedHashMap<>();
        JsonNode claimsNode = body.path("claims");
        if (!claimsNode.isMissingNode() && !claimsNode.isObject()) return error(400, "invalid_request", "claims is an object of strings");
        if (claimsNode.size() > MAX_CLAIMS) return error(400, "invalid_request", "At most " + MAX_CLAIMS + " claims");
        for (Map.Entry<String, JsonNode> claim : claimsNode.properties()) {
            String name = claim.getKey();
            if (!CLAIM_NAME.matcher(name).matches() || IssuanceConstraints.isReserved(name)) {
                return error(400, "invalid_request", "\"" + name + "\" can't be a claim name");
            }
            if (!claim.getValue().isTextual() || claim.getValue().asText().length() > MAX_CLAIM_LENGTH) {
                return error(400, "invalid_request", "Claim \"" + name + "\" is a string of at most " + MAX_CLAIM_LENGTH + " characters");
            }
            claims.put(name, claim.getValue().asText());
        }

        Optional<String> holder = Optional.empty();
        if (body.hasNonNull("holderKeyThumbprint")) {
            String thumbprint = body.get("holderKeyThumbprint").asText();
            if (!THUMBPRINT.matcher(thumbprint).matches()) return error(400, "invalid_request", "holderKeyThumbprint is an RFC 7638 SHA-256 thumbprint (base64url)");
            holder = Optional.of(thumbprint);
        }

        Duration lifetime = DEFAULT_LIFETIME;
        if (body.has("expiresIn")) {
            if (!body.get("expiresIn").canConvertToLong()) return error(400, "invalid_request", "expiresIn is a number of seconds");
            lifetime = Duration.ofSeconds(body.get("expiresIn").asLong());
            if (lifetime.compareTo(MIN_LIFETIME) < 0 || lifetime.compareTo(MAX_LIFETIME) > 0) {
                return error(400, "invalid_request", "expiresIn is between 60 and 3600 seconds");
            }
        }

        String scopedReference = context.scope(reference);
        Optional<TenantOfferReferences.OfferReference> live = references.find(scopedReference);
        if (live.isPresent()) return offer(200, live.get().offerJson(), live.get().expiresAt());

        Instant expiresAt = clock.instant().plus(lifetime);
        String code = randomCode();
        codes.offer(context, code, new PreAuthorizedCodeSession(configurationIds, Optional.empty(),
                IssuanceConstraints.withConstraints(claims, Optional.of(reference), holder), expiresAt));
        String offerJson = CredentialOfferWriter.write(new CredentialOffer(metadata.credentialIssuer(), configurationIds,
                Optional.of(new Grants(Optional.empty(), Optional.of(new PreAuthorizedCodeGrant(code, Optional.empty(), Optional.empty())))))).toString();
        references.save(scopedReference, new TenantOfferReferences.OfferReference(context.scope(code), offerJson, expiresAt));
        audit.info("tenant {} offered {} for reference {}", context.tenantId(), configurationIds, reference);
        return offer(201, offerJson, expiresAt);
    }

    @DeleteMapping("/{reference}")
    public ResponseEntity<String> withdraw(@RequestHeader(name = "Authorization", required = false) String authorization,
                                           @PathVariable String reference, HttpServletRequest request) {
        Optional<ResponseEntity<String>> refused = refuseCaller(authorization, request);
        if (refused.isPresent()) return refused.get();
        if (!REFERENCE.matcher(reference).matches()) return error(400, "invalid_request", "Not a reference");
        IssuerContext context = issuers.resolve(request);
        String scopedReference = context.scope(reference);
        references.find(scopedReference).ifPresent(live -> codeStore.consume(live.scopedCode()));
        references.remove(scopedReference);
        audit.info("tenant {} withdrew the offer for reference {}", context.tenantId(), reference);
        return ResponseEntity.noContent().build();
    }

    /** Empty when the caller may act for the request's tenant; otherwise the answer to give. */
    private Optional<ResponseEntity<String>> refuseCaller(String authorization, HttpServletRequest request) {
        Optional<TenantContext> tenant = TenantContext.from(request);
        if (tenant.isEmpty()) return Optional.of(error(404, "not_found", "No tenant is served here"));
        String token = authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7) ? authorization.substring(7).trim() : null;
        try {
            callers.verify(token, tenant.get().tenant());
            return Optional.empty();
        } catch (TenantCallers.TenantCallerException e) {
            return Optional.of(error(e.status(), e.error(), e.getMessage()));
        }
    }

    private static ResponseEntity<String> offer(int status, String offerJson, Instant expiresAt) {
        ObjectNode body = MAPPER.createObjectNode();
        try {
            body.set("offer", MAPPER.readTree(offerJson));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        body.put("offerUri", "openid-credential-offer://?credential_offer=" + URLEncoder.encode(offerJson, StandardCharsets.UTF_8));
        body.put("expiresAt", expiresAt.toString());
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore()).contentType(MediaType.APPLICATION_JSON).body(body.toString());
    }

    private static ResponseEntity<String> error(int status, String code, String description) {
        ObjectNode body = MAPPER.createObjectNode().put("error", code).put("error_description", description);
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore()).contentType(MediaType.APPLICATION_JSON).body(body.toString());
    }

    private static String randomCode() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
