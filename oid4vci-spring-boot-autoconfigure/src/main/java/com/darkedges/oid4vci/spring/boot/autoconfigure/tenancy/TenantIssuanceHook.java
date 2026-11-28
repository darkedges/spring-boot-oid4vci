package com.darkedges.oid4vci.spring.boot.autoconfigure.tenancy;

import com.darkedges.oid4vc.tenancy.Tenant;
import com.darkedges.oid4vc.tenancy.TenantRepository;
import com.darkedges.oid4vci.core.error.Oid4vciErrorCode;
import com.darkedges.oid4vci.core.error.Oid4vciException;
import com.darkedges.oid4vci.issuer.IssuanceHook;
import com.darkedges.oid4vci.issuer.IssuerContext;
import com.darkedges.oid4vci.issuer.IssuerKeys;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * A tenant's issuance hook, from its settings ({@code issuanceHook.url}): the issuer asks {@code <url>/authorize} before it signs a
 * credential of one of the tenant's referenced offers, tells {@code <url>/issued} after, and {@code <url>/notified} when a wallet
 * reports on one. Without a URL, credentials are issued as the offer says.
 * <ul>
 *   <li><b>Authenticated</b> with a short-lived JWT ({@code typ hook+jwt}) signed by the tenant's own issuer signing key, in
 *       {@code Authorization: Bearer}: {@code iss} the tenant's issuer identifier, {@code aud} the URL called, a {@code jti}, and
 *       {@code body_sha256} binding the exact body. The tenant verifies it against the tenant's published keys.</li>
 *   <li><b>authorize</b>: 200 {@code {"allow": true}} issues; 403 or 409 (with an optional {@code reason}) refuses with
 *       {@code credential_request_denied}; anything else, or no answer in {@link #TIMEOUT}, issues nothing (503 to the wallet).</li>
 *   <li><b>issued</b> carries the {@code credential} (the tenant's own) and its {@code credentialDigest}; retried in the background ({@link #RETRIES}), as the credential is already in the wallet's response; the tenant
 *       treats it as idempotent per reference and format.</li>
 *   <li><b>notified</b>: {@code { reference, credentialConfigurationId, event, notificationId, receivedAt, description? }}, sent in
 *       the background and retried the same way. A tenant without the path (404 or 405) is not asked again for that notice; it can
 *       still read it from the offer API. The tenant treats it as idempotent per notificationId and event.</li>
 * </ul>
 */
public final class TenantIssuanceHook implements IssuanceHook {

    private static final Logger log = LoggerFactory.getLogger(TenantIssuanceHook.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    static final Duration TIMEOUT = Duration.ofSeconds(5);
    static final long[] RETRIES = {1, 5, 30};

    private final TenantRepository tenants;
    private final IssuerKeys keys;
    private final HttpClient http;
    private final ScheduledExecutorService retries;
    private final Clock clock;

    public TenantIssuanceHook(TenantRepository tenants, IssuerKeys keys, HttpClient http, ScheduledExecutorService retries, Clock clock) {
        this.tenants = tenants;
        this.keys = keys;
        this.http = http;
        this.retries = retries;
        this.clock = clock;
    }

    @Override
    public void authorize(IssuerContext context, Attempt attempt) {
        Optional<URI> hook = hookOf(context);
        if (hook.isEmpty()) return;
        URI url = hook.get().resolve(hook.get().getPath().endsWith("/") ? "authorize" : hook.get().getPath() + "/authorize");
        HttpResponse<String> response;
        try {
            response = http.send(request(context, url, body(attempt, null)), HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            throw new IssuanceHookUnavailableException("The tenant's issuance hook did not answer", e);
        }
        if (response.statusCode() == 200 && allowed(response.body())) return;
        if (response.statusCode() == 403 || response.statusCode() == 409) {
            String reason = reasonOf(response.body());
            log.info("tenant {} refused {} for reference {}: {}", context.tenantId(), attempt.credentialConfigurationId(), attempt.reference(), reason);
            throw new Oid4vciException(Oid4vciErrorCode.CREDENTIAL_REQUEST_DENIED,
                    "The issuer's tenant refused this credential" + (reason == null ? "" : " (" + reason + ")"));
        }
        throw new IssuanceHookUnavailableException("The tenant's issuance hook answered " + response.statusCode(), null);
    }

    @Override
    public void issued(IssuerContext context, Attempt attempt, String credential) {
        Optional<URI> hook = hookOf(context);
        if (hook.isEmpty()) return;
        URI url = hook.get().resolve(hook.get().getPath().endsWith("/") ? "issued" : hook.get().getPath() + "/issued");
        // The credential itself goes to the tenant: it is the tenant's own, and a tenant (the bank) checks later presentations against it.
        String body = body(attempt, credential);
        tell(context, url, body, attempt, 0);
    }

    @Override
    public void notified(IssuerContext context, Notice notice) {
        Optional<URI> hook = hookOf(context);
        if (hook.isEmpty()) return;
        URI url = hook.get().resolve(hook.get().getPath().endsWith("/") ? "notified" : hook.get().getPath() + "/notified");
        ObjectNode body = MAPPER.createObjectNode()
                .put("reference", notice.reference())
                .put("credentialConfigurationId", notice.credentialConfigurationId())
                .put("event", notice.event())
                .put("notificationId", notice.notificationId())
                .put("receivedAt", notice.receivedAt().toString());
        notice.description().ifPresent(d -> body.put("description", d));
        // Off the wallet's request thread: the wallet doesn't wait for the tenant.
        String json = body.toString();
        retries.execute(() -> report(context, url, json, notice, 0));
    }

    private void report(IssuerContext context, URI url, String body, Notice notice, int attemptNumber) {
        try {
            HttpResponse<String> response = http.send(request(context, url, body), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 == 2) return;
            if (response.statusCode() == 404 || response.statusCode() == 405) {
                log.info("tenant {} takes no notified calls (reference {})", context.tenantId(), notice.reference());
                return;
            }
            log.warn("tenant {} hook answered {} to notified for reference {}", context.tenantId(), response.statusCode(), notice.reference());
        } catch (Exception e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            log.warn("tenant {} hook unreachable for notified, reference {}: {}", context.tenantId(), notice.reference(), e.toString());
        }
        if (attemptNumber < RETRIES.length) {
            retries.schedule(() -> report(context, url, body, notice, attemptNumber + 1), RETRIES[attemptNumber], TimeUnit.SECONDS);
        } else {
            log.error("tenant {} was never told of {} for reference {}", context.tenantId(), notice.event(), notice.reference());
        }
    }

    private void tell(IssuerContext context, URI url, String body, Attempt attempt, int attemptNumber) {
        try {
            // A fresh token each time: each has its own jti and expiry.
            HttpResponse<String> response = http.send(request(context, url, body), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 == 2) return;
            log.warn("tenant {} hook answered {} to issued for reference {}", context.tenantId(), response.statusCode(), attempt.reference());
        } catch (Exception e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            log.warn("tenant {} hook unreachable for issued, reference {}: {}", context.tenantId(), attempt.reference(), e.toString());
        }
        if (attemptNumber < RETRIES.length) {
            retries.schedule(() -> tell(context, url, body, attempt, attemptNumber + 1), RETRIES[attemptNumber], TimeUnit.SECONDS);
        } else {
            log.error("tenant {} was never told that reference {} ({}) was issued", context.tenantId(), attempt.reference(), attempt.format());
        }
    }

    /** The tenant's hook URL, if its settings name one. */
    Optional<URI> hookOf(IssuerContext context) {
        Optional<Tenant> tenant = tenants.findById(context.tenantId());
        JsonNode url = tenant.map(t -> t.settings().path("issuanceHook").path("url")).orElse(null);
        if (url == null || !url.isTextual() || url.asText().isBlank()) return Optional.empty();
        return Optional.of(URI.create(url.asText()));
    }

    private HttpRequest request(IssuerContext context, URI url, String body) throws Exception {
        return HttpRequest.newBuilder(url)
                .timeout(TIMEOUT)
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + token(context, url, body))
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
    }

    String token(IssuerContext context, URI audience, String body) throws Exception {
        ECKey key = keys.signingKey(context);
        Date now = Date.from(clock.instant());
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(context.issuerIdentifier())
                .audience(audience.toString())
                .jwtID(UUID.randomUUID().toString())
                .issueTime(now)
                .expirationTime(Date.from(clock.instant().plusSeconds(60)))
                .claim("body_sha256", sha256(body.getBytes(StandardCharsets.UTF_8)))
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID())
                .type(new JOSEObjectType("hook+jwt")).build(), claims);
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }

    private static String body(Attempt attempt, String credential) {
        ObjectNode body = MAPPER.createObjectNode()
                .put("reference", attempt.reference())
                .put("credentialConfigurationId", attempt.credentialConfigurationId())
                .put("format", attempt.format())
                .put("holderKeyThumbprint", attempt.holderKeyThumbprint());
        if (credential != null) {
            body.put("credential", credential);
            body.put("credentialDigest", sha256(credential.getBytes(StandardCharsets.US_ASCII)));
        }
        return body.toString();
    }

    private static boolean allowed(String body) {
        try {
            return MAPPER.readTree(body).path("allow").asBoolean(false);
        } catch (Exception e) {
            return false;
        }
    }

    private static String reasonOf(String body) {
        try {
            String reason = MAPPER.readTree(body).path("reason").asText(null);
            return reason != null && reason.matches("[A-Za-z0-9_.-]{1,64}") ? reason : null;
        } catch (Exception e) {
            return null;
        }
    }

    static String sha256(byte[] bytes) {
        try {
            return Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(bytes)).toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
