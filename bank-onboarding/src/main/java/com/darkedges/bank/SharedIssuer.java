package com.darkedges.bank;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The bank's tenant of the platform's shared credential issuer (bank-onboarding/docs/migration-to-shared-services.md):
 * <ul>
 *   <li>staff offers through the issuer's tenant API, with the bank's own worker token ({@link #offer}, {@link #withdraw});</li>
 *   <li>the tenant's published keys, to trust staff credentials it issued, and to check the issuer's calls to the bank's hook
 *       ({@link #verifyHookCall}): a {@code hook+jwt} signed by the tenant's issuer key, for this exact URL and body, used once.</li>
 * </ul>
 */
public final class SharedIssuer {

    /** The bank's settings for its tenant (bank.credentials.*). */
    public record Settings(String issuer, URI tokenUrl, String clientId, String clientSecret, String hookBaseUrl,
                           List<String> offerConfigurations, boolean issueOffers) {}

    /** A call to the bank's hook that didn't come from its tenant of the issuer, or was replayed. */
    public static final class HookCallRejected extends RuntimeException {
        public HookCallRejected(String message) { super(message); }
    }

    private static final ObjectMapper JSON = new ObjectMapper();
    private final Settings settings;
    private final HttpClient http;
    private final Clock clock;
    private final JWKSource<SecurityContext> keys;
    /** One processor per hook path, each expecting its own audience (the URL called): built once, safe to share between threads. */
    private final Map<String, DefaultJWTProcessor<SecurityContext>> hookTokens;
    private final Map<String, Instant> seenHookTokens = new ConcurrentHashMap<>();
    private volatile String accessToken;
    private volatile Instant accessTokenExpires = Instant.EPOCH;

    public SharedIssuer(Settings settings, HttpClient http, Clock clock) {
        this(settings, http, clock, JWKSourceBuilder.create(url(settings.issuer() + "/jwks")).build());
    }

    SharedIssuer(Settings settings, HttpClient http, Clock clock, JWKSource<SecurityContext> keys) {
        this.settings = settings;
        this.http = http;
        this.clock = clock;
        this.keys = keys;
        this.hookTokens = Map.of("authorize", hookProcessor("authorize"), "issued", hookProcessor("issued"));
    }

    private DefaultJWTProcessor<SecurityContext> hookProcessor(String path) {
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("hook+jwt")));
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.ES256, keys));
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                Set.of(settings.hookBaseUrl() + "/" + path),
                new JWTClaimsSet.Builder().issuer(settings.issuer()).build(),
                Set.of("exp", "iat", "jti", "body_sha256"), null));
        return processor;
    }

    private static java.net.URL url(String s) {
        try {
            return URI.create(s).toURL();
        } catch (Exception e) {
            throw new IllegalArgumentException("bank.credentials.issuer is not a URL: " + s, e);
        }
    }

    public String issuer() { return settings.issuer(); }

    public boolean issuesOffers() { return settings.issueOffers(); }

    /** The tenant's key with this kid, as published at its /jwks (a fresh fetch for a kid not seen yet). */
    public Optional<JWK> key(String kid) {
        try {
            List<JWK> found = keys.get(new JWKSelector(new JWKMatcher.Builder().keyID(kid).build()), null);
            return found.isEmpty() ? Optional.empty() : Optional.of(found.getFirst());
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    /**
     * A staff offer for this hire, from the shared issuer: the issuer's offer JSON, plus {@code bank_holder_jwk} (the wallet uses it to
     * pick the key its passport proved; the issuer itself refuses any other, from {@code holderKeyThumbprint}).
     */
    public String offer(String reference, Map<String, String> claims, JsonNode holderJwk, String holderKeyThumbprint) throws Exception {
        ObjectNode body = JSON.createObjectNode().put("reference", reference).put("holderKeyThumbprint", holderKeyThumbprint).put("expiresIn", 600);
        settings.offerConfigurations().forEach(body.putArray("credentialConfigurationIds")::add);
        ObjectNode claimNode = body.putObject("claims");
        claims.forEach(claimNode::put);
        HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create(settings.issuer() + "/tenant-api/v1/offers"))
                .timeout(Duration.ofSeconds(10)).header("Content-Type", "application/json").header("Authorization", "Bearer " + token())
                .POST(HttpRequest.BodyPublishers.ofString(body.toString())).build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200 && response.statusCode() != 201) {
            throw new IllegalStateException("The shared issuer refused the staff offer: " + response.statusCode() + " " + response.body());
        }
        ObjectNode offer = (ObjectNode) JSON.readTree(response.body()).path("offer");
        offer.set("bank_holder_jwk", holderJwk);
        return JSON.writeValueAsString(offer);
    }

    /** Withdraws a live offer (approval revoked, say). Best effort: the hook refuses issuing it anyway. */
    public void withdraw(String reference) {
        try {
            http.send(HttpRequest.newBuilder(URI.create(settings.issuer() + "/tenant-api/v1/offers/" + URLEncoder.encode(reference, StandardCharsets.UTF_8)))
                    .timeout(Duration.ofSeconds(10)).header("Authorization", "Bearer " + token()).DELETE().build(), HttpResponse.BodyHandlers.discarding());
        } catch (Exception e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
        }
    }

    /**
     * Checks a call from the shared issuer to the bank's hook at {@code path} ({@code authorize} or {@code issued}): a {@code hook+jwt}
     * (ES256, the tenant's key) issued by the tenant, for this URL, unexpired, binding this exact body, and not seen before.
     */
    public void verifyHookCall(String authorization, String rawBody, String path) {
        String token = authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7) ? authorization.substring(7).trim() : null;
        if (token == null) throw new HookCallRejected("A hook token is required");
        DefaultJWTProcessor<SecurityContext> processor = hookTokens.get(path);
        if (processor == null) throw new HookCallRejected("Unknown hook path");
        JWTClaimsSet claims;
        try {
            claims = processor.process(token, null);
        } catch (Exception e) {
            throw new HookCallRejected("Not a hook call from the bank's tenant of the issuer");
        }
        String bodyHash;
        try {
            bodyHash = claims.getStringClaim("body_sha256");
        } catch (java.text.ParseException e) {
            bodyHash = null;
        }
        if (bodyHash == null || !bodyHash.equals(sha256(rawBody.getBytes(StandardCharsets.UTF_8)))) throw new HookCallRejected("The body is not the one signed");
        Instant now = clock.instant();
        seenHookTokens.values().removeIf(expires -> expires.isBefore(now));
        Instant expires = claims.getExpirationTime().toInstant();
        if (seenHookTokens.putIfAbsent(claims.getJWTID(), expires) != null) throw new HookCallRejected("This hook token was already used");
    }

    private synchronized String token() throws Exception {
        if (accessToken != null && clock.instant().isBefore(accessTokenExpires)) return accessToken;
        String basic = Base64.getEncoder().encodeToString((settings.clientId() + ":" + settings.clientSecret()).getBytes(StandardCharsets.UTF_8));
        HttpResponse<String> response = http.send(HttpRequest.newBuilder(settings.tokenUrl()).timeout(Duration.ofSeconds(10))
                .header("Authorization", "Basic " + basic).header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials")).build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) throw new IllegalStateException("AuthStack refused the bank's credential services token: " + response.statusCode());
        JsonNode body = JSON.readTree(response.body());
        accessToken = body.path("access_token").asText();
        accessTokenExpires = clock.instant().plusSeconds(Math.max(60, body.path("expires_in").asLong(3600)) - 60);
        return accessToken;
    }

    static String sha256(byte[] bytes) {
        try {
            return Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(bytes)).toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
