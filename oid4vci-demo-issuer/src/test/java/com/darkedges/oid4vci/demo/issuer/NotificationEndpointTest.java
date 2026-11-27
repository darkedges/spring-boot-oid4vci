package com.darkedges.oid4vci.demo.issuer;

import com.darkedges.oid4vc.tenancy.Tenant;
import com.darkedges.oid4vc.tenancy.TenantRepository;
import com.darkedges.oid4vc.tenancy.tenantapi.TenantCallers;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.ActiveProfiles;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The Notification Endpoint on the demo issuer's "tenancy" profile over real HTTP, through the real resource server: a wallet says it
 * deleted a credential, with the access token while that lives or later with the notification token and a DPoP proof by the holder
 * key; the tenant reads what was said. Neither token does anything else, and no tenant or credential can be notified about another's.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "demo.proofing.callback-secret=test-callback-secret")
@ActiveProfiles("tenancy")
class NotificationEndpointTest {

    static final ObjectMapper MAPPER = new ObjectMapper();
    static final HttpClient HTTP = HttpClient.newHttpClient();
    static final String BANK_TOKEN = "bank-backend-token";

    @TestConfiguration
    static class Callers {
        @Bean
        TenantCallers tenantCallers() {
            return (token, tenant) -> {
                if (BANK_TOKEN.equals(token) && tenant.id().equals("env-notify")) return new TenantCallers.TenantCaller(tenant.id(), "bank-worker");
                throw new TenantCallers.TenantCallerException(401, "not the bank");
            };
        }
    }

    @LocalServerPort int port;
    @Autowired TenantRepository tenants;

    /** One credential as a wallet holds it afterwards. */
    record Held(ECKey holder, String accessToken, String notificationId, String notificationToken) {}

    @BeforeEach
    void tenantsExist() {
        tenants.save(tenants.findById("env-notify").orElse(Tenant.create("env-notify", "org-1", "notify")));
        tenants.save(tenants.findById("env-elsewhere").orElse(Tenant.create("env-elsewhere", "org-2", "elsewhere")));
    }

    String origin() { return "http://localhost:" + port; }

    HttpResponse<String> send(String method, String path, String contentType, String body, Map<String, String> headers) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(origin() + path))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        if (contentType != null) request.header("Content-Type", contentType);
        headers.forEach(request::header);
        return HTTP.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    Held issue(String reference) throws Exception {
        ECKey holder = new ECKeyGenerator(Curve.P_256).generate();
        ObjectNode offer = MAPPER.createObjectNode().put("reference", reference);
        offer.putArray("credentialConfigurationIds").add("UniversityDegreeCredential");
        offer.putObject("claims").put("given_name", "Ada").put("family_name", "Lovelace");
        HttpResponse<String> created = send("POST", "/t/notify/tenant-api/v1/offers", "application/json", offer.toString(),
                Map.of("Authorization", "Bearer " + BANK_TOKEN));
        assertThat(created.statusCode()).isEqualTo(201);
        String code = MAPPER.readTree(created.body()).path("offer").path("grants")
                .path("urn:ietf:params:oauth:grant-type:pre-authorized_code").path("pre-authorized_code").asText();
        HttpResponse<String> token = send("POST", "/t/notify/token", "application/x-www-form-urlencoded",
                "grant_type=" + URLEncoder.encode("urn:ietf:params:oauth:grant-type:pre-authorized_code", StandardCharsets.UTF_8)
                        + "&pre-authorized_code=" + URLEncoder.encode(code, StandardCharsets.UTF_8), Map.of());
        String accessToken = MAPPER.readTree(token.body()).path("access_token").asText();

        HttpResponse<String> issued = send("POST", "/t/notify/credential", "application/json", credentialRequest(holder),
                Map.of("Authorization", "Bearer " + accessToken));
        assertThat(issued.statusCode()).isEqualTo(200);
        JsonNode body = MAPPER.readTree(issued.body());
        assertThat(body.path("notification_authorization").path("token_type").asText()).isEqualTo("DPoP");
        return new Held(holder, accessToken, body.path("notification_id").asText(),
                body.path("notification_authorization").path("access_token").asText());
    }

    String credentialRequest(ECKey holder) throws Exception {
        String nonce = MAPPER.readTree(send("POST", "/t/notify/nonce", null, "", Map.of()).body()).path("c_nonce").asText();
        SignedJWT proof = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(holder.toPublicJWK()).build(),
                new JWTClaimsSet.Builder().audience(origin() + "/t/notify").issueTime(new Date()).claim("nonce", nonce).build());
        proof.sign(new ECDSASigner(holder));
        ObjectNode body = MAPPER.createObjectNode().put("credential_configuration_id", "UniversityDegreeCredential");
        body.putObject("proofs").putArray("jwt").add(proof.serialize());
        return body.toString();
    }

    Map<String, String> dpop(String token, ECKey key, String path) throws Exception {
        String ath = Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.US_ASCII))).toString();
        SignedJWT proof = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("dpop+jwt")).jwk(key.toPublicJWK()).build(),
                new JWTClaimsSet.Builder().jwtID(UUID.randomUUID().toString()).issueTime(new Date())
                        .claim("htm", "POST").claim("htu", origin() + path).claim("ath", ath).build());
        proof.sign(new ECDSASigner(key));
        return Map.of("Authorization", "DPoP " + token, "DPoP", proof.serialize());
    }

    static String notification(String id, String event) {
        return MAPPER.createObjectNode().put("notification_id", id).put("event", event).toString();
    }

    HttpResponse<String> notify(String body, Map<String, String> headers) throws Exception {
        return send("POST", "/t/notify/notification", "application/json", body, headers);
    }

    JsonNode events(String reference) throws Exception {
        HttpResponse<String> response = send("GET", "/t/notify/tenant-api/v1/offers/" + reference + "/notifications", null, null,
                Map.of("Authorization", "Bearer " + BANK_TOKEN));
        assertThat(response.statusCode()).isEqualTo(200);
        return MAPPER.readTree(response.body()).path("notifications");
    }

    static String error(HttpResponse<String> response) throws Exception {
        return MAPPER.readTree(response.body()).path("error").asText();
    }

    @Test
    void theIssuerAdvertisesItsNotificationEndpoint() throws Exception {
        JsonNode metadata = MAPPER.readTree(send("GET", "/.well-known/openid-credential-issuer/t/notify", null, null, Map.of()).body());
        assertThat(metadata.path("notification_endpoint").asText()).isEqualTo(origin() + "/t/notify/notification");
    }

    @Test
    void aDeletionIsRecordedOnceAndShownToTheTenant() throws Exception {
        Held held = issue("note-1");
        String body = notification(held.notificationId(), "credential_deleted");
        assertThat(notify(body, dpop(held.notificationToken(), held.holder(), "/t/notify/notification")).statusCode()).isEqualTo(204);
        assertThat(notify(body, dpop(held.notificationToken(), held.holder(), "/t/notify/notification")).statusCode()).isEqualTo(204);
        // The access token may notify too, while it lives.
        assertThat(notify(notification(held.notificationId(), "credential_accepted"),
                Map.of("Authorization", "Bearer " + held.accessToken())).statusCode()).isEqualTo(204);

        JsonNode events = events("note-1");
        assertThat(events).hasSize(2);
        assertThat(events.get(0).path("event").asText()).isEqualTo("credential_deleted");
        assertThat(events.get(0).path("notificationId").asText()).isEqualTo(held.notificationId());
        assertThat(events.get(0).path("credentialConfigurationId").asText()).isEqualTo("UniversityDegreeCredential");
    }

    @Test
    void theNotificationTokenNeedsTheHolderKey() throws Exception {
        Held held = issue("note-2");
        String body = notification(held.notificationId(), "credential_deleted");
        assertThat(notify(body, Map.of()).statusCode()).isEqualTo(401);
        assertThat(notify(body, Map.of("Authorization", "Bearer " + held.notificationToken())).statusCode()).isEqualTo(401);
        ECKey stranger = new ECKeyGenerator(Curve.P_256).generate();
        assertThat(notify(body, dpop(held.notificationToken(), stranger, "/t/notify/notification")).statusCode()).isEqualTo(401);
        assertThat(events("note-2")).isEmpty();
    }

    @Test
    void theNotificationTokenGetsNoCredential() throws Exception {
        Held held = issue("note-3");
        HttpResponse<String> response = send("POST", "/t/notify/credential", "application/json", credentialRequest(held.holder()),
                dpop(held.notificationToken(), held.holder(), "/t/notify/credential"));
        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(error(response)).isEqualTo("invalid_token");
    }

    @Test
    void oneCredentialCannotNotifyAboutAnotherAndBadRequestsAreRefused() throws Exception {
        Held mine = issue("note-4");
        Held theirs = issue("note-5");
        for (Map<String, String> caller : java.util.List.of(
                dpop(mine.notificationToken(), mine.holder(), "/t/notify/notification"),
                Map.of("Authorization", "Bearer " + mine.accessToken()))) {
            HttpResponse<String> refused = notify(notification(theirs.notificationId(), "credential_deleted"), caller);
            assertThat(refused.statusCode()).isEqualTo(400);
            assertThat(error(refused)).isEqualTo("invalid_notification_id");
        }
        assertThat(events("note-5")).isEmpty();

        HttpResponse<String> unknownEvent = notify(notification(mine.notificationId(), "credential_burned"),
                Map.of("Authorization", "Bearer " + mine.accessToken()));
        assertThat(unknownEvent.statusCode()).isEqualTo(400);
        assertThat(error(unknownEvent)).isEqualTo("invalid_notification_request");
        assertThat(error(notify("not json", Map.of("Authorization", "Bearer " + mine.accessToken())))).isEqualTo("invalid_notification_request");
    }

    @Test
    void anotherTenantRefusesTheTokensAndOnlyTheTenantReadsItsEvents() throws Exception {
        Held held = issue("note-6");
        HttpResponse<String> elsewhere = send("POST", "/t/elsewhere/notification", "application/json",
                notification(held.notificationId(), "credential_deleted"),
                dpop(held.notificationToken(), held.holder(), "/t/elsewhere/notification"));
        assertThat(elsewhere.statusCode()).isEqualTo(401);
        assertThat(send("GET", "/t/notify/tenant-api/v1/offers/note-6/notifications", null, null, Map.of()).statusCode()).isEqualTo(401);
        assertThat(send("GET", "/t/elsewhere/tenant-api/v1/offers/note-6/notifications", null, null,
                Map.of("Authorization", "Bearer " + BANK_TOKEN)).statusCode()).isEqualTo(401);
    }
}
