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
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.ActiveProfiles;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The tenant API for offers and the tenant's issuance hook, on the demo issuer's "tenancy" profile over real HTTP: the bank creates an
 * offer for a hire bound to the hire's key, the wallet redeems it, and the bank is asked before the credential is signed and told after.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "demo.proofing.callback-secret=test-callback-secret")
@ActiveProfiles("tenancy")
class TenantOffersAndIssuanceHookTest {

    static final ObjectMapper MAPPER = new ObjectMapper();
    static final HttpClient HTTP = HttpClient.newHttpClient();
    static final String BANK_TOKEN = "bank-backend-token";

    static HttpServer hookServer;
    static final List<Map.Entry<String, String[]>> hookCalls = new CopyOnWriteArrayList<>();  // path -> {authorization, body}
    static volatile int authorizeStatus = 200;
    static volatile String authorizeBody = "{\"allow\":true}";

    @TestConfiguration
    static class Callers {
        /** Stands in for AuthStack: the bank's backend, by one token, for the bank only. */
        @Bean
        TenantCallers tenantCallers() {
            return (token, tenant) -> {
                if (BANK_TOKEN.equals(token) && tenant.id().equals("env-bank")) return new TenantCallers.TenantCaller(tenant.id(), "bank-worker");
                throw new TenantCallers.TenantCallerException(401, "not the bank");
            };
        }
    }

    @LocalServerPort int port;
    @Autowired TenantRepository tenants;
    ECKey holder;

    @BeforeAll
    static void hook() throws Exception {
        hookServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        hookServer.createContext("/hook", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String path = exchange.getRequestURI().getPath();
            hookCalls.add(Map.entry(path, new String[] {exchange.getRequestHeaders().getFirst("Authorization"), body}));
            int status = path.endsWith("/authorize") ? authorizeStatus : 204;
            byte[] out = (path.endsWith("/authorize") ? authorizeBody : "").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, out.length == 0 ? -1 : out.length);
            if (out.length > 0) exchange.getResponseBody().write(out);
            exchange.close();
        });
        hookServer.start();
    }

    @AfterAll
    static void stopHook() { hookServer.stop(0); }

    @BeforeEach
    void bank() throws Exception {
        hookCalls.clear();
        authorizeStatus = 200;
        authorizeBody = "{\"allow\":true}";
        ObjectNode settings = MAPPER.createObjectNode();
        settings.putObject("issuanceHook").put("url", "http://localhost:" + hookServer.getAddress().getPort() + "/hook");
        Tenant bank = tenants.findById("env-bank").orElse(Tenant.create("env-bank", "org-1", "bank"));
        tenants.save(bank.withSettings(settings));
        holder = new ECKeyGenerator(Curve.P_256).generate();
    }

    String origin() { return "http://localhost:" + port; }

    HttpResponse<String> send(String method, String path, String contentType, String body, Map<String, String> headers) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(origin() + path))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        if (contentType != null) request.header("Content-Type", contentType);
        headers.forEach(request::header);
        return HTTP.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    HttpResponse<String> createOffer(String reference, String token, Map<String, Object> extra) throws Exception {
        ObjectNode body = MAPPER.createObjectNode().put("reference", reference);
        body.putArray("credentialConfigurationIds").add("UniversityDegreeCredential");
        body.putObject("claims").put("given_name", "Ada").put("family_name", "Lovelace");
        body.put("holderKeyThumbprint", holder.computeThumbprint().toString());
        extra.forEach((k, v) -> body.set(k, MAPPER.valueToTree(v)));
        return send("POST", "/t/bank/tenant-api/v1/offers", "application/json", body.toString(), token == null ? Map.of() : Map.of("Authorization", "Bearer " + token));
    }

    String code(HttpResponse<String> offer) throws Exception {
        return MAPPER.readTree(offer.body()).path("offer").path("grants").path("urn:ietf:params:oauth:grant-type:pre-authorized_code").path("pre-authorized_code").asText();
    }

    HttpResponse<String> token(String code) throws Exception {
        return send("POST", "/t/bank/token", "application/x-www-form-urlencoded",
                "grant_type=" + URLEncoder.encode("urn:ietf:params:oauth:grant-type:pre-authorized_code", StandardCharsets.UTF_8)
                        + "&pre-authorized_code=" + URLEncoder.encode(code, StandardCharsets.UTF_8), Map.of());
    }

    HttpResponse<String> credential(String accessToken, ECKey proofKey) throws Exception {
        String nonce = MAPPER.readTree(send("POST", "/t/bank/nonce", null, "", Map.of()).body()).path("c_nonce").asText();
        SignedJWT proof = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("openid4vci-proof+jwt")).jwk(proofKey.toPublicJWK()).build(),
                new JWTClaimsSet.Builder().audience(origin() + "/t/bank").issueTime(new Date()).claim("nonce", nonce).build());
        proof.sign(new ECDSASigner(proofKey));
        ObjectNode body = MAPPER.createObjectNode().put("credential_configuration_id", "UniversityDegreeCredential");
        body.putObject("proofs").putArray("jwt").add(proof.serialize());
        return send("POST", "/t/bank/credential", "application/json", body.toString(), Map.of("Authorization", "Bearer " + accessToken));
    }

    String accessToken(String code) throws Exception {
        HttpResponse<String> token = token(code);
        assertThat(token.statusCode()).isEqualTo(200);
        return MAPPER.readTree(token.body()).path("access_token").asText();
    }

    @Test
    void theBankOffersIssuesThroughItsHookAndTheCredentialCarriesOnlyItsClaims() throws Exception {
        HttpResponse<String> created = createOffer("hire-1", BANK_TOKEN, Map.of());
        assertThat(created.statusCode()).isEqualTo(201);
        assertThat(MAPPER.readTree(created.body()).path("offer").path("credential_issuer").asText()).isEqualTo(origin() + "/t/bank");
        assertThat(MAPPER.readTree(created.body()).path("offerUri").asText()).startsWith("openid-credential-offer://?credential_offer=");
        // The same reference while live: the same offer.
        HttpResponse<String> again = createOffer("hire-1", BANK_TOKEN, Map.of());
        assertThat(again.statusCode()).isEqualTo(200);
        assertThat(code(again)).isEqualTo(code(created));

        HttpResponse<String> issued = credential(accessToken(code(created)), holder);
        assertThat(issued.statusCode()).isEqualTo(200);

        // The bank was asked first, with the hire and the key, and told after; each call signed by the bank tenant's own issuer key.
        for (int i = 0; i < 50 && hookCalls.size() < 2; i++) Thread.sleep(100);
        assertThat(hookCalls).extracting(Map.Entry::getKey).containsExactly("/hook/authorize", "/hook/issued");
        ECKey tenantKey = JWKSet.parse(send("GET", "/t/bank/jwks", null, null, Map.of()).body()).getKeys().get(0).toECKey();
        for (var call : hookCalls) {
            SignedJWT jwt = SignedJWT.parse(call.getValue()[0].substring("Bearer ".length()));
            assertThat(jwt.verify(new ECDSAVerifier(tenantKey))).isTrue();
            assertThat(jwt.getHeader().getType().getType()).isEqualTo("hook+jwt");
            assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo(origin() + "/t/bank");
            assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly("http://localhost:" + hookServer.getAddress().getPort() + call.getKey());
            assertThat(jwt.getJWTClaimsSet().getStringClaim("body_sha256"))
                    .isEqualTo(Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(call.getValue()[1].getBytes(StandardCharsets.UTF_8))).toString());
            JsonNode body = MAPPER.readTree(call.getValue()[1]);
            assertThat(body.path("reference").asText()).isEqualTo("hire-1");
            assertThat(body.path("holderKeyThumbprint").asText()).isEqualTo(holder.computeThumbprint().toString());
        }

        // The credential: the bank's claims, and none of the offer's constraints. The bank is told the very credential it was issued.
        String sdJwt = MAPPER.readTree(issued.body()).path("credentials").get(0).path("credential").asText();
        assertThat(MAPPER.readTree(hookCalls.get(1).getValue()[1]).path("credential").asText()).isEqualTo(sdJwt);
        String all = sdJwt + new String(java.util.Base64.getUrlDecoder().decode(sdJwt.substring(0, sdJwt.indexOf('~')).split("\\.")[1]), StandardCharsets.UTF_8)
                + java.util.Arrays.stream(sdJwt.split("~")).skip(1).filter(s -> !s.isEmpty())
                        .map(d -> new String(java.util.Base64.getUrlDecoder().decode(d), StandardCharsets.UTF_8)).collect(Collectors.joining());
        assertThat(all).contains("Lovelace").doesNotContain("__oid4vci").doesNotContain("hire-1");
    }

    @Test
    void theBankIsToldOnceWhenTheWalletDeletesTheCredential() throws Exception {
        String accessToken = accessToken(code(createOffer("hire-told", BANK_TOKEN, Map.of())));
        String notificationId = MAPPER.readTree(credential(accessToken, holder).body()).path("notification_id").asText();
        String body = MAPPER.createObjectNode().put("notification_id", notificationId).put("event", "credential_deleted").toString();
        for (int i = 0; i < 2; i++) {
            assertThat(send("POST", "/t/bank/notification", "application/json", body, Map.of("Authorization", "Bearer " + accessToken)).statusCode()).isEqualTo(204);
        }
        java.util.function.Supplier<List<Map.Entry<String, String[]>>> told =
                () -> hookCalls.stream().filter(c -> c.getKey().equals("/hook/notified")).toList();
        for (int i = 0; i < 50 && told.get().isEmpty(); i++) Thread.sleep(100);
        Thread.sleep(300);
        assertThat(told.get()).hasSize(1);

        String[] call = told.get().get(0).getValue();
        SignedJWT jwt = SignedJWT.parse(call[0].substring("Bearer ".length()));
        ECKey tenantKey = JWKSet.parse(send("GET", "/t/bank/jwks", null, null, Map.of()).body()).getKeys().get(0).toECKey();
        assertThat(jwt.verify(new ECDSAVerifier(tenantKey))).isTrue();
        assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly("http://localhost:" + hookServer.getAddress().getPort() + "/hook/notified");
        JsonNode notice = MAPPER.readTree(call[1]);
        assertThat(notice.path("reference").asText()).isEqualTo("hire-told");
        assertThat(notice.path("event").asText()).isEqualTo("credential_deleted");
        assertThat(notice.path("notificationId").asText()).isEqualTo(notificationId);
    }

    @Test
    void aProofWithAnyOtherKeyIsRefused() throws Exception {
        String accessToken = accessToken(code(createOffer("hire-2", BANK_TOKEN, Map.of())));
        HttpResponse<String> wrongKey = credential(accessToken, new ECKeyGenerator(Curve.P_256).generate());
        assertThat(wrongKey.statusCode()).isEqualTo(400);
        assertThat(MAPPER.readTree(wrongKey.body()).path("error").asText()).isEqualTo("invalid_proof");
        assertThat(hookCalls).isEmpty();
    }

    @Test
    void theBankCanRefuseAndAnUnreachableBankIssuesNothing() throws Exception {
        authorizeStatus = 409;
        authorizeBody = "{\"allow\":false,\"reason\":\"staff_inactive\"}";
        HttpResponse<String> refused = credential(accessToken(code(createOffer("hire-3", BANK_TOKEN, Map.of()))), holder);
        assertThat(refused.statusCode()).isEqualTo(400);
        assertThat(MAPPER.readTree(refused.body()).path("error").asText()).isEqualTo("credential_request_denied");

        authorizeStatus = 500;
        authorizeBody = "{}";
        HttpResponse<String> down = credential(accessToken(code(createOffer("hire-4", BANK_TOKEN, Map.of()))), holder);
        assertThat(down.statusCode()).isEqualTo(503);
        assertThat(MAPPER.readTree(down.body()).path("error").asText()).isEqualTo("temporarily_unavailable");
        assertThat(hookCalls).extracting(Map.Entry::getKey).doesNotContain("/hook/issued");
    }

    @Test
    void aWithdrawnOfferCanNoLongerBeRedeemed() throws Exception {
        String code = code(createOffer("hire-5", BANK_TOKEN, Map.of()));
        assertThat(send("DELETE", "/t/bank/tenant-api/v1/offers/hire-5", null, null, Map.of("Authorization", "Bearer " + BANK_TOKEN)).statusCode()).isEqualTo(204);
        assertThat(token(code).statusCode()).isEqualTo(400);
    }

    @Test
    void onlyTheBankMayCallAndReservedOrUnknownThingsAreRefused() throws Exception {
        assertThat(createOffer("hire-6", null, Map.of()).statusCode()).isEqualTo(401);
        assertThat(createOffer("hire-6", "someone-else", Map.of()).statusCode()).isEqualTo(401);
        assertThat(createOffer("hire-6", BANK_TOKEN, Map.of("claims", Map.of("__oid4vci.holder_jkt", "x"))).statusCode()).isEqualTo(400);
        assertThat(createOffer("hire-6", BANK_TOKEN, Map.of("credentialConfigurationIds", List.of("NoSuchCredential"))).statusCode()).isEqualTo(400);
        assertThat(createOffer("bad reference!", BANK_TOKEN, Map.of()).statusCode()).isEqualTo(400);
        assertThat(createOffer("hire-6", BANK_TOKEN, Map.of("expiresIn", 5)).statusCode()).isEqualTo(400);
    }
}
