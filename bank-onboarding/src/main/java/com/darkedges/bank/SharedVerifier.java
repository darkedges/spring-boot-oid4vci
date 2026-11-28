package com.darkedges.bank;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;

/**
 * The bank's tenant of the platform's shared credential verifier (bank-onboarding/docs/migration-to-shared-services.md, part 2): the
 * bank asks for a presentation through the verifier's tenant API, with its own worker token, and collects what was verified. The
 * verifier says the presentation is genuine and from an issuer the tenant trusts; what that allows is the bank's to decide.
 */
public final class SharedVerifier {

    /** A request the wallet can answer. */
    public record Transaction(String id, String requestUri, String walletUri) {}

    /** One verified credential: who issued it, its claims, and the holder key it proved. */
    public record Credential(String format, String issuer, JsonNode claims, JsonNode holderKey) {}

    private static final ObjectMapper JSON = new ObjectMapper();
    private final String base;
    private final HttpClient http;
    private final WorkerToken token;

    public SharedVerifier(String base, HttpClient http, WorkerToken token) {
        this.base = base.replaceAll("/+$", "");
        this.http = http;
        this.token = token;
    }

    public Transaction create(String registrationId, String reference, Duration lifetime) throws Exception {
        ObjectNode body = JSON.createObjectNode().put("registrationId", registrationId).put("reference", reference)
                .put("expiresIn", lifetime.toSeconds());
        HttpResponse<String> response = send(request("").header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString())));
        if (response.statusCode() != 201) throw refused("start a presentation", response);
        JsonNode answer = JSON.readTree(response.body());
        return new Transaction(required(answer, "transactionId"), required(answer, "requestUri"), required(answer, "walletUri"));
    }

    /** {@code pending}, {@code verified}, {@code collected} or {@code expired}. */
    public String status(String transactionId) throws Exception {
        HttpResponse<String> response = send(request("/" + encode(transactionId)).GET());
        if (response.statusCode() != 200) throw refused("tell a presentation's status", response);
        return required(JSON.readTree(response.body()), "status");
    }

    /**
     * The credential answering {@code queryId}, once. Empty when there is nothing to collect (not verified yet, or already collected).
     */
    public Optional<Credential> collect(String transactionId, String queryId) throws Exception {
        HttpResponse<String> response = send(request("/" + encode(transactionId) + "/consume").POST(HttpRequest.BodyPublishers.noBody()));
        if (response.statusCode() == 409) return Optional.empty();
        if (response.statusCode() != 200) throw refused("hand out a result", response);
        JsonNode credential = JSON.readTree(response.body()).path("credentials").path(queryId);
        if (!credential.isObject()) return Optional.empty();
        return Optional.of(new Credential(credential.path("format").asText(), credential.path("issuer").asText(),
                credential.path("claims"), credential.path("holderKey")));
    }

    private HttpRequest.Builder request(String path) throws Exception {
        return HttpRequest.newBuilder(URI.create(base + "/tenant-api/v1/transactions" + path)).timeout(Duration.ofSeconds(10))
                .header("Authorization", "Bearer " + token.get());
    }

    private HttpResponse<String> send(HttpRequest.Builder request) throws Exception {
        try {
            return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw e;
        }
    }

    private static String required(JsonNode node, String field) {
        String value = node.path(field).asText("");
        if (value.isEmpty()) throw new IllegalStateException("The shared verifier's answer has no " + field);
        return value;
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    // The body can carry the verified claims on success only, so a refusal's is safe to report.
    private static IllegalStateException refused(String what, HttpResponse<String> response) {
        return new IllegalStateException("The shared verifier would not " + what + ": " + response.statusCode() + " " + response.body());
    }
}
