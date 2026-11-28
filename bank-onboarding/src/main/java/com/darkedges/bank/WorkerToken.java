package com.darkedges.bank;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

/**
 * The access token of the bank's dedicated worker in AuthStack, with which it calls the shared credential services' tenant APIs
 * (client credentials), kept until shortly before it expires.
 */
public final class WorkerToken {

    private static final ObjectMapper JSON = new ObjectMapper();
    private final URI tokenUrl;
    private final String clientId;
    private final String clientSecret;
    private final HttpClient http;
    private final Clock clock;
    private String accessToken;
    private Instant expires = Instant.EPOCH;

    public WorkerToken(URI tokenUrl, String clientId, String clientSecret, HttpClient http, Clock clock) {
        this.tokenUrl = tokenUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.http = http;
        this.clock = clock;
    }

    public synchronized String get() throws Exception {
        if (accessToken != null && clock.instant().isBefore(expires)) return accessToken;
        String basic = Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
        HttpResponse<String> response = http.send(HttpRequest.newBuilder(tokenUrl).timeout(Duration.ofSeconds(10))
                .header("Authorization", "Basic " + basic).header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials")).build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) throw new IllegalStateException("AuthStack refused the bank's credential services token: " + response.statusCode());
        JsonNode body = JSON.readTree(response.body());
        accessToken = body.path("access_token").asText();
        expires = clock.instant().plusSeconds(Math.max(60, body.path("expires_in").asLong(3600)) - 60);
        return accessToken;
    }
}
