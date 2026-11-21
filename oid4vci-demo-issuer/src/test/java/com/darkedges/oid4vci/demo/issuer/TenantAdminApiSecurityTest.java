package com.darkedges.oid4vci.demo.issuer;

import com.darkedges.oid4vc.tenancy.admin.ConsoleAccount;
import com.darkedges.oid4vc.tenancy.admin.ConsoleAccounts;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.ActiveProfiles;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The AuthStack console reaches the tenancy admin API with its console token as {@code Authorization: Bearer}. The issuer's resource
 * server must not take that for an issuer access token and refuse it before the admin controller sees it (the console showed
 * "https://issuer.zkp.au answered 401"), while the credential endpoint still demands a real access token.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"demo.proofing.callback-secret=test-callback-secret", "oid4vc.tenancy.admin.enabled=true"})
@ActiveProfiles("tenancy")
class TenantAdminApiSecurityTest {

    static final String CONSOLE_TOKEN = "console-token-for-tests";
    static final HttpClient HTTP = HttpClient.newHttpClient();
    static final ObjectMapper MAPPER = new ObjectMapper();

    @TestConfiguration
    static class Accounts {
        /** Stands in for AuthStack's /api/auth/me: one platform administrator, by one token. */
        @Bean
        ConsoleAccounts consoleAccounts() {
            return token -> {
                if (CONSOLE_TOKEN.equals(token)) return new ConsoleAccount("user-1", "admin@example.test", ConsoleAccount.Role.ADMIN, "org-1", Map.of());
                throw new ConsoleAccounts.ConsoleAccountException(401, "Your AuthStack console session has ended; sign in again");
            };
        }
    }

    @LocalServerPort
    int port;

    HttpResponse<String> send(String method, String path, String authorization) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .method(method, method.equals("POST") ? HttpRequest.BodyPublishers.ofString("{}") : HttpRequest.BodyPublishers.noBody());
        if (authorization != null) request.header("Authorization", authorization);
        if (method.equals("POST")) request.header("Content-Type", "application/json");
        return HTTP.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void aConsoleTokenReachesTheAdminApi() throws Exception {
        HttpResponse<String> response = send("GET", "/admin/api/tenants", "Bearer " + CONSOLE_TOKEN);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(MAPPER.readTree(response.body()).path("service").asText()).isEqualTo("issuer");
    }

    @Test
    void aRefusedConsoleTokenIsTheControllersAnswer() throws Exception {
        HttpResponse<String> response = send("GET", "/admin/api/tenants", "Bearer not-a-console-token");
        assertThat(response.statusCode()).isEqualTo(401);
        // The admin controller's JSON, not the resource server's empty challenge.
        assertThat(MAPPER.readTree(response.body()).path("error").asText()).isEqualTo("unauthorized");
        assertThat(response.headers().firstValue("WWW-Authenticate")).isEmpty();
    }

    @Test
    void theCredentialEndpointStillDemandsAnAccessToken() throws Exception {
        HttpResponse<String> response = send("POST", "/credential", "Bearer " + CONSOLE_TOKEN);
        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.headers().firstValue("WWW-Authenticate")).isPresent();
    }
}
