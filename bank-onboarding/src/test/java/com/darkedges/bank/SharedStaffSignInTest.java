package com.darkedges.bank;

import com.darkedges.oid4vci.core.metadata.SdJwtVcCredentialConfiguration;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.darkedges.oid4vci.issuer.SdJwtVcCredentialIssuanceService;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.SdJwtVcMeta;
import com.darkedges.oid4vp.core.response.PresentationEntry;
import com.darkedges.oid4vp.core.response.PresentationVerificationParams;
import com.darkedges.oid4vp.sdjwt.KbJwtBuilder;
import com.darkedges.oid4vp.sdjwt.SdJwtVerifier;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.transaction.support.TransactionTemplate;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * Staff sign-in carried out by the shared verifier (bank.credentials.verify-staff-via=shared): the bank asks it, collects what it
 * verified, and applies its own rules. Against a real PostgreSQL database (BANK_TEST_DATABASE_URL, skipped without it) and a stand-in
 * verifier whose result is what the verification library really produces for a presentation of the stored credential.
 */
class SharedStaffSignInTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String BASE = "https://bank.example";
    private static final String ISSUER = "https://issuer.bank.example";

    @TempDir Path dir;
    JdbcTemplate db;
    TransactionTemplate tx;
    BankController bank;
    JourneyApiController journey;
    HttpServer server;
    ECKey issuerKey, holder;
    UUID staff;
    String stored;
    volatile String status = "pending";
    volatile ObjectNode result;
    volatile boolean down;
    final List<String> calls = new CopyOnWriteArrayList<>();

    @BeforeEach
    void setUp() throws Exception {
        String url = System.getenv("BANK_TEST_DATABASE_URL");
        Assumptions.assumeTrue(url != null && !url.isBlank(), "BANK_TEST_DATABASE_URL not set");
        var dataSource = new DriverManagerDataSource(url);
        db = new JdbcTemplate(dataSource);
        tx = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        db.execute("drop table if exists bank_issued_credential, bank_directory_outbox, bank_applicant_ref, bank_presentation, bank_audit, bank_hire cascade");
        for (String statement : new String(getClass().getResourceAsStream("/schema.sql").readAllBytes()).split(";")) if (!statement.isBlank()) db.execute(statement);

        issuerKey = new ECKeyGenerator(Curve.P_256).keyID("tenant-key").generate();
        holder = new ECKeyGenerator(Curve.P_256).generate();
        staff = hire("ACTIVE", null);
        stored = credential(ISSUER, ISSUER, holder, Instant.now().minusSeconds(120));
        db.update("update bank_hire set issued_credential=? where id=?", stored, staff);
        result = verified(stored, ISSUER);

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            calls.add(exchange.getRequestMethod() + " " + path);
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            int code = 200;
            String answer;
            if (path.equals("/token")) {
                answer = "{\"access_token\":\"worker\",\"expires_in\":3600}";
            } else if (down || !"Bearer worker".equals(exchange.getRequestHeaders().getFirst("Authorization"))) {
                code = 503; answer = "{}";
            } else if (path.equals("/tenant-api/v1/transactions")) {
                code = 201;
                assertThat(body).contains("\"registrationId\":\"staff-sign-in\"").contains("\"expiresIn\":600");
                answer = "{\"transactionId\":\"vt-1\",\"requestUri\":\"https://v.example/r/1\",\"walletUri\":\"openid4vp://?client_id=x&request_uri=y\"}";
            } else if (path.endsWith("/consume")) {
                if (status.equals("verified")) {
                    status = "collected";
                    ObjectNode node = JSON.createObjectNode();
                    node.putObject("credentials").set("staff", result);
                    answer = node.toString();
                } else {
                    code = 409; answer = "{\"error\":\"no_result\"}";
                }
            } else {
                answer = "{\"status\":\"" + status + "\"}";
            }
            byte[] bytes = answer.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(code, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();

        Path passport = dir.resolve("passport.jwk");
        Files.writeString(passport, new ECKeyGenerator(Curve.P_256).generate().toPublicJWK().toJSONString());
        ECKey bankKey = new ECKeyGenerator(Curve.P_256).generate();
        bank = new BankController(db, mock(PreAuthorizedCodeStore.class), bankKey, BASE, "https://passport.example", passport.toString(), "Bank");
        String origin = "http://127.0.0.1:" + server.getAddress().getPort();
        var http = HttpClient.newHttpClient();
        bank.setSharedIssuer(new SharedIssuer(new SharedIssuer.Settings(ISSUER, URI.create(origin + "/token"), "bank", "secret",
                BASE + "/api/issuer-hook/v1", List.of("BankStaffCredential"), true), http, Clock.systemUTC()));
        bank.setSharedVerifier(new SharedVerifier(origin, http, new WorkerToken(URI.create(origin + "/token"), "bank", "secret", http, Clock.systemUTC())));
        bank.setStaffVerification("shared");
        bank.checkStaffVerification();
        journey = new JourneyApiController(db, bank, 60);
    }

    @AfterEach
    void tearDown() {
        if (server != null) server.stop(0);
    }

    private UUID hire(String status, UUID previous) {
        UUID id = UUID.randomUUID();
        db.update("insert into bank_hire(id,expected_given,expected_family,birth_date,email,department,status,invite_hash,invite_expires,previous_hire_id) values (?,?,?,?,?,?,?,?,?,?)",
                id, "Ada", "Lovelace", LocalDate.of(1990, 1, 1), "ada@personal.example", "Risk", status, BankController.hash(id.toString()),
                Timestamp.from(Instant.now().plusSeconds(3600)), previous);
        return id;
    }

    private String credential(String issuer, String bankId, ECKey boundTo, Instant at) throws Exception {
        var configuration = new SdJwtVcCredentialConfiguration(issuer + "/vct/BankStaffCredential", List.of(), Map.of(), List.of(), List.of(), Optional.empty());
        return new SdJwtVcCredentialIssuanceService(issuerKey, List.of(), Duration.ofDays(1), Clock.fixed(at, java.time.ZoneOffset.UTC))
                .issue(configuration, Map.of("staff_id", staff.toString(), "bank_id", bankId), boundTo.toPublicJWK(), issuer);
    }

    /** The verifier's result for a presentation of {@code credential}: its claims and holder key as the library verifies them. */
    private ObjectNode verified(String credential, String issuer) throws Exception {
        String presented = credential + KbJwtBuilder.build(credential, "n", "aud", Instant.now(), JWSAlgorithm.ES256, new ECDSASigner(holderOf(credential))).serialize();
        var query = CredentialQuery.builder("staff", CredentialFormat.DC_SD_JWT).meta(new SdJwtVcMeta(List.of(issuer + "/vct/BankStaffCredential"))).build();
        var verified = new SdJwtVerifier().verify(new PresentationEntry.StringPresentation(presented), new PresentationVerificationParams(query, "n", "aud", "aud",
                "https://v.example/response", Optional.empty(), (i, kid, chain) -> Optional.of(JSON.valueToTree(issuerKey.toPublicJWK().toJSONObject())), Clock.systemUTC()));
        ObjectNode node = JSON.createObjectNode().put("format", "dc+sd-jwt").put("issuer", issuer);
        node.set("claims", verified.verifiedClaims());
        node.set("holderKey", verified.holderKeyConfirmed().orElseThrow());
        return node;
    }

    private final Map<String, ECKey> holders = new java.util.HashMap<>();

    private ECKey holderOf(String credential) throws Exception {
        String bound = JSON.readTree(com.nimbusds.jwt.SignedJWT.parse(credential.split("~")[0]).getPayload().toString()).path("cnf").path("jwk").path("x").asText();
        if (holder.getX().toString().equals(bound)) return holder;
        return holders.get(bound);
    }

    private BankController.NewPresentation start() {
        return bank.newPresentation(null, "authr");
    }

    private boolean settle(String id) {
        return Boolean.TRUE.equals(tx.execute(status -> bank.settle(id)));
    }

    private Map<String, Object> row(String id) {
        return db.queryForMap("select * from bank_presentation where id=?", id);
    }

    @Test
    void theVerifierCarriesOutTheRequestAndTheBankAnswersNeitherSideOfItself() throws Exception {
        var started = start();
        assertThat(started.walletUri()).isEqualTo("openid4vp://?client_id=x&request_uri=y");
        assertThat(started.requestUri()).isEqualTo("https://v.example/r/1");
        assertThat(row(started.id()).get("verifier_transaction_id")).isEqualTo("vt-1");

        assertThatThrownBy(() -> bank.request(started.id())).hasMessageContaining("not answered here");
        assertThatThrownBy(() -> bank.response(started.id(), started.id(), "{\"staff\":[\"x\"]}")).hasMessageContaining("not answered here");
        assertThat(row(started.id()).get("complete")).isEqualTo(false);
    }

    @Test
    void theJourneyHearsPendingThenCompleteAndSignsTheStaffMemberIn() {
        var started = start();
        assertThat(journey.presentation(started.id(), started.secret())).containsEntry("status", "pending");
        status = "verified";
        assertThat(journey.presentation(started.id(), started.secret())).containsEntry("status", "complete");
        assertThat(row(started.id()).get("staff_id")).isEqualTo(staff);
        assertThat(journey.consume(started.id(), started.secret())).containsEntry("staffSubject", staff.toString());
        assertThat(calls.stream().filter(c -> c.endsWith("/consume"))).hasSize(1);
    }

    @Test
    void someoneWithoutTheCompletionSecretCausesNothingToBeCollected() {
        var started = start();
        status = "verified";
        assertThatThrownBy(() -> journey.presentation(started.id(), "not-the-secret")).isInstanceOf(JourneyApiController.JourneyRefusal.class);
        assertThat(calls).noneMatch(c -> c.endsWith("/consume"));
        assertThat(row(started.id()).get("complete")).isEqualTo(false);
    }

    @Test
    void thePortalPageIsToldAndTheBrowserSignedIn() {
        var session = new MockHttpSession();
        var started = bank.newPresentation(null, "portal");
        session.setAttribute("vp:" + started.id(), started.secret());
        assertThat(bank.presentationStatus(started.id(), session)).contains("pending");
        status = "verified";
        assertThat(bank.presentationStatus(started.id(), session)).contains("complete");
        assertThat(bank.result(started.id(), session, new org.springframework.mock.web.MockHttpServletRequest() {{ getSession(); }})).isEqualTo("redirect:/staff");
        assertThat(session.getAttribute("staff")).isEqualTo(staff.toString());
    }

    @Test
    void anInactiveStaffMemberIsRefused() {
        db.update("update bank_hire set status='REVOKED' where id=?", staff);
        var started = start();
        status = "verified";
        assertThat(journey.presentation(started.id(), started.secret())).containsEntry("status", "refused").containsEntry("refusedReason", "staff_inactive");
    }

    @Test
    void aReplacedCredentialIsRefusedAsSuperseded() throws Exception {
        // Reissued since: the stored credential is a later one than the wallet presented.
        db.update("update bank_hire set issued_credential=? where id=?", credential(ISSUER, ISSUER, holder, Instant.now().minusSeconds(5)), staff);
        var started = start();
        status = "verified";
        assertThat(settle(started.id())).isTrue();
        assertThat(row(started.id()).get("refused_reason")).isEqualTo("staff_superseded");
    }

    @Test
    void aCredentialBoundToAnotherKeyThanTheStoredOneIsSuperseded() throws Exception {
        ECKey other = new ECKeyGenerator(Curve.P_256).generate();
        holders.put(other.getX().toString(), other);
        Instant at = Instant.now().minusSeconds(120);
        db.update("update bank_hire set issued_credential=? where id=?", credential(ISSUER, ISSUER, holder, at), staff);
        result = verified(credential(ISSUER, ISSUER, other, at), ISSUER);
        var started = start();
        status = "verified";
        assertThat(settle(started.id())).isTrue();
        assertThat(row(started.id()).get("refused_reason")).isEqualTo("staff_superseded");
    }

    @Test
    void aResultThatIsNotAStaffCredentialOfThisBankCompletesNothing() throws Exception {
        List<ObjectNode> unacceptable = new ArrayList<>();
        unacceptable.add(result.deepCopy().put("issuer", "https://passport.example"));                       // not the issuer the claims name
        ObjectNode stranger = result.deepCopy().put("issuer", "https://passport.example");                   // trusted by the verifier, not for this
        ((ObjectNode) stranger.get("claims")).put("iss", "https://passport.example");
        unacceptable.add(stranger);
        ObjectNode wrongType = result.deepCopy();
        ((ObjectNode) wrongType.get("claims")).put("vct", BASE + "/vct/BankStaffCredential");               // another issuer's type
        unacceptable.add(wrongType);
        ObjectNode wrongBank = result.deepCopy();
        ((ObjectNode) wrongBank.get("claims")).put("bank_id", BASE);
        unacceptable.add(wrongBank);
        ObjectNode expired = result.deepCopy();
        ((ObjectNode) expired.get("claims")).put("exp", Instant.now().minusSeconds(1).getEpochSecond());
        unacceptable.add(expired);
        ObjectNode noStaff = result.deepCopy();
        ((ObjectNode) noStaff.get("claims")).put("staff_id", "someone");
        unacceptable.add(noStaff);
        ObjectNode unbound = result.deepCopy();
        unbound.remove("holderKey");
        unacceptable.add(unbound);
        ObjectNode mdoc = result.deepCopy().put("format", "mso_mdoc");
        unacceptable.add(mdoc);

        for (ObjectNode answer : unacceptable) {
            result = answer;
            var started = start();
            status = "verified";
            assertThat(settle(started.id())).as(answer.toString()).isFalse();
            assertThat(row(started.id()).get("complete")).isEqualTo(false);
            assertThat(row(started.id()).get("refused_reason")).isNull();
        }
    }

    @Test
    void whileTheVerifierCannotBeReachedItStaysPendingAndNewSignInsSayUnavailable() {
        var started = start();
        down = true;
        assertThat(journey.presentation(started.id(), started.secret())).containsEntry("status", "pending");
        assertThatThrownBy(this::start).hasMessageContaining("unavailable");
        down = false;
        status = "verified";
        assertThat(journey.presentation(started.id(), started.secret())).containsEntry("status", "complete");
    }

    @Test
    void callersRacingCollectTheResultOnce() throws Exception {
        var started = start();
        status = "verified";
        var pool = Executors.newFixedThreadPool(6);
        List<Future<Boolean>> attempts = new ArrayList<>();
        for (int i = 0; i < 6; i++) attempts.add(pool.submit(() -> settle(started.id())));
        int changed = 0;
        for (Future<Boolean> attempt : attempts) if (attempt.get()) changed++;
        pool.shutdown();
        assertThat(changed).isEqualTo(1);
        assertThat(calls.stream().filter(c -> c.endsWith("/consume"))).hasSize(1);
        assertThat(row(started.id()).get("complete")).isEqualTo(true);
    }

    @Test
    void passportChecksAreStillTheBanksOwnAndSoIsStaffSignInWhenSwitchedBack() {
        UUID applicant = hire("INVITED", null);
        var passport = bank.newPresentation(applicant, "authr");
        assertThat(passport.requestUri()).startsWith(BASE + "/vp/request/");
        bank.setStaffVerification("embedded");
        var staffSignIn = start();
        assertThat(staffSignIn.requestUri()).startsWith(BASE + "/vp/request/");
        assertThat(row(staffSignIn.id()).get("verifier_transaction_id")).isNull();
        assertThat(calls).noneMatch(c -> c.contains("/tenant-api/"));
    }

    @Test
    void aResultStartedBeforeSwitchingBackIsStillCollected() {
        var started = start();
        bank.setStaffVerification("embedded");
        status = "verified";
        assertThat(journey.presentation(started.id(), started.secret())).containsEntry("status", "complete");
    }

    @Test
    void sharedVerificationNeedsTheVerifierAndASaneSetting() throws Exception {
        Path passport = dir.resolve("passport.jwk");
        var unconfigured = new BankController(db, mock(PreAuthorizedCodeStore.class), issuerKey, BASE, "https://passport.example", passport.toString(), "Bank");
        unconfigured.setStaffVerification("shared");
        assertThatThrownBy(unconfigured::checkStaffVerification).hasMessageContaining("bank.credentials.verifier");
        assertThatThrownBy(() -> unconfigured.setStaffVerification("both")).hasMessageContaining("shared or embedded");
    }
}
