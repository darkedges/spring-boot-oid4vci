package com.darkedges.bank;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** The bank's issuance hook: only its own tenant of the shared issuer may call it, and the bank's rules decide what is issued. */
class IssuerHookTest {

    static final String ISSUER = "https://issuer.bank.example";
    static final String HOOK = "https://hr.bank.example/api/issuer-hook/v1";

    static ECKey tenantKey, otherKey;
    SharedIssuer shared;

    @BeforeAll static void keys() throws Exception {
        tenantKey = new ECKeyGenerator(Curve.P_256).keyID("tenant").generate();
        otherKey = new ECKeyGenerator(Curve.P_256).keyID("tenant").generate();
    }

    @BeforeEach void issuer() {
        shared = new SharedIssuer(new SharedIssuer.Settings(ISSUER, null, "", "", HOOK, List.of("BankStaffCredential"), true),
                HttpClient.newHttpClient(), Clock.systemUTC(), new ImmutableJWKSet<>(new JWKSet(tenantKey.toPublicJWK())));
    }

    static String hookToken(ECKey key, String issuer, String path, String body, JOSEObjectType type) throws Exception {
        Instant now = Instant.now();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(type).keyID(key.getKeyID()).build(),
                new JWTClaimsSet.Builder().issuer(issuer).audience(HOOK + "/" + path).issueTime(Date.from(now))
                        .expirationTime(Date.from(now.plusSeconds(60))).jwtID(UUID.randomUUID().toString())
                        .claim("body_sha256", SharedIssuer.sha256(body.getBytes(StandardCharsets.UTF_8))).build());
        jwt.sign(new ECDSASigner(key));
        return "Bearer " + jwt.serialize();
    }

    static String hookToken(String path, String body) throws Exception {
        return hookToken(tenantKey, ISSUER, path, body, new JOSEObjectType("hook+jwt"));
    }

    @Nested class HookTokens {
        final String body = "{\"reference\":\"x\"}";

        @Test void acceptsTheTenantsOwnCall() throws Exception {
            assertThatCode(() -> shared.verifyHookCall(hookToken("authorize", body), body, "authorize")).doesNotThrowAnyException();
        }

        @Test void refusesAReplay() throws Exception {
            String token = hookToken("authorize", body);
            shared.verifyHookCall(token, body, "authorize");
            assertThatThrownBy(() -> shared.verifyHookCall(token, body, "authorize")).isInstanceOf(SharedIssuer.HookCallRejected.class);
        }

        @Test void refusesAnotherBody() throws Exception {
            String token = hookToken("authorize", body);
            assertThatThrownBy(() -> shared.verifyHookCall(token, "{\"reference\":\"y\"}", "authorize")).isInstanceOf(SharedIssuer.HookCallRejected.class);
        }

        @Test void refusesATokenForTheOtherHookPath() throws Exception {
            String token = hookToken("issued", body);
            assertThatThrownBy(() -> shared.verifyHookCall(token, body, "authorize")).isInstanceOf(SharedIssuer.HookCallRejected.class);
        }

        @Test void refusesAnotherKeyAnotherIssuerOrAnotherType() throws Exception {
            for (String token : List.of(
                    hookToken(otherKey, ISSUER, "authorize", body, new JOSEObjectType("hook+jwt")),
                    hookToken(tenantKey, "https://issuer.zkp.au/t/demo", "authorize", body, new JOSEObjectType("hook+jwt")),
                    hookToken(tenantKey, ISSUER, "authorize", body, JOSEObjectType.JWT))) {
                assertThatThrownBy(() -> shared.verifyHookCall(token, body, "authorize")).isInstanceOf(SharedIssuer.HookCallRejected.class);
            }
            assertThatThrownBy(() -> shared.verifyHookCall(null, body, "authorize")).isInstanceOf(SharedIssuer.HookCallRejected.class);
        }
    }

    @Nested class AgainstPostgres {
        JdbcTemplate db;
        IssuerHookController hook;
        ECKey holder;
        UUID hire;

        @SuppressWarnings("unchecked")
        @BeforeEach void setUp() throws Exception {
            String url = System.getenv("BANK_TEST_DATABASE_URL");
            Assumptions.assumeTrue(url != null && !url.isBlank(), "BANK_TEST_DATABASE_URL not set");
            db = new JdbcTemplate(new DriverManagerDataSource(url));
            db.execute("drop table if exists bank_issued_credential, bank_directory_outbox, bank_applicant_ref, bank_presentation, bank_audit, bank_hire cascade");
            for (String statement : new String(getClass().getResourceAsStream("/schema.sql").readAllBytes()).split(";")) if (!statement.isBlank()) db.execute(statement);
            ObjectProvider<SharedIssuer> issuers = mock(ObjectProvider.class);
            when(issuers.getIfAvailable()).thenReturn(shared);
            hook = new IssuerHookController(db, issuers, mock(ObjectProvider.class));
            holder = new ECKeyGenerator(Curve.P_256).generate();
            hire = UUID.randomUUID();
            db.update("insert into bank_hire(id,expected_given,expected_family,birth_date,email,department,status,holder_jwk) values (?,'Ada','Lovelace','1990-01-01','ada@bank.example','Risk','APPROVED',?)",
                    hire, holder.toPublicJWK().toJSONString());
        }

        String body(String format, String thumbprint, String credential) {
            return "{\"reference\":\"" + hire + "\",\"credentialConfigurationId\":\"BankStaffCredential\",\"format\":\"" + format
                    + "\",\"holderKeyThumbprint\":\"" + thumbprint + "\"" + (credential == null ? "" : ",\"credential\":\"" + credential + "\"") + "}";
        }

        int authorize(String body) throws Exception {
            return hook.authorize(hookToken("authorize", body), body).getStatusCode().value();
        }

        @Test void allowsTheApprovedHiresOwnWalletOncePerFormat() throws Exception {
            String thumbprint = holder.computeThumbprint().toString();
            assertThat(authorize(body("dc+sd-jwt", thumbprint, null))).isEqualTo(200);

            String issued = body("dc+sd-jwt", thumbprint, "eyJ.sd-jwt~");
            assertThat(hook.issued(hookToken("issued", issued), issued).getStatusCode().value()).isEqualTo(204);
            // The issuer retries "issued": the second call changes nothing.
            assertThat(hook.issued(hookToken("issued", issued), issued).getStatusCode().value()).isEqualTo(204);
            assertThat(db.queryForMap("select status, issued_credential from bank_hire where id=?", hire))
                    .containsEntry("status", "ACTIVE").containsEntry("issued_credential", "eyJ.sd-jwt~");
            assertThat(db.queryForObject("select count(*) from bank_audit where hire_id=? and action='ISSUED'", Integer.class, hire)).isEqualTo(1);

            // Issued once per format: another SD-JWT is refused; the mdoc may still be issued.
            assertThat(authorize(body("dc+sd-jwt", thumbprint, null))).isEqualTo(409);
            assertThat(authorize(body("mso_mdoc", thumbprint, null))).isEqualTo(200);
        }

        @Test void aDeletionInTheWalletIsRecordedOnceAndRevokesNothing() throws Exception {
            String issued = body("dc+sd-jwt", holder.computeThumbprint().toString(), "eyJ.sd-jwt~");
            hook.issued(hookToken("issued", issued), issued);
            String deleted = "{\"reference\":\"" + hire + "\",\"credentialConfigurationId\":\"BankStaffCredential\",\"event\":\"credential_deleted\",\"notificationId\":\"n1\"}";
            String accepted = deleted.replace("credential_deleted", "credential_accepted");

            assertThat(hook.notified(hookToken("notified", accepted), accepted).getStatusCode().value()).isEqualTo(204);
            assertThat(db.queryForObject("select count(*) from bank_issued_credential where deleted_at is not null", Integer.class)).isZero();
            assertThat(hook.notified(null, deleted).getStatusCode().value()).isEqualTo(401);
            assertThat(hook.notified(hookToken("issued", deleted), deleted).getStatusCode().value()).isEqualTo(401);
            for (int i = 0; i < 2; i++) assertThat(hook.notified(hookToken("notified", deleted), deleted).getStatusCode().value()).isEqualTo(204);

            assertThat(db.queryForObject("select count(*) from bank_issued_credential where deleted_at is not null", Integer.class)).isEqualTo(1);
            assertThat(db.queryForObject("select count(*) from bank_audit where hire_id=? and action='CREDENTIAL_DELETED'", Integer.class, hire)).isEqualTo(1);
            assertThat(db.queryForObject("select status from bank_hire where id=?", String.class, hire)).isEqualTo("ACTIVE");
        }

        @Test void refusesAnotherWalletAClosedHireAnUnknownOneAndAnUnsignedCall() throws Exception {
            String thumbprint = holder.computeThumbprint().toString();
            assertThat(authorize(body("dc+sd-jwt", new ECKeyGenerator(Curve.P_256).generate().computeThumbprint().toString(), null))).isEqualTo(409);

            String unknown = body("dc+sd-jwt", thumbprint, null).replace(hire.toString(), UUID.randomUUID().toString());
            assertThat(authorize(unknown)).isEqualTo(409);
            assertThat(authorize("{\"reference\":\"step3-live-check\"}")).isEqualTo(409);

            String body = body("dc+sd-jwt", thumbprint, null);
            assertThat(hook.authorize(null, body).getStatusCode().value()).isEqualTo(401);

            db.update("update bank_hire set status='REVOKED' where id=?", hire);
            assertThat(authorize(body)).isEqualTo(409);
        }
    }
}
