package com.darkedges.bank;

import com.darkedges.oid4vci.core.metadata.SdJwtVcCredentialConfiguration;
import com.darkedges.oid4vci.issuer.*;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.sdjwt.KbJwtBuilder;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.env.MockEnvironment;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/** The bank on the multi-tenant issuer: passports from several trusted issuers (tenants among them), and issuing only as itself. */
class BankTenantIssuersTest {
    static final String PLATFORM = "https://issuer.zkp.au", TENANT = "https://issuer.zkp.au/t/bank";
    static final ObjectMapper JSON = new ObjectMapper();
    @TempDir Path dir;
    JdbcTemplate db; BankController bank; ECKey platformKey, tenantKey, holder, bankKey; UUID hire;

    @BeforeEach void setup() throws Exception {
        db = mock(JdbcTemplate.class);
        platformKey = new ECKeyGenerator(Curve.P_256).generate();
        tenantKey = new ECKeyGenerator(Curve.P_256).generate();
        holder = new ECKeyGenerator(Curve.P_256).generate();
        bankKey = new ECKeyGenerator(Curve.P_256).generate();
        var env = new MockEnvironment()
                .withProperty("bank.passport-issuers[0].issuer", PLATFORM)
                .withProperty("bank.passport-issuers[0].key-file", write("platform.jwk", platformKey))
                .withProperty("bank.passport-issuers[1].issuer", TENANT + "/")
                .withProperty("bank.passport-issuers[1].key-file", write("tenant.jwk", tenantKey));
        bank = new BankController(db, mock(PreAuthorizedCodeStore.class), bankKey, "http://bank", PassportTrust.from(env), "Example Bank");
        hire = UUID.randomUUID();
        when(db.queryForMap(anyString(), eq("transaction"))).thenReturn(Map.of("nonce", "expected", "hire_id", hire, "complete", false));
        when(db.update(startsWith("update bank_hire"), any(), any(), any(), any(), any())).thenReturn(1);
    }

    String write(String name, ECKey key) throws Exception {
        Path file = dir.resolve(name);
        Files.writeString(file, key.toPublicJWK().toJSONString());
        return file.toString();
    }

    /** A proofed passport issued as {@code iss} with type {@code vct}, signed by {@code signer}, presented with a key binding. */
    String presentation(ECKey signer, String iss, String vct) throws Exception {
        var config = new SdJwtVcCredentialConfiguration(vct, List.of(), Map.of(), List.of(), List.of(), Optional.empty());
        String credential = new SdJwtVcCredentialIssuanceService(signer, List.of(), Duration.ofDays(1), Clock.systemUTC()).issue(config,
                Map.of("given_name", "Jane", "family_name", "Smith", "birth_date", "1990-01-01", "assurance_level", "poc-demo", "expiry_date", "2099-01-01",
                        "evidence", "liveness=passed; face-match=passed; chip-signature=verified; csca-chain=verified; portrait-from-chip=verified"),
                holder.toPublicJWK(), iss);
        String kb = KbJwtBuilder.build(credential, "expected", "redirect_uri:http://bank/vp/response/transaction", Instant.now(), JWSAlgorithm.ES256, new ECDSASigner(holder)).serialize();
        return JSON.writeValueAsString(Map.of("passport", List.of(credential + kb)));
    }

    @Test void asksForAPassportFromEveryTrustedIssuer() {
        assertThat(bank.vcts("passport")).containsExactly(PLATFORM + "/vct/PassportCredential", TENANT + "/vct/PassportCredential");
        assertThat(bank.vcts("staff")).containsExactly("http://bank/vct/BankStaffCredential");
    }

    @Test void acceptsAPassportFromATenantIssuer() throws Exception {
        assertThat(bank.response("transaction", "transaction", presentation(tenantKey, TENANT, TENANT + "/vct/PassportCredential"))).isEqualTo("{}");
    }

    @Test void acceptsAPassportFromThePlatformIssuer() throws Exception {
        assertThat(bank.response("transaction", "transaction", presentation(platformKey, PLATFORM, PLATFORM + "/vct/PassportCredential"))).isEqualTo("{}");
    }

    @Test void refusesOneTrustedIssuerVouchingForAnothersType() throws Exception {
        // Signed by the platform issuer (trusted) as itself, but claiming the tenant's passport type.
        String crossed = presentation(platformKey, PLATFORM, TENANT + "/vct/PassportCredential");
        assertThatThrownBy(() -> bank.response("transaction", "transaction", crossed)).isInstanceOf(RuntimeException.class);
        verify(db, never()).update(startsWith("update bank_hire"), any(), any(), any(), any(), any());
    }

    @Test void refusesAPassportSignedWithAnotherTrustedIssuersKey() throws Exception {
        String forged = presentation(platformKey, TENANT, TENANT + "/vct/PassportCredential");
        assertThatThrownBy(() -> bank.response("transaction", "transaction", forged)).isInstanceOf(RuntimeException.class);
        verify(db, never()).update(startsWith("update bank_hire"), any(), any(), any(), any(), any());
    }

    @Test void refusesAnUntrustedTenant() throws Exception {
        ECKey other = new ECKeyGenerator(Curve.P_256).generate();
        String untrusted = presentation(other, "https://issuer.zkp.au/t/other", "https://issuer.zkp.au/t/other/vct/PassportCredential");
        assertThatThrownBy(() -> bank.response("transaction", "transaction", untrusted)).isInstanceOf(RuntimeException.class);
    }

    @Test void theOldSingleIssuerSettingsStillWork() throws Exception {
        var env = new MockEnvironment().withProperty("bank.passport-issuer", PLATFORM).withProperty("bank.passport-key-file", write("single.jwk", platformKey));
        assertThat(PassportTrust.from(env).issuers()).containsExactly(PLATFORM);
    }

    @Test void refusesBadTrustSettings() throws Exception {
        String key = write("k.jwk", platformKey);
        Path secret = dir.resolve("private.jwk");
        Files.writeString(secret, platformKey.toJSONString());
        assertThatThrownBy(() -> PassportTrust.from(new MockEnvironment()
                .withProperty("bank.passport-issuers[0].issuer", PLATFORM).withProperty("bank.passport-issuers[0].key-file", secret.toString())))
                .hasMessageContaining("public only");
        assertThatThrownBy(() -> PassportTrust.from(new MockEnvironment()
                .withProperty("bank.passport-issuers[0].issuer", PLATFORM).withProperty("bank.passport-issuers[0].key-file", key)
                .withProperty("bank.passport-issuers[1].issuer", PLATFORM + "/").withProperty("bank.passport-issuers[1].key-file", key)))
                .hasMessageContaining("twice");
        assertThatThrownBy(() -> PassportTrust.from(new MockEnvironment()
                .withProperty("bank.passport-issuers[0].issuer", PLATFORM + "?x=1").withProperty("bank.passport-issuers[0].key-file", key)))
                .hasMessageContaining("query");
    }

    @Test void issuesOnlyAsTheBankItself() {
        CredentialIssuanceServiceResolver resolver = new BankSecurity().credentialIssuanceServiceResolver(bankKey, db, "http://bank",
                new org.springframework.beans.factory.support.StaticListableBeanFactory().getBeanProvider(DirectoryOutbox.class));
        assertThat(resolver.resolve(IssuerContext.single("http://bank"), CredentialFormat.MSO_MDOC)).isEmpty();
        CredentialIssuanceService staff = resolver.resolve(IssuerContext.single("http://bank"), CredentialFormat.DC_SD_JWT).orElseThrow();
        var config = new SdJwtVcCredentialConfiguration("http://bank/vct/BankStaffCredential", List.of(), Map.of(), List.of(), List.of(), Optional.empty());
        var claims = Map.of("staff_id", UUID.randomUUID().toString());
        assertThatThrownBy(() -> staff.issue(new IssuerContext("tenant-a", "https://bank.example/t/a"), config, claims, holder.toPublicJWK()))
                .hasMessageContaining("only as itself");
        assertThatThrownBy(() -> staff.issue(IssuerContext.single("https://elsewhere.example"), config, claims, holder.toPublicJWK()))
                .hasMessageContaining("canonical");
        verifyNoInteractions(db);
    }
}
