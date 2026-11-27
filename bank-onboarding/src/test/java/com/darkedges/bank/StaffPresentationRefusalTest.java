package com.darkedges.bank;

import com.darkedges.oid4vci.core.metadata.SdJwtVcCredentialConfiguration;
import com.darkedges.oid4vci.issuer.PreAuthorizedCodeStore;
import com.darkedges.oid4vci.issuer.SdJwtVcCredentialIssuanceService;
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
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * A deactivated (or superseded) staff member presenting a valid staff credential: the bank refuses it, and records the refusal, so the
 * Authr journey waiting on it hears "refused" at once instead of waiting ten minutes for the request to expire.
 */
class StaffPresentationRefusalTest {
    static final ObjectMapper JSON = new ObjectMapper();
    static final String REFUSE_SQL = "update bank_presentation set refused_reason=? where id=? and refused_reason is null";
    @TempDir Path dir;
    JdbcTemplate db; BankController bank; ECKey bankKey, holder; UUID staff; String current;

    @BeforeEach void setup() throws Exception {
        db = mock(JdbcTemplate.class);
        bankKey = new ECKeyGenerator(Curve.P_256).generate();
        holder = new ECKeyGenerator(Curve.P_256).generate();
        Path passportKey = dir.resolve("passport.jwk");
        Files.writeString(passportKey, new ECKeyGenerator(Curve.P_256).generate().toPublicJWK().toJSONString());
        bank = new BankController(db, mock(PreAuthorizedCodeStore.class), bankKey, "http://bank", "http://passport", passportKey.toString(), "Bank");
        staff = UUID.randomUUID();
        var tx = new HashMap<String, Object>(); tx.put("nonce", "expected"); tx.put("complete", false); tx.put("hire_id", null);
        when(db.queryForMap(anyString(), eq("transaction"))).thenReturn(tx);
        current = staffCredential();
        when(db.queryForMap("select issued_credential from bank_hire where id=?", staff)).thenReturn(Map.of("issued_credential", current));
    }

    String staffCredential() throws Exception {
        var config = new SdJwtVcCredentialConfiguration("http://bank/vct/BankStaffCredential", List.of(), Map.of(), List.of(), List.of(), Optional.empty());
        return new SdJwtVcCredentialIssuanceService(bankKey, List.of(), Duration.ofDays(1), Clock.systemUTC())
                .issue(config, Map.of("staff_id", staff.toString(), "bank_id", "http://bank"), holder.toPublicJWK(), "http://bank");
    }

    String vpToken(String credential) throws Exception {
        String kb = KbJwtBuilder.build(credential, "expected", "redirect_uri:http://bank/vp/response/transaction", Instant.now(), JWSAlgorithm.ES256, new ECDSASigner(holder)).serialize();
        return JSON.writeValueAsString(Map.of("staff", List.of(credential + kb)));
    }

    void staffIsActive(boolean active) {
        when(db.queryForObject(contains("not exists"), eq(Integer.class), eq(staff))).thenReturn(active ? 1 : 0);
    }

    @Test void aDeactivatedStaffMembersCredentialIsRefusedAndTheRefusalRecorded() throws Exception {
        staffIsActive(false);
        String vp = vpToken(current);
        assertThatThrownBy(() -> bank.response("transaction", "transaction", vp))
                .isInstanceOfSatisfying(BankController.PresentationRefused.class, e -> {
                    assertThat(e.reason).isEqualTo("staff_inactive");
                    assertThat(e.getStatusCode().value()).isEqualTo(400);
                });
        verify(db).update(REFUSE_SQL, "staff_inactive", "transaction");
        verify(db, never()).update(startsWith("update bank_presentation set complete=true"), any(), any());
    }

    @Test void aSupersededCredentialIsRefusedAsSuperseded() throws Exception {
        staffIsActive(true);
        String older = staffCredential();
        assertThatThrownBy(() -> bank.response("transaction", "transaction", vpToken(older)))
                .isInstanceOfSatisfying(BankController.PresentationRefused.class, e -> assertThat(e.reason).isEqualTo("staff_superseded"));
        verify(db).update(REFUSE_SQL, "staff_superseded", "transaction");
    }

    @Test void somethingThatDoesNotVerifyLeavesThePresentationPending() throws Exception {
        staffIsActive(false);
        // Signed by a key the bank doesn't trust: whoever sent it can't end someone else's sign-in.
        bankKey = new ECKeyGenerator(Curve.P_256).generate();
        String forged = vpToken(staffCredential());
        assertThatThrownBy(() -> bank.response("transaction", "transaction", forged)).isNotInstanceOf(BankController.PresentationRefused.class);
        assertThatThrownBy(() -> bank.response("transaction", "transaction", "{\"staff\":[\"garbage\"]}")).isNotInstanceOf(BankController.PresentationRefused.class);
        verify(db, never()).update(eq(REFUSE_SQL), any(), any());
    }

    @Test void aRefusedPresentationCannotBeAnsweredAgain() throws Exception {
        staffIsActive(true);
        var tx = new HashMap<String, Object>(); tx.put("nonce", "expected"); tx.put("complete", false); tx.put("hire_id", null); tx.put("refused_reason", "staff_inactive");
        when(db.queryForMap(anyString(), eq("transaction"))).thenReturn(tx);
        String vp = vpToken(current);
        assertThatThrownBy(() -> bank.response("transaction", "transaction", vp)).hasMessageContaining("refused");
        verify(db, never()).update(startsWith("update bank_presentation set complete=true"), any(), any());
    }

    @Test void theRefusalIsKeptWhenTheWalletIsAnswered400() throws Exception {
        Transactional tx = BankController.class.getDeclaredMethod("response", String.class, String.class, String.class).getAnnotation(Transactional.class);
        assertThat(tx.noRollbackFor()).contains(BankController.PresentationRefused.class);
    }

    @Test void aStaffSignInRefusedByAuthStackShowsTheStaffMessageAndNothingElseDoes() {
        var denied = new org.springframework.security.oauth2.core.OAuth2AuthenticationException(new org.springframework.security.oauth2.core.OAuth2Error("access_denied"));
        var other = new org.springframework.security.oauth2.core.OAuth2AuthenticationException(new org.springframework.security.oauth2.core.OAuth2Error("invalid_token_response"));
        assertThat(BankSecurity.signInFailurePage("/login/oauth2/code/staff", denied)).isEqualTo("/?staff=refused");
        assertThat(BankSecurity.signInFailurePage("/login/oauth2/code/staff", other)).isEqualTo("/?signin=failed");
        // An HR sign-in refused by the HR provider is not a staff matter.
        assertThat(BankSecurity.signInFailurePage("/login/oauth2/code/hr", denied)).isEqualTo("/?signin=failed");
        assertThat(BankSecurity.signInFailurePage(null, denied)).isEqualTo("/?signin=failed");
    }

    @Test void oneStatusForThePortalAndTheJourney() {
        assertThat(BankController.presentationStatus(Map.of(), true)).isEqualTo("pending");
        assertThat(BankController.presentationStatus(Map.of("refused_reason", "staff_inactive"), true)).isEqualTo("refused");
        assertThat(BankController.presentationStatus(Map.of("complete", true), true)).isEqualTo("complete");
        // Expiry wins, as it always has.
        assertThat(BankController.presentationStatus(Map.of("refused_reason", "staff_inactive"), false)).isEqualTo("expired");
    }
}
