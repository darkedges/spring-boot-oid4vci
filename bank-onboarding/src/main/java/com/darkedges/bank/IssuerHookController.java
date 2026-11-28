package com.darkedges.bank;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * The bank's say when the shared issuer issues a staff credential (its issuance hook; bank-onboarding/docs/migration-to-shared-services.md,
 * 1.2). The issuer asks {@code authorize} just before it signs, and tells {@code issued} just after. Every call is checked to come from
 * the bank's own tenant of the issuer ({@link SharedIssuer#verifyHookCall}). The rules are the bank's, as when it was the issuer itself:
 * <ul>
 *   <li>the hire exists, is APPROVED or ACTIVE, and no newer attempt has replaced it;</li>
 *   <li>the wallet proves the key its passport presentation proved;</li>
 *   <li>a format is issued once per hire.</li>
 * </ul>
 * {@code issued} records the credential (per format), and then, as before, the hire becomes ACTIVE, the audit says ISSUED, and the
 * AuthStack directory hears of it. {@code notified} says what a wallet reported: a staff credential deleted from the wallet is
 * recorded, audited and shown to HR. It revokes nothing; the hire's status is HR's to change.
 */
@RestController
@RequestMapping(path = "/api/issuer-hook/v1", produces = MediaType.APPLICATION_JSON_VALUE)
public class IssuerHookController {

    private static final ObjectMapper JSON = new ObjectMapper();
    private final JdbcTemplate db;
    private final ObjectProvider<SharedIssuer> shared;
    private final ObjectProvider<DirectoryOutbox> directory;

    public IssuerHookController(JdbcTemplate db, ObjectProvider<SharedIssuer> shared, ObjectProvider<DirectoryOutbox> directory) {
        this.db = db;
        this.shared = shared;
        this.directory = directory;
    }

    record Call(UUID hire, String configurationId, String format, String holderKeyThumbprint, String credential) {}

    @PostMapping(path = "/authorize", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> authorize(@RequestHeader(name = "Authorization", required = false) String authorization,
                                                         @RequestBody String rawBody) {
        Call call;
        try {
            call = checked(authorization, rawBody, "authorize");
        } catch (Refusal r) {
            return r.answer();
        }
        String refusal = refusal(call);
        if (refusal != null) return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("allow", false, "reason", refusal));
        return ResponseEntity.ok(Map.of("allow", true));
    }

    @PostMapping(path = "/issued", consumes = MediaType.APPLICATION_JSON_VALUE) @Transactional
    public ResponseEntity<Map<String, Object>> issued(@RequestHeader(name = "Authorization", required = false) String authorization,
                                                      @RequestBody String rawBody) {
        Call call;
        try {
            call = checked(authorization, rawBody, "issued");
        } catch (Refusal r) {
            return r.answer();
        }
        if (call.credential() == null || call.credential().isBlank()) return ResponseEntity.badRequest().body(Map.of("error", "invalid_request"));
        // Idempotent: the issuer retries this call, so a second one for the same hire and format changes nothing.
        int recorded = db.update("insert into bank_issued_credential(hire_id, format, credential_configuration_id, credential) values (?,?,?,?) on conflict do nothing",
                call.hire(), call.format(), call.configurationId(), call.credential());
        if (recorded == 1) {
            // The SD-JWT is the one the bank checks staff sign-ins against (superseded or not), as it was when the bank issued it itself.
            if ("dc+sd-jwt".equals(call.format())) {
                db.update("update bank_hire set status='ACTIVE', issued_credential=? where id=? and status in ('APPROVED','ACTIVE')", call.credential(), call.hire());
            } else {
                db.update("update bank_hire set status='ACTIVE' where id=? and status='APPROVED'", call.hire());
            }
            db.update("insert into bank_audit(hire_id,action,actor) values (?,'ISSUED','issuer')", call.hire());
            directory.ifAvailable(outbox -> outbox.changed(call.hire()));
        }
        return ResponseEntity.noContent().build();
    }

    @PostMapping(path = "/notified", consumes = MediaType.APPLICATION_JSON_VALUE) @Transactional
    public ResponseEntity<Map<String, Object>> notified(@RequestHeader(name = "Authorization", required = false) String authorization,
                                                        @RequestBody String rawBody) {
        Call call;
        String event;
        try {
            call = checked(authorization, rawBody, "notified");
            event = JSON.readTree(rawBody).path("event").asText();
        } catch (Refusal r) {
            return r.answer();
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid_request"));
        }
        // Only a deletion changes anything here. Idempotent: the issuer retries, and one already recorded matches no row.
        if ("credential_deleted".equals(event)
                && db.update("update bank_issued_credential set deleted_at=now() where hire_id=? and credential_configuration_id=? and deleted_at is null",
                        call.hire(), call.configurationId()) > 0) {
            db.update("insert into bank_audit(hire_id,action,actor) values (?,'CREDENTIAL_DELETED','wallet')", call.hire());
        }
        return ResponseEntity.noContent().build();
    }

    /** Why this credential may not be issued now, or null. */
    String refusal(Call call) {
        var rows = db.queryForList("select status, holder_jwk from bank_hire where id=?", call.hire());
        if (rows.isEmpty()) return "unknown_reference";
        var hire = rows.getFirst();
        if (!Set.of("APPROVED", "ACTIVE").contains(String.valueOf(hire.get("status")))) return "staff_inactive";
        if (!db.queryForList("select id from bank_hire where previous_hire_id=?", call.hire()).isEmpty()) return "superseded";
        try {
            if (!(hire.get("holder_jwk") instanceof String jwk) || !ECKey.parse(jwk).computeThumbprint().toString().equals(call.holderKeyThumbprint())) return "wrong_holder";
        } catch (Exception e) {
            return "wrong_holder";
        }
        Integer issued = db.queryForObject("select count(*) from bank_issued_credential where hire_id=? and format=?", Integer.class, call.hire(), call.format());
        if (issued != null && issued > 0) return "already_issued";
        return null;
    }

    private Call checked(String authorization, String rawBody, String path) {
        SharedIssuer issuer = shared.getIfAvailable();
        if (issuer == null) throw new Refusal(HttpStatus.NOT_FOUND, "not_found");
        try {
            issuer.verifyHookCall(authorization, rawBody, path);
        } catch (SharedIssuer.HookCallRejected e) {
            throw new Refusal(HttpStatus.UNAUTHORIZED, "invalid_token");
        }
        try {
            JsonNode body = JSON.readTree(rawBody);
            return new Call(UUID.fromString(body.path("reference").asText()), body.path("credentialConfigurationId").asText(),
                    body.path("format").asText(), body.path("holderKeyThumbprint").asText(), body.path("credential").asText(null));
        } catch (Exception e) {
            // A reference that isn't a hire id is not one of the bank's offers.
            throw new Refusal(HttpStatus.CONFLICT, "unknown_reference");
        }
    }

    private static final class Refusal extends RuntimeException {
        final HttpStatus status;
        final String code;
        Refusal(HttpStatus status, String code) { super(code); this.status = status; this.code = code; }
        ResponseEntity<Map<String, Object>> answer() {
            return status == HttpStatus.CONFLICT ? ResponseEntity.status(status).body(Map.of("allow", false, "reason", code))
                    : ResponseEntity.status(status).body(Map.of("error", code));
        }
    }
}
