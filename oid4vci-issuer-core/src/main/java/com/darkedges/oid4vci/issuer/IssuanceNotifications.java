package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vci.core.error.Oid4vciErrorCode;
import com.darkedges.oid4vci.core.error.Oid4vciException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * The Notification Endpoint's rules (OID4VCI 1.0, Section 11): a wallet says a credential was accepted, failed or was deleted.
 *
 * <p>A credential is usually deleted long after the access token that fetched it has expired. So each credential response carries,
 * beside its {@code notification_id}, a <em>notification token</em>: long-lived, good for notifying about that one response and
 * nothing else, and sender-constrained (RFC 9449, {@code cnf.jkt}) to the holder key the first credential is bound to. A wallet
 * presents it with the {@code DPoP} scheme and a proof signed with that key. It is signed with the tenant's key, so removing a
 * retired key also ends the notification tokens it signed.
 *
 * <p>A deletion is recorded and shown to the tenant. It revokes nothing: removing a credential from one wallet is not the tenant
 * withdrawing it.
 */
public final class IssuanceNotifications {

    /** The claim that marks a notification token; the Credential Endpoint refuses a token carrying it. */
    public static final String TOKEN_USE_CLAIM = "token_use";
    public static final String TOKEN_USE = "notification";
    public static final String NOTIFICATION_ID_CLAIM = "notification_id";
    public static final Set<String> EVENTS = Set.of("credential_accepted", "credential_failure", "credential_deleted");
    public static final int MAX_DESCRIPTION = 256;
    /** At most this many events are kept for one tenant reference, the oldest dropped first. */
    static final int MAX_EVENTS = 100;

    private final IssuanceNotificationStore store;
    private final IssuerKeys keys;
    private final Duration tokenTtl;
    private final Clock clock;

    public IssuanceNotifications(IssuanceNotificationStore store, IssuerKeys keys, Duration tokenTtl, Clock clock) {
        this.store = store;
        this.keys = keys;
        this.tokenTtl = tokenTtl;
        this.clock = clock;
    }

    /** What a credential response adds. */
    public record Registration(String notificationId, String token, long expiresIn) {}

    /**
     * Who is notifying, from the verified access token.
     *
     * @param notificationToken whether it is a notification token, good only for {@code notificationId}
     */
    public record Caller(String subject, boolean notificationToken, String notificationId) {}

    public Registration register(IssuerContext context, String subject, String credentialConfigurationId, Optional<String> reference,
                                 String holderKeyThumbprint) {
        Instant now = clock.instant();
        Instant expiresAt = now.plus(tokenTtl);
        String notificationId = UUID.randomUUID().toString();
        store.save(context.scope(notificationId),
                new IssuanceNotificationStore.Issuance(subject, credentialConfigurationId, reference, now, expiresAt, Set.of()));

        ECKey key = keys.signingKey(context);
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(context.issuerIdentifier())
                .audience(context.issuerIdentifier())
                .subject(subject)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(expiresAt))
                .jwtID(UUID.randomUUID().toString())
                .claim(TOKEN_USE_CLAIM, TOKEN_USE)
                .claim(NOTIFICATION_ID_CLAIM, notificationId)
                .claim("cnf", Map.of("jkt", holderKeyThumbprint))
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID()).build(), claims);
        try {
            jwt.sign(new ECDSASigner(key));
        } catch (JOSEException e) {
            throw new IllegalStateException("failed to sign a notification token", e);
        }
        return new Registration(notificationId, jwt.serialize(), tokenTtl.toSeconds());
    }

    /**
     * Records one notification. Repeating one changes nothing.
     *
     * @throws Oid4vciException {@code invalid_notification_request} for an unknown event or an over-long description;
     *                          {@code invalid_notification_id} for an id this caller may not notify about, whether or not it exists
     */
    public void receive(IssuerContext context, Caller caller, String notificationId, String event, Optional<String> description) {
        if (notificationId == null || notificationId.isBlank() || event == null || !EVENTS.contains(event)) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_NOTIFICATION_REQUEST, "notification_id and a known event are required");
        }
        if (description.map(d -> d.length() > MAX_DESCRIPTION).orElse(false)) {
            throw new Oid4vciException(Oid4vciErrorCode.INVALID_NOTIFICATION_REQUEST, "event_description is too long");
        }
        Instant now = clock.instant();
        Optional<String> key = context.scopeIfValid(notificationId);
        IssuanceNotificationStore.Issuance issuance = key.flatMap(k -> store.find(k, now))
                .filter(i -> caller.notificationToken()
                        ? notificationId.equals(caller.notificationId())
                        : i.subject().equals(caller.subject()))
                .orElseThrow(() -> new Oid4vciException(Oid4vciErrorCode.INVALID_NOTIFICATION_ID, "no such notification_id"));
        if (issuance.received().contains(event)) return;

        // The tenant's list first: if the second write fails, the wallet's retry records it again rather than losing it.
        issuance.reference().ifPresent(reference -> {
            String referenceKey = context.scope(reference);
            List<IssuanceNotificationStore.Event> events = new ArrayList<>(store.events(referenceKey, now));
            events.removeIf(e -> e.notificationId().equals(notificationId) && e.event().equals(event));
            events.add(new IssuanceNotificationStore.Event(notificationId, issuance.credentialConfigurationId(), event, description, now));
            while (events.size() > MAX_EVENTS) events.remove(0);
            store.saveEvents(referenceKey, events, now.plus(tokenTtl));
        });
        Set<String> received = new HashSet<>(issuance.received());
        received.add(event);
        store.save(key.orElseThrow(), new IssuanceNotificationStore.Issuance(issuance.subject(), issuance.credentialConfigurationId(),
                issuance.reference(), issuance.issuedAt(), issuance.expiresAt(), received));
    }

    /** The notifications received for one of the tenant's references, oldest first. */
    public List<IssuanceNotificationStore.Event> events(IssuerContext context, String reference) {
        return store.events(context.scope(reference), clock.instant());
    }
}
