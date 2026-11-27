package com.darkedges.oid4vci.issuer;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * What the issuer remembers so a wallet can tell it later what became of a credential ({@link IssuanceNotifications}). No claim
 * values are kept. Keys are already scoped to their tenant. Entries are unreadable after their expiry, when the token that could
 * notify about them has expired too.
 */
public interface IssuanceNotificationStore {

    /**
     * One credential response.
     *
     * @param subject   the access token's subject, which may notify while that token lives
     * @param reference the tenant's own reference for the offer, if it had one
     * @param received  the events already received, so a repeat changes nothing
     */
    record Issuance(String subject, String credentialConfigurationId, Optional<String> reference, Instant issuedAt, Instant expiresAt,
                    Set<String> received) {
        public Issuance {
            received = Set.copyOf(received);
        }
    }

    /** A notification a tenant can read, for one of its references. */
    record Event(String notificationId, String credentialConfigurationId, String event, Optional<String> description, Instant receivedAt) {}

    void save(String notificationKey, Issuance issuance);

    Optional<Issuance> find(String notificationKey, Instant now);

    void saveEvents(String referenceKey, List<Event> events, Instant expiresAt);

    List<Event> events(String referenceKey, Instant now);
}
