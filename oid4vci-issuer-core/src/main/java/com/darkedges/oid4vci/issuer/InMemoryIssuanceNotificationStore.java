package com.darkedges.oid4vci.issuer;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** For a single instance, and tests: notifications are forgotten on restart. */
public final class InMemoryIssuanceNotificationStore implements IssuanceNotificationStore {

    private record Events(List<Event> events, Instant expiresAt) {}

    private final Map<String, Issuance> issuances = new ConcurrentHashMap<>();
    private final Map<String, Events> events = new ConcurrentHashMap<>();

    @Override
    public void save(String notificationKey, Issuance issuance) {
        issuances.put(notificationKey, issuance);
    }

    @Override
    public Optional<Issuance> find(String notificationKey, Instant now) {
        return Optional.ofNullable(issuances.get(notificationKey)).filter(i -> i.expiresAt().isAfter(now));
    }

    @Override
    public void saveEvents(String referenceKey, List<Event> list, Instant expiresAt) {
        events.put(referenceKey, new Events(List.copyOf(list), expiresAt));
    }

    @Override
    public List<Event> events(String referenceKey, Instant now) {
        Events stored = events.get(referenceKey);
        return stored == null || !stored.expiresAt().isAfter(now) ? List.of() : stored.events();
    }
}
