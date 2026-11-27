package com.darkedges.oid4vci.issuer;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The live offers a tenant created through its tenant API, by the tenant's own reference: so creating one twice for the same reference
 * returns the same offer, and the tenant can withdraw it. Keys are already scoped to the tenant ({@link IssuerContext#scope}).
 */
public interface TenantOfferReferences {

    /** A live offer: its pre-authorized code (scoped, as the code store holds it), the offer JSON, and when it expires. */
    record OfferReference(String scopedCode, String offerJson, Instant expiresAt) {}

    void save(String scopedReference, OfferReference offer);

    Optional<OfferReference> find(String scopedReference);

    void remove(String scopedReference);

    /** In memory, for one instance and tests. */
    final class InMemory implements TenantOfferReferences {
        private final Map<String, OfferReference> offers = new ConcurrentHashMap<>();
        private final Clock clock;

        public InMemory(Clock clock) { this.clock = clock; }

        @Override public void save(String scopedReference, OfferReference offer) {
            Instant now = clock.instant();
            offers.values().removeIf(o -> !o.expiresAt().isAfter(now));
            offers.put(scopedReference, offer);
        }

        @Override public Optional<OfferReference> find(String scopedReference) {
            OfferReference offer = offers.get(scopedReference);
            return offer != null && offer.expiresAt().isAfter(clock.instant()) ? Optional.of(offer) : Optional.empty();
        }

        @Override public void remove(String scopedReference) { offers.remove(scopedReference); }
    }
}
