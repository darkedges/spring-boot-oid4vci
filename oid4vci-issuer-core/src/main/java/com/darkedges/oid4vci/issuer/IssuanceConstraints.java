package com.darkedges.oid4vci.issuer;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * What an offer may add to how its credentials are issued, beyond the claims: the tenant's own reference for it (told to the tenant's
 * {@link IssuanceHook}), and the holder key the credentials must be bound to.
 *
 * <p>They travel with the offer's claims, as reserved entries ({@value #PREFIX}...), through the pre-authorized code and the claims behind
 * the access token, in whatever store keeps them. {@link #credentialClaims} takes them out again before anything is issued, so they never
 * reach a credential. A caller's own claims may not use the prefix ({@link #isReserved}).
 */
public final class IssuanceConstraints {

    public static final String PREFIX = "__oid4vci.";
    static final String REFERENCE = PREFIX + "reference";
    static final String HOLDER_JKT = PREFIX + "holder_jkt";

    private IssuanceConstraints() {}

    /** The claims, plus the constraints (either may be absent). */
    public static Map<String, String> withConstraints(Map<String, String> claims, Optional<String> reference, Optional<String> holderKeyThumbprint) {
        Map<String, String> all = new LinkedHashMap<>(claims);
        reference.ifPresent(r -> all.put(REFERENCE, r));
        holderKeyThumbprint.ifPresent(t -> all.put(HOLDER_JKT, t));
        return all;
    }

    public static Optional<String> reference(Map<String, String> claims) {
        return Optional.ofNullable(claims.get(REFERENCE));
    }

    /** The RFC 7638 thumbprint (SHA-256, base64url) of the only key a proof may use, if the offer pinned one. */
    public static Optional<String> holderKeyThumbprint(Map<String, String> claims) {
        return Optional.ofNullable(claims.get(HOLDER_JKT));
    }

    /** The claims to put in the credential: without the constraints. */
    public static Map<String, String> credentialClaims(Map<String, String> claims) {
        Map<String, String> only = new LinkedHashMap<>(claims);
        only.keySet().removeIf(IssuanceConstraints::isReserved);
        return only;
    }

    public static boolean isReserved(String claimName) {
        return claimName != null && claimName.startsWith(PREFIX);
    }
}
