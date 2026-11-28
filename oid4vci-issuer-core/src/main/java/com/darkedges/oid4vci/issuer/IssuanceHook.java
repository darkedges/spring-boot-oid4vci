package com.darkedges.oid4vci.issuer;

import com.darkedges.oid4vci.core.error.Oid4vciException;

/**
 * The tenant's say in issuing a credential of one of its offers (one with a {@link IssuanceConstraints#reference reference}), at the
 * moment it is issued: {@link #authorize} just before signing, {@link #issued} just after. A tenant whose rules decide who may hold a
 * credential (a bank: is this staff member still active, has a newer attempt replaced them, was it already issued) keeps them in its own
 * system this way, instead of handing them to the issuer.
 */
public interface IssuanceHook {

    /** One credential about to be, or just, issued. */
    record Attempt(String reference, String credentialConfigurationId, String format, String holderKeyThumbprint) {}

    /**
     * Whether this credential may be issued now. Returns to allow it.
     *
     * @throws Oid4vciException with {@code credential_request_denied} when the tenant refuses
     * @throws IssuanceHookUnavailableException when the tenant can't be asked: the credential is not issued (fail closed)
     */
    void authorize(IssuerContext context, Attempt attempt);

    /** The credential was issued (and is in the response). Must not throw; failures to tell the tenant are the hook's to retry. */
    void issued(IssuerContext context, Attempt attempt, String credential);

    /** What a wallet said became of a credential issued for one of the tenant's references. */
    record Notice(String reference, String credentialConfigurationId, String event, String notificationId,
                  java.util.Optional<String> description, java.time.Instant receivedAt) {}

    /**
     * A wallet reported on a credential (OID4VCI notification), such as that it was deleted. Called once per new event. Must neither
     * throw nor delay the wallet; telling the tenant, and retrying, is the hook's. By default the tenant is not told.
     */
    default void notified(IssuerContext context, Notice notice) {}

    /** No hook: every credential is issued as the offer says. */
    IssuanceHook NONE = new IssuanceHook() {
        @Override public void authorize(IssuerContext context, Attempt attempt) {}
        @Override public void issued(IssuerContext context, Attempt attempt, String credential) {}
    };

    /** The tenant's hook could not be reached, or answered unexpectedly: nothing is issued, and the wallet may try again. */
    final class IssuanceHookUnavailableException extends RuntimeException {
        public IssuanceHookUnavailableException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
