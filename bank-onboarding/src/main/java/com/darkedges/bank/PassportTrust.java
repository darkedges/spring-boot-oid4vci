package com.darkedges.bank;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.Environment;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * The passport issuers the bank trusts, each with its public key, pinned: the platform issuer is multi-tenant, so a passport can come
 * from {@code https://issuer.zkp.au}, a tenant such as {@code https://issuer.zkp.au/t/bank}, or a customer's own domain. Each key is
 * obtained from its issuer's operator, never from a credential, and saved as a public P-256 JWK file.
 *
 * <pre>
 * bank.passport-issuers[0].issuer   = https://issuer.zkp.au/t/bank      (BANK_PASSPORT_ISSUERS_0_ISSUER)
 * bank.passport-issuers[0].key-file = /keys/bank-passport.jwk            (BANK_PASSPORT_ISSUERS_0_KEY_FILE)
 * </pre>
 * Without a list, {@code bank.passport-issuer} and {@code bank.passport-key-file} ({@code PASSPORT_ISSUER},
 * {@code PASSPORT_PUBLIC_JWK_FILE}) are the one trusted issuer, as before.
 */
public final class PassportTrust {

    /** One configured issuer, as bound from bank.passport-issuers. */
    public static class Entry {
        private String issuer;
        private String keyFile;
        public String getIssuer() { return issuer; }
        public void setIssuer(String issuer) { this.issuer = issuer; }
        public String getKeyFile() { return keyFile; }
        public void setKeyFile(String keyFile) { this.keyFile = keyFile; }
    }

    private final Map<String, ECKey> keys;

    PassportTrust(Map<String, ECKey> keys) {
        if (keys.isEmpty()) throw new IllegalArgumentException("Trust at least one passport issuer (bank.passport-issuers, or PASSPORT_ISSUER)");
        this.keys = Collections.unmodifiableMap(new LinkedHashMap<>(keys));
    }

    /** One trusted issuer, with its key file. */
    static PassportTrust single(String issuer, String keyFile) throws Exception {
        String normalized = normalize(issuer);
        return new PassportTrust(Map.of(normalized, publicKey(Files.readString(Path.of(keyFile)), normalized)));
    }

    static PassportTrust from(Environment environment) throws Exception {
        List<Entry> entries = Binder.get(environment).bind("bank.passport-issuers", Bindable.listOf(Entry.class)).orElse(List.of());
        if (entries.isEmpty()) {
            Entry single = new Entry();
            single.setIssuer(environment.getProperty("bank.passport-issuer"));
            single.setKeyFile(environment.getProperty("bank.passport-key-file"));
            entries = List.of(single);
        }
        Map<String, ECKey> keys = new LinkedHashMap<>();
        for (Entry entry : entries) {
            String issuer = normalize(entry.getIssuer());
            if (entry.getKeyFile() == null || entry.getKeyFile().isBlank()) throw new IllegalArgumentException("No key file for passport issuer " + issuer);
            if (keys.put(issuer, publicKey(Files.readString(Path.of(entry.getKeyFile())), issuer)) != null) {
                throw new IllegalArgumentException("Passport issuer listed twice: " + issuer);
            }
        }
        return new PassportTrust(keys);
    }

    static String normalize(String issuer) {
        if (issuer == null || issuer.isBlank()) throw new IllegalArgumentException("A passport issuer needs its identifier");
        // The pinned key is what is trusted; the identifier only has to match the credential's iss exactly.
        String trimmed = issuer.trim().replaceAll("/+$", "");
        java.net.URI uri = java.net.URI.create(trimmed);
        if (uri.getScheme() == null || uri.getHost() == null) throw new IllegalArgumentException("A passport issuer identifier is a URL: " + trimmed);
        if (uri.getQuery() != null || uri.getFragment() != null) throw new IllegalArgumentException("A passport issuer identifier has no query or fragment: " + trimmed);
        return trimmed;
    }

    static ECKey publicKey(String json, String issuer) throws java.text.ParseException {
        ECKey key = ECKey.parse(json);
        if (key.isPrivate()) throw new IllegalArgumentException("The key for " + issuer + " must be public only");
        if (!Curve.P_256.equals(key.getCurve())) throw new IllegalArgumentException("The key for " + issuer + " must be P-256");
        return key;
    }

    /** The trusted issuers, in configured order. */
    public List<String> issuers() { return List.copyOf(keys.keySet()); }

    /** The passport credential types the bank asks for: one per trusted issuer. */
    public List<String> vcts() { return issuers().stream().map(PassportTrust::vct).toList(); }

    public static String vct(String issuer) { return issuer + "/vct/PassportCredential"; }

    /** The pinned key of a trusted issuer; empty for any other. */
    public Optional<ECKey> key(String issuer) { return Optional.ofNullable(issuer == null ? null : keys.get(issuer)); }

    /** A passport's type and issuer agree, and the issuer is trusted. */
    public boolean accepts(String issuer, String vct) { return key(issuer).isPresent() && vct(issuer).equals(vct); }
}
