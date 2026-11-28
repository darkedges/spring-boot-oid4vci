package com.darkedges.oid4vci.demo.issuer;

import com.darkedges.oid4vci.spring.boot.autoconfigure.MdocIssuerKeyMaterial;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.List;

/**
 * Loads the demo Issuer's signing key material from two checked-in PKCS12 keystores (one for SD-JWT
 * VC/access-token/JWKS signing, one for the mdoc {@code IssuerAuth} key) — same {@code keytool} technique
 * as {@code oid4vp-demo-wallet}'s {@code DemoMdocCredentialConfig} and {@code oid4vp-demo-verifier}'s
 * {@code DemoVerifierSigningKeyConfig}, except the leaf is CA-issued rather than self-signed: HAIP's
 * {@code ValidateSdJwtCredentialX5cCertificateChain} check (confirmed live against a real conformance
 * run) rejects a self-signed leaf outright, so {@code demo-issuer-signing-key.p12}'s {@code demo-issuer}
 * alias holds a 2-certificate chain — a leaf issued by (not the same cert as) a throwaway self-signed
 * "oid4vci Demo CA" root, both generated via plain {@code keytool -genkeypair}/{@code -certreq}/
 * {@code -gencert}, no real CA involved. {@code oid4vp-demo-verifier}'s own {@code IssuerKeyResolver}
 * still trusts the embedded chain's leaf outright with no path validation, so this is enough.
 *
 * <p>Only the non-self-signed entries of that chain go into the JWS {@code x5c} header ({@link #issuerSigningKey}):
 * the same HAIP check also rejects an x5c that includes the self-signed trust anchor itself (confirmed
 * live) — a verifier is expected to already trust that root out-of-band, not receive it inside the token —
 * so the root is filtered out, leaving just the leaf (or, with a deeper chain, leaf plus any intermediates).
 *
 * <p>Built via plain {@link KeyStore} rather than Nimbus's {@code ECKey.load(KeyStore, ...)}: that
 * convenience method reaches for BouncyCastle internally, and this project has no BouncyCastle
 * dependency — same reasoning as {@code DemoVerifierSigningKeyConfig}.
 *
 * <p><b>The checked-in keystores are for local development: their private keys are published with this source,</b> so a credential
 * signed with them proves nothing. A deployment brings its own, kept outside the source tree: {@code demo.signing.keystore} (entry
 * {@code demo-issuer}) and {@code demo.signing.mdoc-keystore} (entry {@code demo-issuer-mdoc}), each with its
 * {@code ...-password}. With {@code demo.signing.require-external-key=true}, as the {@code cloudflare} profile sets, the Issuer
 * refuses to start without both, or with a published one.
 *
 * <p>Embedding a real cert chain (rather than the previous fresh-every-startup, chain-less keys) is
 * what lets {@code oid4vp-demo-verifier} resolve this issuer's key straight from a presented
 * credential, closing the cross-repo interop gap documented in the project README.
 */
@Configuration
public class DemoIssuerKeyConfig {

    private static final char[] PUBLISHED_PASSWORD = "changeit".toCharArray();
    private static final String SIGNING_ALIAS = "demo-issuer";
    private static final String MDOC_ALIAS = "demo-issuer-mdoc";

    @Value("${demo.signing.keystore:}")
    private String keystore = "";
    @Value("${demo.signing.keystore-password:}")
    private String keystorePassword = "";
    @Value("${demo.signing.mdoc-keystore:}")
    private String mdocKeystore = "";
    @Value("${demo.signing.mdoc-keystore-password:}")
    private String mdocKeystorePassword = "";
    @Value("${demo.signing.require-external-key:false}")
    private boolean requireExternalKey;

    @Bean
    public ECKey issuerSigningKey() throws Exception {
        if ("showcase".equals(System.getProperty("spring.profiles.active")) && System.getProperty("showcase.signing-key-file") != null) {
            return ECKey.parse(java.nio.file.Files.readString(java.nio.file.Path.of(System.getProperty("showcase.signing-key-file"))));
        }
        Entry entry = entry("demo.signing.keystore", keystore, keystorePassword, "/demo-issuer-signing-key.p12", SIGNING_ALIAS);
        ECPublicKey publicKey = (ECPublicKey) entry.chain()[0].getPublicKey();
        List<Base64> x5c = Arrays.stream(entry.chain())
                .filter(cert -> !isSelfSigned(cert))
                .map(DemoIssuerKeyConfig::encode)
                .toList();

        ECKey.Builder key = new ECKey.Builder(Curve.P_256, publicKey)
                .privateKey(entry.privateKey())
                .keyID(entry.published() ? SIGNING_ALIAS : null);
        if (!x5c.isEmpty()) key.x509CertChain(x5c);
        // A key of one's own is identified by its thumbprint, so verifiers that cached the previous key don't mistake one for the other.
        if (!entry.published()) key.keyIDFromThumbprint();
        return key.build();
    }

    /** A keystore entry: the deployment's own when configured, else the checked-in development one (when that is allowed). */
    private Entry entry(String property, String file, String password, String publishedResource, String alias) throws Exception {
        if (file.isBlank()) {
            if (requireExternalKey) {
                throw new IllegalStateException("This deployment needs its own signing keys: set " + property + " and " + property
                        + "-password. The keys shipped with the source are public.");
            }
            return published(publishedResource, alias);
        }
        Entry own;
        try (InputStream in = Files.newInputStream(Path.of(file))) {
            own = load(in, password.toCharArray(), alias, false);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read " + property + " " + file + ": " + e.getMessage(), e);
        }
        if (requireExternalKey && Arrays.equals(own.chain()[0].getPublicKey().getEncoded(),
                published(publishedResource, alias).chain()[0].getPublicKey().getEncoded())) {
            throw new IllegalStateException(property + " holds the key shipped with the source, which is public: generate a new one");
        }
        return own;
    }

    private static Entry published(String resource, String alias) throws Exception {
        try (InputStream in = DemoIssuerKeyConfig.class.getResourceAsStream(resource)) {
            return load(in, PUBLISHED_PASSWORD, alias, true);
        }
    }

    private static Entry load(InputStream in, char[] password, String alias, boolean published) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(in, password);
        ECPrivateKey privateKey = (ECPrivateKey) keyStore.getKey(alias, password);
        Certificate[] chain = keyStore.getCertificateChain(alias);
        if (privateKey == null || chain == null) {
            throw new IllegalStateException("the keystore has no private key entry \"" + alias + "\"");
        }
        return new Entry(privateKey, chain, published);
    }

    private record Entry(ECPrivateKey privateKey, Certificate[] chain, boolean published) {}

    private static boolean isSelfSigned(Certificate certificate) {
        if (!(certificate instanceof java.security.cert.X509Certificate x509)) {
            return false;
        }
        return x509.getIssuerX500Principal().equals(x509.getSubjectX500Principal());
    }

    private static Base64 encode(Certificate certificate) {
        try {
            return Base64.encode(certificate.getEncoded());
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new IllegalStateException("failed to encode certificate from demo-issuer-signing-key.p12", e);
        }
    }

    @Bean
    public MdocIssuerKeyMaterial mdocIssuerKeyMaterial() throws Exception {
        Entry entry = entry("demo.signing.mdoc-keystore", mdocKeystore, mdocKeystorePassword, "/demo-issuer-mdoc-key.p12", MDOC_ALIAS);
        List<String> x5chain = List.of(java.util.Base64.getEncoder().encodeToString(entry.chain()[0].getEncoded()));
        return new MdocIssuerKeyMaterial(entry.privateKey(), x5chain);
    }
}
