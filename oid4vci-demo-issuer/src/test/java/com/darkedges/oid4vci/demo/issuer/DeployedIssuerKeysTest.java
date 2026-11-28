package com.darkedges.oid4vci.demo.issuer;

import com.nimbusds.jose.jwk.ECKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Deployed (demo.signing.require-external-key, as the "cloudflare" profile sets), the issuer signs only with keys of its own. */
class DeployedIssuerKeysTest {

    private static final String PASSWORD = "only-for-this-test";

    @TempDir
    Path dir;

    private static DemoIssuerKeyConfig deployed() {
        DemoIssuerKeyConfig config = new DemoIssuerKeyConfig();
        ReflectionTestUtils.setField(config, "requireExternalKey", true);
        return config;
    }

    private static void use(DemoIssuerKeyConfig config, String prefix, Object file, String password) {
        ReflectionTestUtils.setField(config, prefix.isEmpty() ? "keystore" : prefix + "Keystore", file.toString());
        ReflectionTestUtils.setField(config, prefix.isEmpty() ? "keystorePassword" : prefix + "KeystorePassword", password);
    }

    /** A new key, made as an operator would make one. */
    private Path generate(String alias) throws Exception {
        Path file = dir.resolve(alias + ".p12");
        Process process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "keytool").toString(), "-genkeypair",
                "-alias", alias, "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=own issuer", "-validity", "2",
                "-storetype", "PKCS12", "-keystore", file.toString(), "-storepass", PASSWORD).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes());
        assertThat(process.waitFor()).as(output).isZero();
        return file;
    }

    @Test
    void signsWithItsOwnKeysUnderANewKeyId() throws Exception {
        DemoIssuerKeyConfig config = deployed();
        use(config, "", generate("demo-issuer"), PASSWORD);
        use(config, "mdoc", generate("demo-issuer-mdoc"), PASSWORD);

        ECKey own = config.issuerSigningKey();
        ECKey published = new DemoIssuerKeyConfig().issuerSigningKey();
        assertThat(own.isPrivate()).isTrue();
        assertThat(own.computeThumbprint()).isNotEqualTo(published.computeThumbprint());
        assertThat(own.getKeyID()).isEqualTo(own.computeThumbprint().toString()).isNotEqualTo(published.getKeyID());
        assertThat(own.getX509CertChain()).as("a self-signed leaf is not sent").isNull();
        assertThat(config.mdocIssuerKeyMaterial()).isNotNull();
    }

    @Test
    void willNotRunWithThePublishedKeysOrNone() throws Exception {
        assertThatThrownBy(() -> deployed().issuerSigningKey()).hasMessageContaining("needs its own signing keys");
        assertThatThrownBy(() -> deployed().mdocIssuerKeyMaterial()).hasMessageContaining("demo.signing.mdoc-keystore");

        DemoIssuerKeyConfig published = deployed();
        use(published, "", "src/main/resources/demo-issuer-signing-key.p12", "changeit");
        use(published, "mdoc", "src/main/resources/demo-issuer-mdoc-key.p12", "changeit");
        assertThatThrownBy(published::issuerSigningKey).hasMessageContaining("which is public");
        assertThatThrownBy(published::mdocIssuerKeyMaterial).hasMessageContaining("which is public");

        DemoIssuerKeyConfig missing = deployed();
        use(missing, "", dir.resolve("none.p12"), PASSWORD);
        assertThatThrownBy(missing::issuerSigningKey).hasMessageContaining("Cannot read");
    }
}
