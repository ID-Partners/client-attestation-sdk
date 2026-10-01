package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@link OpenBaoTransitSigner} against an in-process fake transit API. The interoperability contract (an
 * attestation signed inside the fake vault verifies with the real AS-side verifier) is
 * {@code OpenBaoTransitSignerInteropTest}, under the {@code interop} profile.
 */
class OpenBaoTransitSignerTest {

    private static final String TOKEN = "unit-test-token";

    private FakeBaoServer bao;

    @BeforeEach
    void start() throws Exception {
        bao = new FakeBaoServer(TOKEN);
    }

    @AfterEach
    void stop() {
        bao.close();
    }

    @Test
    void derivesPublicJwkFromTransitKeyMetadata() {
        OpenBaoTransitSigner signer = new OpenBaoTransitSigner(bao.url(), TOKEN, FakeBaoServer.KEY_NAME);
        Map<String, Object> jwk = signer.publicJwk();
        Map<String, Object> expected = bao.key.toParams(org.jose4j.jwk.JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        assertEquals("ES256", signer.algorithm());
        assertEquals("EC", jwk.get("kty"));
        assertEquals("P-256", jwk.get("crv"));
        assertEquals(expected.get("x"), jwk.get("x"));
        assertEquals(expected.get("y"), jwk.get("y"));
        assertEquals(signer.keyId(), jwk.get("kid"), "kid must be carried in the public JWK");
    }

    @Test
    void wrongTokenFailsClosed() {
        assertThrows(IllegalStateException.class,
                () -> new OpenBaoTransitSigner(bao.url(), "wrong-token", FakeBaoServer.KEY_NAME));
    }

    @Test
    void vaultDownFailsClosed() {
        OpenBaoTransitSigner signer = new OpenBaoTransitSigner(bao.url(), TOKEN, FakeBaoServer.KEY_NAME);
        bao.close();
        assertThrows(IllegalStateException.class, () -> signer.sign("payload".getBytes()));
    }
}
