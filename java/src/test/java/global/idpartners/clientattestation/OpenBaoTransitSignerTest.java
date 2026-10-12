package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    @Test
    void plainHttpToANonLoopbackVaultIsRefused() {
        // Refused before any request: the vault token must not travel in cleartext, and a key read from
        // whoever answers would become the attester's published JWK.
        ClientAttestation.ClientAttestationException e = assertThrows(ClientAttestation.ClientAttestationException.class,
                () -> new OpenBaoTransitSigner("http://openbao.internal.invalid:8200", TOKEN, FakeBaoServer.KEY_NAME));
        assertTrue(e.getMessage().contains("must use https"), e.getMessage());
    }

    @Test
    void allowInsecureLiftsTheHttpsRule() {
        // The call is attempted, and fails only because nothing is there.
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> new OpenBaoTransitSigner(
                "http://openbao.internal.invalid:8200", TOKEN, FakeBaoServer.KEY_NAME, true));
        assertTrue(e.getMessage().contains("unreachable"), e.getMessage());
    }

    @Test
    void loopbackHttpIsAllowed() {
        String localhost = bao.url().replace("127.0.0.1", "localhost");
        assertEquals("ES256", new OpenBaoTransitSigner(localhost, TOKEN, FakeBaoServer.KEY_NAME).algorithm());
    }

    @Test
    void keyNamesThatEscapeThePathAreRefusedBeforeAnyRequest() throws Exception {
        try (StubHttpServer vault = new StubHttpServer()) {
            vault.respond("/", 200, "{\"data\":{}}");
            for (String name : new String[]{"../../sys/raw/x", "k/../../../sys/seal", "k?x=1", "k#frag", "a/b",
                    "%2e%2e", ".", "..", "", "k y"}) {
                assertThrows(IllegalArgumentException.class, () -> new OpenBaoTransitSigner(vault.url(""), TOKEN, name),
                        name);
            }
            assertEquals(0, vault.hits("/"), "the vault token must not be sent");
        }
        assertEquals("ES256", new OpenBaoTransitSigner(bao.url(), TOKEN, FakeBaoServer.KEY_NAME).algorithm());
    }
}
