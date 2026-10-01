package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** {@link ClientAttestationCredential} unit coverage: constructor validation and header assembly. */
class ClientAttestationCredentialTest {

    private static final String ATTESTER_ISS = "https://attester.example.com";
    private static final String CLIENT_ID = "https://rp.example.com";
    private static final String AUDIENCE = "https://as.example.com";
    private static final String TOKEN_ENDPOINT = "https://as.example.com/as/token.oauth2";

    private static final SigningKeyPair ATTESTER_KEY = SigningKeyPair.generate("ES256");
    private static final SigningKeyPair INSTANCE_KEY = SigningKeyPair.generate("ES256");

    private static String attestation() {
        return new ClientAttestationBuilder(ATTESTER_KEY, ATTESTER_ISS)
                .clientId(CLIENT_ID)
                .confirmationKey(INSTANCE_KEY)
                .expiresIn(Duration.ofMinutes(5))
                .build();
    }

    @Test
    void attestationJwtIsRequired() {
        assertThrows(IllegalArgumentException.class, () -> new ClientAttestationCredential(null, INSTANCE_KEY));
        assertThrows(IllegalArgumentException.class, () -> new ClientAttestationCredential("  ", INSTANCE_KEY));
    }

    @Test
    void instanceKeyIsRequired() {
        assertThrows(NullPointerException.class, () -> new ClientAttestationCredential(attestation(), null));
    }

    @Test
    void popHeadersCarryAttestationAndFreshPop() throws Exception {
        String attestation = attestation();
        Map<String, String> headers = new ClientAttestationCredential(attestation, INSTANCE_KEY)
                .popHeaders(null, AUDIENCE, "challenge-1");
        assertEquals(2, headers.size());
        assertEquals(attestation, headers.get(ClientAttestationCredential.ATTESTATION_HEADER));
        Map<String, Object> popClaims = JwtTestSupport.claims(headers.get(ClientAttestationCredential.POP_HEADER));
        assertEquals(AUDIENCE, popClaims.get("aud"));
        assertEquals("challenge-1", popClaims.get("challenge"));
        assertFalse(popClaims.containsKey("iss"), "iss omitted when clientId is null");
        assertFalse(headers.containsKey(ClientAttestationCredential.DPOP_HEADER));
    }

    @Test
    void dpopHeadersCarryAttestationAndDpopProof() throws Exception {
        String attestation = attestation();
        Map<String, String> headers = new ClientAttestationCredential(attestation, INSTANCE_KEY)
                .dpopHeaders(null, TOKEN_ENDPOINT, "nonce-1");
        assertEquals(2, headers.size());
        assertEquals(attestation, headers.get(ClientAttestationCredential.ATTESTATION_HEADER));
        Map<String, Object> dpopClaims = JwtTestSupport.claims(headers.get(ClientAttestationCredential.DPOP_HEADER));
        assertEquals("POST", dpopClaims.get("htm"), "null method must fall back to POST");
        assertEquals(TOKEN_ENDPOINT, dpopClaims.get("htu"));
        assertEquals("nonce-1", dpopClaims.get("nonce"));
        assertTrue(headers.containsKey(ClientAttestationCredential.DPOP_HEADER));
        assertFalse(headers.containsKey(ClientAttestationCredential.POP_HEADER));
    }
}
