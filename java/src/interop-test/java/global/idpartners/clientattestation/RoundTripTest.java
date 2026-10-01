package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.pingidentity.ps.oidf.common.InMemoryAttestationChallengeService;
import com.pingidentity.ps.oidf.common.InMemoryAttestationReplayCache;
import com.pingidentity.ps.oidf.common.ClientAttestationConfig;
import com.pingidentity.ps.oidf.common.ClientAttestationResult;
import com.pingidentity.ps.oidf.common.ClientAttestationVerifier;
import com.pingidentity.ps.oidf.common.JwtCodec;
import com.pingidentity.ps.oidf.common.StaticAttesterKeyResolver;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Round-trips the client SDK against the real AS-side {@link ClientAttestationVerifier}: what the SDK
 * builds, the verifier accepts. This is the interoperability contract for both PoP-JWT and DPoP modes.
 */
class RoundTripTest {

    private static final String ATTESTER_ISS = "https://attester.example.com";
    private static final String CLIENT_ID = "https://rp.example.com";
    private static final String AUDIENCE = "https://as.example.com";
    private static final String TOKEN_ENDPOINT = "https://as.example.com/as/token.oauth2";

    private ClientAttestationVerifier verifier(SigningKeyPair attesterKey) {
        StaticAttesterKeyResolver resolver = new StaticAttesterKeyResolver(
                Map.of(ATTESTER_ISS, List.of(attesterKey.publicJsonWebKey())));
        ClientAttestationConfig config = ClientAttestationConfig.builder()
                .addAcceptedAudience(AUDIENCE)
                .expectedHtu(TOKEN_ENDPOINT)
                .build();
        return new ClientAttestationVerifier(resolver, config, new InMemoryAttestationReplayCache(), new InMemoryAttestationChallengeService());
    }

    private String attestation(SigningKeyPair attesterKey, SigningKeyPair instanceKey) {
        return new ClientAttestationBuilder(attesterKey, ATTESTER_ISS)
                .clientId(CLIENT_ID)
                .confirmationKey(instanceKey)
                .expiresIn(Duration.ofMinutes(5))
                .build();
    }

    @Test
    void popModeRoundTrips() throws Exception {
        SigningKeyPair attesterKey = SigningKeyPair.generate("ES256");
        SigningKeyPair instanceKey = SigningKeyPair.generate("ES256");

        Map<String, String> headers = new ClientAttestationCredential(attestation(attesterKey, instanceKey), instanceKey)
                .popHeaders(CLIENT_ID, AUDIENCE, null);

        ClientAttestationResult result = verifier(attesterKey).verify(
                headers.get(ClientAttestationCredential.ATTESTATION_HEADER),
                headers.get(ClientAttestationCredential.POP_HEADER),
                null, "POST", TOKEN_ENDPOINT, CLIENT_ID);

        assertEquals(CLIENT_ID, result.clientId());
        assertEquals(ClientAttestationResult.Mode.POP_JWT, result.mode());
        assertEquals(ATTESTER_ISS, result.attesterIssuer());
        assertNotNull(result.proofJti());
    }

    @Test
    void dpopCombinedModeRoundTrips() throws Exception {
        SigningKeyPair attesterKey = SigningKeyPair.generate("ES256");
        SigningKeyPair instanceKey = SigningKeyPair.generate("ES256");

        Map<String, String> headers = new ClientAttestationCredential(attestation(attesterKey, instanceKey), instanceKey)
                .dpopHeaders("POST", TOKEN_ENDPOINT, null);

        ClientAttestationResult result = verifier(attesterKey).verify(
                headers.get(ClientAttestationCredential.ATTESTATION_HEADER),
                null, headers.get(ClientAttestationCredential.DPOP_HEADER),
                "POST", TOKEN_ENDPOINT, CLIENT_ID);

        assertEquals(CLIENT_ID, result.clientId());
        assertEquals(ClientAttestationResult.Mode.DPOP, result.mode());
    }

    @Test
    void rsaInstanceKeyRoundTrips() throws Exception {
        SigningKeyPair attesterKey = SigningKeyPair.generate("ES256");
        SigningKeyPair instanceKey = SigningKeyPair.generate("RS256");

        Map<String, String> headers = new ClientAttestationCredential(attestation(attesterKey, instanceKey), instanceKey)
                .popHeaders(CLIENT_ID, AUDIENCE, null);

        ClientAttestationResult result = verifier(attesterKey).verify(
                headers.get(ClientAttestationCredential.ATTESTATION_HEADER),
                headers.get(ClientAttestationCredential.POP_HEADER),
                null, "POST", TOKEN_ENDPOINT, CLIENT_ID);

        assertEquals(CLIENT_ID, result.clientId());
        assertEquals(ClientAttestationResult.Mode.POP_JWT, result.mode());
    }

    @Test
    void popHeaderCarriesTheExpectedType() throws Exception {
        SigningKeyPair instanceKey = SigningKeyPair.generate("ES256");
        String pop = new PopBuilder(instanceKey).clientId(CLIENT_ID).audience(AUDIENCE).build();
        Map<String, Object> headers = JwtCodec.getJwtHeaders(pop);
        assertEquals(PopBuilder.TYP, headers.get("typ"));
        assertEquals("ES256", headers.get("alg"));
    }
}
