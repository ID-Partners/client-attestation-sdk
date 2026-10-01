package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.pingidentity.ps.oidf.common.ClientAttestationConfig;
import com.pingidentity.ps.oidf.common.ClientAttestationResult;
import com.pingidentity.ps.oidf.common.ClientAttestationVerifier;
import com.pingidentity.ps.oidf.common.InMemoryAttestationChallengeService;
import com.pingidentity.ps.oidf.common.InMemoryAttestationReplayCache;
import com.pingidentity.ps.oidf.common.StaticAttesterKeyResolver;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The interoperability contract for {@link OpenBaoTransitSigner}: an attestation signed inside the (fake) vault
 * verifies with the real AS-side verifier. Runs under the {@code interop} profile only.
 */
class OpenBaoTransitSignerInteropTest {

    private static final String TOKEN = "unit-test-token";
    private static final String ATTESTER_ISS = "https://attester.example.com";
    private static final String CLIENT_ID = "https://rp.example.com";
    private static final String AUDIENCE = "https://as.example.com";
    private static final String TOKEN_ENDPOINT = "https://as.example.com/as/token.oauth2";

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
    void vaultSignedAttestationRoundTripsAgainstRealVerifier() throws Exception {
        OpenBaoTransitSigner signer = new OpenBaoTransitSigner(bao.url(), TOKEN, FakeBaoServer.KEY_NAME);
        SigningKeyPair instanceKey = SigningKeyPair.generate("ES256");

        String attestation = new ClientAttestationBuilder(signer, ATTESTER_ISS)
                .clientId(CLIENT_ID)
                .confirmationKey(instanceKey)
                .expiresIn(Duration.ofMinutes(5))
                .build();
        Map<String, String> headers = new ClientAttestationCredential(attestation, instanceKey)
                .popHeaders(CLIENT_ID, AUDIENCE, null);

        StaticAttesterKeyResolver resolver = new StaticAttesterKeyResolver(
                Map.of(ATTESTER_ISS, List.of(Jwks.fromMap(signer.publicJwk()))));
        ClientAttestationConfig config = ClientAttestationConfig.builder()
                .addAcceptedAudience(AUDIENCE)
                .expectedHtu(TOKEN_ENDPOINT)
                .build();
        ClientAttestationVerifier verifier = new ClientAttestationVerifier(resolver, config,
                new InMemoryAttestationReplayCache(), new InMemoryAttestationChallengeService());

        ClientAttestationResult result = verifier.verify(
                headers.get(ClientAttestationCredential.ATTESTATION_HEADER),
                headers.get(ClientAttestationCredential.POP_HEADER),
                null, "POST", TOKEN_ENDPOINT, CLIENT_ID);

        assertEquals(CLIENT_ID, result.clientId());
        assertEquals(ClientAttestationResult.Mode.POP_JWT, result.mode());
        assertEquals(ATTESTER_ISS, result.attesterIssuer());
        assertNotNull(result.proofJti());
    }
}
