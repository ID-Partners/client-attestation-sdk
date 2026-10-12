package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@link ClientAttestation}'s calls through the shared transport: token-endpoint error bodies are kept for
 * challenge handling, redirects are refused before credentials leave, and timeouts / malformed or
 * mis-shaped responses all surface as {@link ClientAttestation.ClientAttestationException}.
 */
class ClientAttestationTransportTest {
    /** The evidence_audience the fake attester's discovery document names. */
    private static final String AUD = "https://attester.example.com";

    private StubHttpServer server;

    @BeforeEach
    void start() throws Exception {
        this.server = new StubHttpServer();
        String sub = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"sub\":\"demo-client\"}".getBytes(StandardCharsets.UTF_8));
        this.server.respond("/federation/attestation", 200, "{\"attestation\":\"h." + sub + ".sig\"}");
    }

    @AfterEach
    void stop() {
        this.server.close();
    }

    /** Discovery advertising {@code tokenPath} as the token endpoint (and no challenge endpoint). */
    private ClientAttestation client(String tokenPath, Duration timeout) {
        String host = "/host" + tokenPath.replace('/', '_');
        this.server.respond(host + "/.well-known/client-attester", 200, "{"
                + "\"attestation_endpoint\":\"" + this.server.url("/federation/attestation") + "\","
                + "\"token_endpoint\":\"" + this.server.url(tokenPath) + "\","
                + "\"evidence_audience\":\"" + AUD + "\"}");
        return ClientAttestation.builder(this.server.url(host)).evidence(new SvidSource.Static("svid")).evidenceAudience(AUD)
                .timeout(timeout).build();
    }

    private ClientAttestation client(String tokenPath) {
        return client(tokenPath, Duration.ofSeconds(5));
    }

    @Test
    void tokenEndpointErrorBodyIsPreservedForChallengeHandling() {
        String error = "{\"error\":\"use_attestation_challenge\",\"attestation_challenge\":\"fresh-1\"}";
        this.server.respond("/token", 400, error);
        ClientAttestation.ClientAttestationException e =
                assertThrows(ClientAttestation.ClientAttestationException.class, () -> client("/token").token());
        assertEquals("token endpoint returned HTTP 400", e.getMessage());
        assertEquals(400, e.status());
        assertEquals(error, e.body());
    }

    @Test
    void tokenEndpointRedirectIsRefusedAndTheAttestationIsNotForwarded() {
        this.server.respond("/evil", 200, "{\"access_token\":\"x\"}");
        this.server.redirect("/token", this.server.url("/evil"));
        ClientAttestation.ClientAttestationException e =
                assertThrows(ClientAttestation.ClientAttestationException.class, () -> client("/token").token());
        assertEquals(302, e.status());
        assertInstanceOf(TransportException.class, e.getCause());
        assertEquals(1, this.server.hits("/token"));
        assertEquals(0, this.server.hits("/evil"));
    }

    @Test
    void tokenEndpointTimeoutIsAClientAttestationException() {
        this.server.slow("/token", 3000);
        ClientAttestation.ClientAttestationException e = assertThrows(
                ClientAttestation.ClientAttestationException.class,
                () -> client("/token", Duration.ofMillis(500)).token());
        assertTrue(e.getMessage().contains("timed out"), e.getMessage());
    }

    @Test
    void malformedOrMisShapedTokenResponsesAreClientAttestationExceptions() {
        this.server.respond("/garbage", 200, "<html/>");
        this.server.respond("/numeric", 200, "{\"access_token\":42}");
        ClientAttestation.ClientAttestationException garbage = assertThrows(
                ClientAttestation.ClientAttestationException.class, () -> client("/garbage").token());
        assertEquals(200, garbage.status());
        assertNull(garbage.body());   // a 2xx body is never kept: it may hold the token
        ClientAttestation.ClientAttestationException numeric = assertThrows(
                ClientAttestation.ClientAttestationException.class, () -> client("/numeric").token());
        assertTrue(numeric.getMessage().contains("no access_token"));
    }

    @Test
    void discoveryFailuresAreClientAttestationExceptions() {
        ClientAttestation missing = ClientAttestation.builder(this.server.url("/nothing-here"))
                .evidence(new SvidSource.Static("svid")).evidenceAudience(AUD).build();
        ClientAttestation.ClientAttestationException e =
                assertThrows(ClientAttestation.ClientAttestationException.class, missing::discovery);
        assertEquals(404, e.status());

        this.server.respond("/bad/.well-known/client-attester", 200, "[not, an, object");
        assertThrows(ClientAttestation.ClientAttestationException.class,
                () -> ClientAttestation.builder(this.server.url("/bad")).build().discovery());
    }

    @Test
    void discoveryWithoutAnAttestationEndpointFailsCleanly() {
        this.server.respond("/noendpoint/.well-known/client-attester", 200,
                "{\"evidence_audience\":\"" + AUD + "\"}");
        ClientAttestation.ClientAttestationException e = assertThrows(
                ClientAttestation.ClientAttestationException.class,
                () -> ClientAttestation.builder(this.server.url("/noendpoint"))
                        .evidence(new SvidSource.Static("svid")).evidenceAudience(AUD).build().token());
        assertTrue(e.getMessage().contains("attestation_endpoint"), e.getMessage());
    }

    @Test
    void nonStringEvidenceAudienceIsRejectedNotACastFailure() {
        this.server.respond("/numaud/.well-known/client-attester", 200, "{\"evidence_audience\":{\"x\":1}}");
        // A non-string audience used to throw ClassCastException outside the wrapper; now it is either
        // accepted as text or rejected as a ClientAttestationException — never a raw RuntimeException.
        assertThrows(ClientAttestation.ClientAttestationException.class,
                () -> ClientAttestation.builder(this.server.url("/numaud"))
                        .evidence(new SvidSource.Static("svid")).evidenceAudience(AUD).build().token());
    }
}
