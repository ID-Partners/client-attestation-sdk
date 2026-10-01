package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The one-call client fails closed: an advertised challenge that cannot be fetched stops the flow (unless
 * {@code requireChallenge(false)}), and the host and every discovered endpoint must be https unless
 * loopback or {@code allowInsecure(true)}.
 */
class ClientAttestationFailClosedTest {

    private StubHttpServer server;

    @BeforeEach
    void start() throws Exception {
        this.server = new StubHttpServer();
        String sub = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"sub\":\"demo-client\"}".getBytes(StandardCharsets.UTF_8));
        this.server.respond("/attest", 200, "{\"attestation\":\"h." + sub + ".sig\"}");
        this.server.respond("/token", 200, "{\"access_token\":\"AT\",\"expires_in\":60}");
    }

    @AfterEach
    void stop() {
        this.server.close();
    }

    /** A host whose discovery advertises the given endpoints (null = omitted). */
    private String host(String name, String attestation, String challenge, String token) {
        StringBuilder doc = new StringBuilder("{\"evidence_audience\":\"https://attester.example.com\"");
        if (attestation != null) {
            doc.append(",\"attestation_endpoint\":\"").append(attestation).append('"');
        }
        if (challenge != null) {
            doc.append(",\"challenge_endpoint\":\"").append(challenge).append('"');
        }
        if (token != null) {
            doc.append(",\"token_endpoint\":\"").append(token).append('"');
        }
        this.server.respond("/" + name + "/.well-known/client-attester", 200, doc.append('}').toString());
        return this.server.url("/" + name);
    }

    private ClientAttestation.Builder builder(String host) {
        return ClientAttestation.builder(host).evidence(new SvidSource.Static("svid"));
    }

    // ── item 11a: challenge ─────────────────────────────────────────────────────────────────────────

    @Test
    void failedChallengeFetchFailsTheFlow() {
        this.server.respond("/challenge-500", 500, "{\"error\":\"down\"}");
        String host = host("h500", this.server.url("/attest"), this.server.url("/challenge-500"),
                this.server.url("/token"));
        ClientAttestation.ClientAttestationException e = assertThrows(
                ClientAttestation.ClientAttestationException.class, () -> builder(host).build().token());
        assertTrue(e.getMessage().contains("challenge_endpoint"), e.getMessage());
        assertTrue(e.getMessage().contains("requireChallenge(false)"), e.getMessage());
        assertEquals(500, e.status());
        assertEquals(0, this.server.hits("/attest"));                 // nothing minted without the challenge
        assertEquals(0, this.server.hits("/token"));
    }

    @Test
    void challengeResponseWithoutAChallengeFailsTheFlow() {
        this.server.respond("/challenge-empty", 200, "{\"expires_in\":300}");
        String host = host("hempty", this.server.url("/attest"), this.server.url("/challenge-empty"),
                this.server.url("/token"));
        ClientAttestation.ClientAttestationException e = assertThrows(
                ClientAttestation.ClientAttestationException.class, () -> builder(host).build().token());
        assertTrue(e.getMessage().contains("attestation_challenge"), e.getMessage());
        assertEquals(0, this.server.hits("/attest"));
    }

    @Test
    void unreachableChallengeEndpointFailsTheFlow() throws Exception {
        String dead;
        try (java.net.ServerSocket s = new java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
            dead = "http://127.0.0.1:" + s.getLocalPort() + "/challenge";
        }
        String host = host("hdead", this.server.url("/attest"), dead, this.server.url("/token"));
        ClientAttestation.ClientAttestationException e = assertThrows(
                ClientAttestation.ClientAttestationException.class, () -> builder(host).build().token());
        assertEquals(0, e.status());
        assertTrue(e.getMessage().contains(dead), e.getMessage());
    }

    @Test
    void requireChallengeFalseProceedsWithoutOne() throws Exception {
        this.server.respond("/challenge-500b", 500, "{}");
        String host = host("hoptout", this.server.url("/attest"), this.server.url("/challenge-500b"),
                this.server.url("/token"));
        ClientAttestation ca = builder(host).requireChallenge(false).build();
        assertEquals("AT", ca.token());
        String pop = this.server.lastHeaders.get("/token").getFirst(ClientAttestation.POP_HEADER);
        assertFalse(JwtTestSupport.claims(pop).containsKey("challenge"));
    }

    @Test
    void noChallengeEndpointMeansNoChallengeAndNoError() throws Exception {
        String host = host("hnone", this.server.url("/attest"), null, this.server.url("/token"));
        assertEquals("AT", builder(host).build().token());
    }

    // ── item 11c: transport security ────────────────────────────────────────────────────────────────

    @Test
    void plainHttpHostIsRefusedUnlessLoopbackOrAllowed() {
        ClientAttestation.ClientAttestationException e = assertThrows(
                ClientAttestation.ClientAttestationException.class,
                () -> ClientAttestation.builder("http://pf.example.com").build());
        assertTrue(e.getMessage().contains("http://pf.example.com"), e.getMessage());
        assertThrows(ClientAttestation.ClientAttestationException.class,
                () -> new ClientAttestation("http://pf.example.com:9031/"));

        assertDoesNotThrow(() -> new ClientAttestation("pf.example.com"));          // defaults to https
        assertDoesNotThrow(() -> new ClientAttestation("HTTPS://pf.example.com"));
        assertDoesNotThrow(() -> new ClientAttestation("http://localhost:9031"));
        assertDoesNotThrow(() -> new ClientAttestation("http://LOCALHOST"));
        assertDoesNotThrow(() -> new ClientAttestation("http://127.0.0.1:9031"));
        assertDoesNotThrow(() -> new ClientAttestation("http://[::1]:9031"));
        assertDoesNotThrow(() -> ClientAttestation.builder("http://pf.example.com").allowInsecure(true).build());
    }

    @Test
    void urlChecks() {
        assertTrue(ClientAttestation.isLoopback("::1"));
        assertTrue(ClientAttestation.isLoopback("[::1]"));
        assertFalse(ClientAttestation.isLoopback("127.0.0.2"));
        assertFalse(ClientAttestation.isLoopback(null));
        ClientAttestation.ClientAttestationException bad = assertThrows(
                ClientAttestation.ClientAttestationException.class,
                () -> ClientAttestation.requireSecure("http://bad host/x", "token_endpoint", false));
        assertTrue(bad.getMessage().contains("token_endpoint"), bad.getMessage());
        assertDoesNotThrow(() -> ClientAttestation.requireSecure("http://bad host/x", "token_endpoint", true));
    }

    @Test
    void insecureDiscoveredAttestationEndpointIsRefusedBeforeAnySecretLeaves() {
        String insecure = "http://attester.example.com/attest";
        String host = host("hatt", insecure, null, this.server.url("/token"));
        ClientAttestation.ClientAttestationException e = assertThrows(
                ClientAttestation.ClientAttestationException.class, () -> builder(host).build().token());
        assertTrue(e.getMessage().contains(insecure), e.getMessage());
        assertTrue(e.getMessage().contains("attestation_endpoint"), e.getMessage());
    }

    @Test
    void insecureDiscoveredChallengeEndpointIsRefusedEvenWhenChallengesAreOptional() {
        String insecure = "http://attester.example.com/challenge";
        String host = host("hchal", this.server.url("/attest"), insecure, this.server.url("/token"));
        ClientAttestation.ClientAttestationException e = assertThrows(
                ClientAttestation.ClientAttestationException.class,
                () -> builder(host).requireChallenge(false).build().token());
        assertTrue(e.getMessage().contains(insecure), e.getMessage());
    }

    @Test
    void insecureDiscoveredTokenEndpointIsRefused() {
        String insecure = "http://pf.example.com/as/token.oauth2";
        String host = host("htok", this.server.url("/attest"), null, insecure);
        ClientAttestation.ClientAttestationException e = assertThrows(
                ClientAttestation.ClientAttestationException.class, () -> builder(host).build().token());
        assertTrue(e.getMessage().contains(insecure), e.getMessage());
        assertTrue(e.getMessage().contains("token_endpoint"), e.getMessage());
    }
}
