package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Credentials stay out of exceptions and default string forms: a 2xx body that can't be used is never kept
 * or quoted anywhere in the cause chain (it is where tokens, attestations and SVIDs travel), a non-2xx body
 * is kept up to the cap, and {@code toString} leaves secrets out.
 */
class CredentialRedactionTest {
    /** The evidence_audience the fake attester's discovery document names. */
    private static final String AUD = "https://attester.example.com";

    /** Starts with eyJ like every JWT, and carries a marker that must not show up anywhere. */
    private static final String SECRET = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.SECRET-MARKER";

    private StubHttpServer server;

    @BeforeEach
    void start() throws Exception {
        this.server = new StubHttpServer();
    }

    @AfterEach
    void stop() {
        this.server.close();
    }

    /** A client whose mint answers {@code mintBody} and whose token endpoint answers {@code tokenBody}. */
    private ClientAttestation client(String name, int mintStatus, String mintBody, int tokenStatus, String tokenBody) {
        this.server.respond("/" + name + "/.well-known/client-attester", 200, "{"
                + "\"attestation_endpoint\":\"" + this.server.url("/" + name + "-mint") + "\","
                + "\"token_endpoint\":\"" + this.server.url("/" + name + "-token") + "\","
                + "\"evidence_audience\":\"" + AUD + "\"}");
        this.server.respond("/" + name + "-mint", mintStatus, mintBody);
        this.server.respond("/" + name + "-token", tokenStatus, tokenBody);
        return ClientAttestation.builder(this.server.url("/" + name)).evidence(new SvidSource.Static("svid")).evidenceAudience(AUD).build();
    }

    private static String attestation() {
        String sub = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"sub\":\"demo-client\"}".getBytes(StandardCharsets.UTF_8));
        return "{\"attestation\":\"h." + sub + ".sig\"}";
    }

    /** Nothing in the chain (message, string form or kept body) carries the marker. */
    private static void assertNoSecret(Throwable thrown) {
        for (Throwable t = thrown; t != null; t = t.getCause()) {
            String shown = String.valueOf(t);
            assertFalse(shown.contains("SECRET-MARKER"), "leaks in " + shown);
            String body = t instanceof ClientAttestation.ClientAttestationException e ? e.body()
                    : t instanceof TransportException e ? e.body() : null;
            assertFalse(body != null && body.contains("SECRET-MARKER"), "body leaks in " + shown);
        }
    }

    @Test
    void unusable2xxTokenResponseKeepsNoBody() {
        List<String> bodies = List.of(
                "{\"access_token\":\"" + SECRET + "\",\"access_token\":\"other\"}",   // duplicate member
                "{\"access_token\":\"" + SECRET + "\",\"token_type\":\"Bearer\"} trailing",
                "access_token=" + SECRET + "&token_type=Bearer",
                "{\"token_type\":\"Bearer\"} \"" + SECRET + "\"",   // the parser's own message quotes this
                "{\"accessToken\":\"" + SECRET + "\",\"token_type\":\"Bearer\"}");
        for (int i = 0; i < bodies.size(); i++) {
            ClientAttestation ca = client("t" + i, 200, attestation(), 200, bodies.get(i));
            ClientAttestation.ClientAttestationException e =
                    assertThrows(ClientAttestation.ClientAttestationException.class, ca::token);
            assertNoSecret(e);
            assertNull(e.body(), bodies.get(i));
        }
    }

    @Test
    void unusable2xxMintResponseKeepsNoBody() {
        List<String> bodies = List.of(
                "{\"attestation\":\"" + SECRET + "\",\"attestation\":\"other\"}",
                "{\"client_attestation\":\"" + SECRET + "\"}");
        for (int i = 0; i < bodies.size(); i++) {
            ClientAttestation ca = client("m" + i, 200, bodies.get(i), 200, "{\"access_token\":\"AT\"}");
            ClientAttestation.ClientAttestationException e =
                    assertThrows(ClientAttestation.ClientAttestationException.class, ca::token);
            assertNoSecret(e);
            assertNull(e.body(), bodies.get(i));
        }
    }

    @Test
    void unusable2xxIssuanceResponseIsNotQuoted() {
        this.server.respond("/federation/attestation", 200, "{\"attestation\":\"" + SECRET + "\"} trailing");
        AttestationIssuanceClient client = new AttestationIssuanceClient(this.server.url("/federation/attestation"),
                "c", "https://attester.example.com", new SvidSource.Static("svid"));
        assertNoSecret(assertThrows(AttestationIssuanceClient.IssuanceException.class, () -> client.bootstrap(null, null)));
    }

    @Test
    void nonOkErrorBodiesAreCapped() {
        String longBody = "{\"error\":\"invalid_client\",\"error_description\":\"" + "d".repeat(2000) + "\"}";
        ClientAttestation.ClientAttestationException token = assertThrows(
                ClientAttestation.ClientAttestationException.class,
                () -> client("cap", 200, attestation(), 401, longBody).token());
        assertEquals(401, token.status());
        assertEquals(longBody.substring(0, 512), token.body());
        ClientAttestation.ClientAttestationException mint = assertThrows(
                ClientAttestation.ClientAttestationException.class,
                () -> client("capmint", 500, longBody, 200, "{}").token());
        assertEquals(500, mint.status());
        assertEquals(longBody.substring(0, 512), mint.body());
    }

    @Test
    void mintRecordsLeaveCredentialsOutOfToString() {
        MintRequest request = new MintRequest(SigningKeyPair.generate("ES256"), SECRET, "CHALLENGE-SECRET-MARKER",
                "client-1", null, Map.of("name", "ops"));
        assertFalse(request.toString().contains("SECRET-MARKER"), request.toString());
        assertTrue(request.toString().contains("clientId=client-1"), request.toString());
        MintResult result = new MintResult(SECRET, 60L);
        assertFalse(result.toString().contains("SECRET-MARKER"), result.toString());
        assertTrue(result.toString().contains("expiresIn=60"), result.toString());
    }
}
