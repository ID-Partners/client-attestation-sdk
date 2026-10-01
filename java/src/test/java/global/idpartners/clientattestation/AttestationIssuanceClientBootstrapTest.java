package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@link AttestationIssuanceClient#bootstrap} end to end against a loopback issuance endpoint: the request
 * it sends, how it reads the minted attestation, and how every failure surfaces as {@link
 * AttestationIssuanceClient.IssuanceException} through the shared transport.
 */
class AttestationIssuanceClientBootstrapTest {

    private static final String CLIENT_ID = "https://payment-agent.example";
    private static final String ATTESTER = "https://attester.example";

    private StubHttpServer server;

    @BeforeEach
    void start() throws Exception {
        this.server = new StubHttpServer();
    }

    @AfterEach
    void stop() {
        this.server.close();
    }

    private AttestationIssuanceClient client(String path) {
        return new AttestationIssuanceClient(this.server.url(path) + "/", CLIENT_ID, ATTESTER,
                new SvidSource.Static("the-svid"));
    }

    @Test
    void bootstrapSendsAProvenRequestAndReturnsTheMintedAttestation() throws Exception {
        this.server.respond("/federation/attestation", 200, "{\"attestation\":\"h.p.s\",\"expires_in\":600}");
        AttestationIssuanceClient client = client("/federation/attestation");

        AttestationIssuanceClient.IssuedAttestation issued = client.bootstrap(
                List.of(Map.of("type", "sales_agent")), "chal-9");

        assertEquals("h.p.s", issued.attestation());
        assertEquals(600L, issued.expiresIn());
        assertSame(client.instanceKey(), issued.instanceKey());

        Map<String, Object> sent = JsonUtil.parseJson(this.server.lastBodies.get("/federation/attestation"));
        assertEquals(CLIENT_ID, sent.get("client_id"));
        assertEquals("the-svid", sent.get("svid"));
        assertEquals(client.instanceKey().publicJwk(), sent.get("instance_key"));
        assertEquals(List.of(Map.of("type", "sales_agent")), sent.get("authorization_details"));
        assertEquals("application/json",
                this.server.lastHeaders.get("/federation/attestation").getFirst("Content-Type"));

        // The instance-key proof is signed by the instance key and bound to the attester and challenge.
        String proof = (String) sent.get("proof");
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(proof);
        jws.setKey(JsonWebKey.Factory.newJwk(client.instanceKey().publicJwk()).getKey());
        assertTrue(jws.verifySignature());
        assertEquals(AttestationIssuanceClient.INSTANCE_PROOF_TYP, JwtTestSupport.header(proof).get("typ"));
        Map<String, Object> claims = JwtTestSupport.claims(proof);
        assertEquals(ATTESTER, claims.get("aud"));
        assertEquals("chal-9", claims.get("challenge"));
    }

    @Test
    void optionalFieldsAreOmittedAndMissingExpiryIsNull() throws Exception {
        this.server.respond("/mint", 200, "{\"attestation\":\"h.p.s\"}");
        AttestationIssuanceClient.IssuedAttestation issued = client("/mint").bootstrap(null, null);
        assertNull(issued.expiresIn());
        Map<String, Object> sent = JsonUtil.parseJson(this.server.lastBodies.get("/mint"));
        assertFalse(sent.containsKey("authorization_details"));
        assertFalse(JwtTestSupport.claims((String) sent.get("proof")).containsKey("challenge"));
    }

    @Test
    void non2xxIsAnIssuanceExceptionWithStatusAndTruncatedBody() {
        this.server.respond("/mint", 403, "{\"error\":\"" + "d".repeat(4000) + "\"}");
        AttestationIssuanceClient.IssuanceException e = assertThrows(
                AttestationIssuanceClient.IssuanceException.class, () -> client("/mint").bootstrap(null, null));
        assertEquals(403, e.status());
        assertTrue(e.getMessage().startsWith("attestation issuance failed: HTTP 403: "));
        assertTrue(e.getMessage().length() < 600, "error body must be truncated");
    }

    @Test
    void redirectIsRefusedAndTheSvidIsNotForwarded() {
        this.server.respond("/elsewhere", 200, "{\"attestation\":\"h.p.s\"}");
        this.server.redirect("/mint", this.server.url("/elsewhere"));
        AttestationIssuanceClient.IssuanceException e = assertThrows(
                AttestationIssuanceClient.IssuanceException.class, () -> client("/mint").bootstrap(null, null));
        assertEquals(302, e.status());
        assertInstanceOf(TransportException.class, e.getCause());
        assertEquals(0, this.server.hits("/elsewhere"));
    }

    @Test
    void malformedJsonIsAnIssuanceException() {
        this.server.respond("/mint", 200, "not json");
        AttestationIssuanceClient.IssuanceException e = assertThrows(
                AttestationIssuanceClient.IssuanceException.class, () -> client("/mint").bootstrap(null, null));
        assertEquals(200, e.status());
        assertInstanceOf(TransportException.class, e.getCause());
    }

    @Test
    void missingOrNonStringAttestationIsAnIssuanceException() {
        this.server.respond("/none", 200, "{\"expires_in\":5}");
        this.server.respond("/numeric", 200, "{\"attestation\":42}");
        assertThrows(AttestationIssuanceClient.IssuanceException.class, () -> client("/none").bootstrap(null, null));
        assertThrows(AttestationIssuanceClient.IssuanceException.class,
                () -> client("/numeric").bootstrap(null, null));
    }

    @Test
    void oversizeResponseIsAnIssuanceException() {
        this.server.respond("/mint", 200, "{\"attestation\":\"" + "a".repeat(2 * 1024 * 1024) + "\"}");
        AttestationIssuanceClient.IssuanceException e = assertThrows(
                AttestationIssuanceClient.IssuanceException.class, () -> client("/mint").bootstrap(null, null));
        assertTrue(e.getMessage().contains("exceeds"), e.getMessage());
    }
}
