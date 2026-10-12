package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Offline test for the one-call token source: the full flow against a fake attester + token endpoint
 * (mirrors {@code python/tests/test_token_source.py}), plus base-URL normalization. No live PingFederate.
 */
class ClientAttestationTest {
    /** The evidence_audience the fake attester's discovery document names. */
    private static final String AUD = "https://attester.example.com";

    private HttpServer server;
    private String baseUrl;
    private volatile String lastMintBody;
    private volatile String lastTokenForm;
    private volatile String lastPopHeader;
    private volatile String lastDpopHeader;

    @BeforeEach
    void startFakeAttester() throws IOException {
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);

        // Discovery: /.well-known/client-attester
        this.server.createContext("/.well-known/client-attester", exchange -> {
            String base = "http://127.0.0.1:" + server.getAddress().getPort();
            json(exchange, 200, "{"
                    + "\"attestation_endpoint\":\"" + base + "/federation/attestation\","
                    + "\"challenge_endpoint\":\"" + base + "/federation/attestation-challenge\","
                    + "\"token_endpoint\":\"" + base + "/as/token.oauth2\","
                    + "\"evidence_audience\":\"" + AUD + "\","
                    + "\"pop_audience\":\"https://pf.issuer.example\"}");
        });

        this.server.createContext("/federation/attestation-challenge", exchange ->
                json(exchange, 200, "{\"attestation_challenge\":\"chal-123\",\"expires_in\":300}"));

        // Mint: echoes an attestation whose payload has sub=demo-client.
        this.server.createContext("/federation/attestation", exchange -> {
            String body = read(exchange);
            this.lastMintBody = body;
            String sub = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"sub\":\"demo-client\"}".getBytes(StandardCharsets.UTF_8));
            json(exchange, 200, "{\"attestation\":\"h." + sub + ".sig\",\"expires_in\":300}");
        });

        // Token endpoint: requires both attestation headers.
        this.server.createContext("/as/token.oauth2", exchange -> {
            this.lastTokenForm = read(exchange);
            this.lastPopHeader = exchange.getRequestHeaders().getFirst(ClientAttestation.POP_HEADER);
            this.lastDpopHeader = exchange.getRequestHeaders().getFirst(ClientAttestation.DPOP_HEADER);
            if (exchange.getRequestHeaders().getFirst(ClientAttestation.ATTESTATION_HEADER) == null
                    || (this.lastPopHeader == null && this.lastDpopHeader == null)) {
                json(exchange, 401, "{\"error\":\"invalid_client\"}");
                return;
            }
            json(exchange, 200, "{\"access_token\":\"AT-xyz\",\"expires_in\":3600,\"token_type\":\"Bearer\"}");
        });

        this.server.start();
        this.baseUrl = "http://127.0.0.1:" + this.server.getAddress().getPort();
    }

    @AfterEach
    void stop() {
        this.server.stop(0);
    }

    @Test
    void fullFlowReturnsAndCachesAToken() throws Exception {
        ClientAttestation ca = ClientAttestation.builder(this.baseUrl).evidenceAudience(AUD)
                .evidence(new SvidSource.Static("fake-svid")).build();

        String token = ca.token();
        assertEquals("AT-xyz", token);
        assertEquals("Bearer AT-xyz", ca.authorizationHeader().get("Authorization"));

        // Cached: a second call returns the same token without re-minting.
        assertEquals("AT-xyz", ca.token());

        // Evidence-first: the mint body carries instance_key/svid/proof but NO client_id.
        assertTrue(this.lastMintBody.contains("instance_key"));
        assertTrue(this.lastMintBody.contains("svid"));
        assertTrue(this.lastMintBody.contains("proof"));
        assertFalse(this.lastMintBody.contains("client_id"));

        // The token form is client_credentials with no secret and no client_id.
        assertTrue(this.lastTokenForm.contains("grant_type=client_credentials"));
        assertFalse(this.lastTokenForm.contains("client_secret"));
        assertFalse(this.lastTokenForm.contains("client_id"));

        // The fetched challenge must not be dropped: it is carried in the PoP JWT's challenge claim.
        Map<String, Object> popClaims = JwtTestSupport.claims(this.lastPopHeader);
        assertEquals("chal-123", popClaims.get("challenge"));
    }

    @Test
    void dpopCombinedModeSendsDpopHeaderWithNonceInsteadOfPop() throws Exception {
        ClientAttestation ca = ClientAttestation.builder(this.baseUrl).evidenceAudience(AUD)
                .evidence(new SvidSource.Static("fake-svid"))
                .popMethod("dpop_combined")
                .build();

        String token = ca.token();
        assertEquals("AT-xyz", token);

        // A DPoP header is sent instead of the dedicated PoP header.
        assertTrue(this.lastDpopHeader != null && !this.lastDpopHeader.isBlank());
        assertNull(this.lastPopHeader);

        // The DPoP proof's nonce carries the fake attester's fixed challenge.
        Map<String, Object> dpopClaims = JwtTestSupport.claims(this.lastDpopHeader);
        assertEquals("chal-123", dpopClaims.get("nonce"));
        assertEquals("POST", dpopClaims.get("htm"));
    }

    @Test
    void draftRevisionIsTen() {
        assertEquals("10", ClientAttestation.DRAFT_REVISION);
    }

    @Test
    void operatorGoesInTheMintBodyAndAsASortedCompactTokenParameter() throws Exception {
        Map<String, Object> operator = new java.util.LinkedHashMap<>();
        operator.put("sub", "ops@example.com");
        operator.put("iss", "https://idp.example/é");
        operator.put("aud", java.util.List.of(Map.of("z", 1, "a", true)));
        ClientAttestation ca = ClientAttestation.builder(this.baseUrl).evidenceAudience(AUD)
                .evidence(new SvidSource.Static("fake-svid")).operator(operator).build();
        assertEquals("AT-xyz", ca.token());

        Map<String, Object> mint = org.jose4j.json.JsonUtil.parseJson(this.lastMintBody);
        assertEquals(ClientAttestation.canonicalJson(operator), ClientAttestation.canonicalJson((Map<?, ?>) mint.get("operator")));

        // Exactly what Python's json.dumps(op, separators=(",", ":"), sort_keys=True) produces.
        String expected = "{\"aud\":[{\"a\":true,\"z\":1}],\"iss\":\"https://idp.example/\\u00e9\","
                + "\"sub\":\"ops@example.com\"}";
        assertEquals("grant_type=client_credentials&operator="
                + java.net.URLEncoder.encode(expected, StandardCharsets.UTF_8), this.lastTokenForm);
        Map<String, String> form = parseForm(this.lastTokenForm);
        assertEquals(expected, form.get("operator"));
    }

    @Test
    void noOperatorMeansNothingSent() throws Exception {
        ClientAttestation ca = ClientAttestation.builder(this.baseUrl).evidenceAudience(AUD)
                .evidence(new SvidSource.Static("fake-svid")).operator(Map.of()).build();
        ca.token();
        assertFalse(this.lastMintBody.contains("operator"));
        assertEquals("grant_type=client_credentials", this.lastTokenForm);
    }

    @Test
    void challengeAtTokenFalseKeepsTheChallengeOutOfThePop() throws Exception {
        ClientAttestation ca = ClientAttestation.builder(this.baseUrl).evidenceAudience(AUD)
                .evidence(new SvidSource.Static("fake-svid")).challengeAtToken(false).build();
        assertEquals("AT-xyz", ca.token());
        assertFalse(JwtTestSupport.claims(this.lastPopHeader).containsKey("challenge"));
        // The challenge still protects the mint's instance proof.
        assertEquals("chal-123", mintProofChallenge());
    }

    @Test
    void challengeAtTokenFalseKeepsTheChallengeOutOfTheDpopNonce() throws Exception {
        ClientAttestation ca = ClientAttestation.builder(this.baseUrl).evidenceAudience(AUD)
                .evidence(new SvidSource.Static("fake-svid")).popMethod("dpop_combined").challengeAtToken(false)
                .build();
        assertEquals("AT-xyz", ca.token());
        assertFalse(JwtTestSupport.claims(this.lastDpopHeader).containsKey("nonce"));
        assertEquals("chal-123", mintProofChallenge());
    }

    @Test
    void challengeAtTokenDefaultsToTrue() throws Exception {
        ClientAttestation.builder(this.baseUrl).evidenceAudience(AUD).evidence(new SvidSource.Static("fake-svid")).build().token();
        assertEquals("chal-123", JwtTestSupport.claims(this.lastPopHeader).get("challenge"));
        assertEquals("chal-123", mintProofChallenge());
    }

    private Object mintProofChallenge() throws Exception {
        Map<String, Object> mint = org.jose4j.json.JsonUtil.parseJson(this.lastMintBody);
        return JwtTestSupport.claims((String) mint.get("proof")).get("challenge");
    }

    private static Map<String, String> parseForm(String form) {
        Map<String, String> out = new java.util.HashMap<>();
        for (String pair : form.split("&")) {
            String[] kv = pair.split("=", 2);
            out.put(java.net.URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                    java.net.URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
        }
        return out;
    }

    @Test
    void normalizeBaseUrlAddsHttpsAndStripsSlash() {
        assertEquals("https://pf.example.com", ClientAttestation.normalizeBaseUrl("pf.example.com"));
        assertEquals("https://pf.example.com", ClientAttestation.normalizeBaseUrl("https://pf.example.com/"));
        assertEquals("http://pf.pf:9080", ClientAttestation.normalizeBaseUrl("http://pf.pf:9080"));
        assertThrows(IllegalArgumentException.class, () -> ClientAttestation.normalizeBaseUrl("   "));
    }

    /** An evidence source that records the audiences it was asked for. */
    private static final class RecordingSource implements SvidSource {
        final java.util.List<String> audiences = new java.util.ArrayList<>();

        @Override
        public String fetch(String audience) {
            this.audiences.add(audience);
            return "svid";
        }
    }

    @Test
    void evidenceAudienceIsRequiredBeforeAnyRequest() {
        // Without a pin the discovery document would choose the audience the workload's identity token is for.
        RecordingSource source = new RecordingSource();
        ClientAttestation ca = ClientAttestation.builder("https://attester.invalid") // not resolvable: any request would fail
                .evidence(source).build();
        ClientAttestation.ClientAttestationException e =
                assertThrows(ClientAttestation.ClientAttestationException.class, ca::token);
        assertTrue(e.getMessage().startsWith("evidenceAudience is required"), e.getMessage());
        assertEquals(java.util.List.of(), source.audiences);
    }

    @Test
    void aDiscoveredAudienceOtherThanThePinFetchesNoEvidence() {
        RecordingSource source = new RecordingSource();
        ClientAttestation ca = ClientAttestation.builder(this.baseUrl).evidence(source)
                .evidenceAudience("https://other-service.example").build();
        ClientAttestation.ClientAttestationException e =
                assertThrows(ClientAttestation.ClientAttestationException.class, ca::token);
        assertEquals("the attester asks for evidence for \"https://attester.example.com\", but evidenceAudience is "
                + "\"https://other-service.example\"", e.getMessage());
        assertEquals(java.util.List.of(), source.audiences);
        assertNull(this.lastMintBody);
    }

    @Test
    void staticMetadataNeedsNoPinButMustMatchOne() throws Exception {
        AttesterMetadata meta = AttesterMetadata.of("aud-1", this.baseUrl + "/federation/attestation",
                this.baseUrl + "/as/token.oauth2");
        RecordingSource source = new RecordingSource();
        ClientAttestation.ClientAttestationException e = assertThrows(ClientAttestation.ClientAttestationException.class,
                () -> ClientAttestation.builder().metadata(meta).evidence(source).evidenceAudience("aud-2").build()
                        .token());
        assertTrue(e.getMessage().endsWith("but evidenceAudience is \"aud-2\""), e.getMessage());
        assertEquals(java.util.List.of(), source.audiences);
        // No pin needed: the flow runs to a token.
        assertEquals("AT-xyz", ClientAttestation.builder().metadata(meta).evidence(source).build().token());
        assertEquals(java.util.List.of("aud-1"), source.audiences);
        // A matching pin is accepted.
        assertEquals("AT-xyz", ClientAttestation.builder().metadata(meta).evidence(source).evidenceAudience("aud-1")
                .build().token());
    }

    // ── helpers ─────────────────────────────────────────────────────────────────────────────────────

    private static String read(HttpExchange exchange) throws IOException {
        return new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    }

    private static void json(HttpExchange exchange, int code, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(code, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }
}
