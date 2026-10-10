package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * DPoP-bound tokens from the one-call client ({@code dpop_combined}): the instance key that minted the
 * attestation is kept with the cached token, {@code token_type} is honoured, and resource requests carry a
 * proof that a fake resource server verifies end to end (signature by the embedded jwk, jwk thumbprint =
 * the key the AS bound the token to, htm, htu, ath, nonce) — including the {@code use_dpop_nonce} retry at
 * both the resource and the token endpoint. Loopback fakes only.
 */
class ClientAttestationDpopTest {

    private StubHttpServer server;
    private final HttpClient client = HttpClient.newHttpClient();

    // fake AS knobs and records
    private volatile String tokenType = "DPoP";
    private volatile boolean asDemandsNonce;
    private volatile boolean asSendsNonceHeader = true;
    private final AtomicInteger issued = new AtomicInteger();
    private final Map<String, String> boundThumbprints = new ConcurrentHashMap<>();
    private final List<String> tokenEndpointProofs = Collections.synchronizedList(new ArrayList<>());

    // fake resource knobs and records
    private volatile String resourceNonce = "rs-nonce-1";
    private volatile boolean resourceUses400;
    private volatile boolean alwaysChallenge;
    private volatile String rotateNonceTo;                          // sent as DPoP-Nonce on the next 200
    private final List<Map<String, Object>> acceptedProofs = Collections.synchronizedList(new ArrayList<>());
    private final List<String> resourceAuthorizations = Collections.synchronizedList(new ArrayList<>());

    @BeforeEach
    void start() throws Exception {
        this.server = new StubHttpServer();
        this.server.respond("/.well-known/client-attester", 200, "{"
                + "\"attestation_endpoint\":\"" + this.server.url("/attest") + "\","
                + "\"challenge_endpoint\":\"" + this.server.url("/challenge") + "\","
                + "\"token_endpoint\":\"" + this.server.url("/token") + "\","
                + "\"evidence_audience\":\"https://attester.example.com\"}");
        this.server.respond("/challenge", 200, "{\"attestation_challenge\":\"chal-1\"}");
        String sub = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"sub\":\"demo-client\"}".getBytes(StandardCharsets.UTF_8));
        this.server.respond("/attest", 200, "{\"attestation\":\"h." + sub + ".sig\"}");
        this.server.route("/token", this::tokenEndpoint);
        this.server.route("/resource", this::resource);
    }

    @AfterEach
    void stop() {
        this.server.close();
    }

    private ClientAttestation dpopClient() {
        return ClientAttestation.builder(this.server.url("")).evidence(new SvidSource.Static("svid"))
                .popMethod("dpop_combined").build();
    }

    @Test
    void refusesRedirectFollowingResourceClientBeforeObtainingCredentials() {
        URI uri = URI.create(this.server.url("/resource"));
        for (HttpClient.Redirect policy : new HttpClient.Redirect[]{HttpClient.Redirect.NORMAL, HttpClient.Redirect.ALWAYS}) {
            HttpClient following = HttpClient.newBuilder().followRedirects(policy).build();
            assertThrows(IllegalArgumentException.class, () -> dpopClient().send(following,
                    HttpRequest.newBuilder(uri).GET(), "GET", uri, HttpResponse.BodyHandlers.ofString()));
        }
        assertEquals(0, this.issued.get());
        assertEquals(0, this.server.hits("/resource"));
    }

    // ── fake AS ─────────────────────────────────────────────────────────────────────────────────────

    private void tokenEndpoint(HttpExchange exchange) throws IOException {
        String proof = exchange.getRequestHeaders().getFirst("DPoP");
        if (proof == null) {
            proof = exchange.getRequestHeaders().getFirst(ClientAttestation.POP_HEADER);
        }
        this.tokenEndpointProofs.add(proof);
        Map<String, Object> claims = claims(proof);
        if (this.asDemandsNonce && !"as-nonce".equals(claims.get("nonce"))) {
            if (this.asSendsNonceHeader) {
                exchange.getResponseHeaders().set("DPoP-Nonce", "as-nonce");
            }
            StubHttpServer.send(exchange, 400, "{\"error\":\"use_dpop_nonce\"}");
            return;
        }
        String token = "AT-" + this.issued.incrementAndGet();
        this.boundThumbprints.put(token, verifiedThumbprint(proof));
        String type = this.tokenType == null ? "" : ",\"token_type\":\"" + this.tokenType + "\"";
        StubHttpServer.send(exchange, 200, "{\"access_token\":\"" + token + "\",\"expires_in\":3600" + type + "}");
    }

    // ── fake resource ───────────────────────────────────────────────────────────────────────────────

    private void resource(HttpExchange exchange) throws IOException {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        this.resourceAuthorizations.add(authorization);
        String proof = exchange.getRequestHeaders().getFirst("DPoP");
        if (authorization == null || !authorization.startsWith("DPoP ") || proof == null) {
            // Not a DPoP request: answer as if this resource wanted a nonce, to prove Bearer never retries.
            exchange.getResponseHeaders().set("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"");
            exchange.getResponseHeaders().set("DPoP-Nonce", "irrelevant");
            StubHttpServer.send(exchange, 401, "{}");
            return;
        }
        String token = authorization.substring("DPoP ".length());
        Map<String, Object> claims = claims(proof);
        String thumbprint = verifiedThumbprint(proof);
        String expectedHtu = this.server.url("/resource");
        if (!thumbprint.equals(this.boundThumbprints.get(token))
                || !exchange.getRequestMethod().equals(claims.get("htm"))
                || !expectedHtu.equals(claims.get("htu"))
                || !DpopProofBuilder.accessTokenHash(token).equals(claims.get("ath"))
                || claims.get("jti") == null || claims.get("iat") == null) {
            StubHttpServer.send(exchange, 401, "{\"error\":\"invalid_dpop_proof\"}");
            return;
        }
        if (this.alwaysChallenge) {
            this.resourceNonce = "fresh-" + System.nanoTime();
        }
        if (!this.resourceNonce.equals(claims.get("nonce"))) {
            exchange.getResponseHeaders().set("DPoP-Nonce", this.resourceNonce);
            if (this.resourceUses400) {
                StubHttpServer.send(exchange, 400, "{\"error\":\"use_dpop_nonce\"}");
            } else {
                exchange.getResponseHeaders().set("WWW-Authenticate",
                        "DPoP error=\"use_dpop_nonce\", error_description=\"Resource server requires nonce\"");
                StubHttpServer.send(exchange, 401, "{}");
            }
            return;
        }
        this.acceptedProofs.add(claims);
        if (this.rotateNonceTo != null) {
            exchange.getResponseHeaders().set("DPoP-Nonce", this.rotateNonceTo);
            this.resourceNonce = this.rotateNonceTo;
            this.rotateNonceTo = null;
        }
        StubHttpServer.send(exchange, 200, "{\"ok\":true}");
    }

    // ── tests ───────────────────────────────────────────────────────────────────────────────────────

    @Test
    void resourceNonceChallengeIsRetriedOnceAndTheNonceIsRemembered() throws Exception {
        ClientAttestation ca = dpopClient();
        URI uri = URI.create(this.server.url("/resource") + "?page=2#frag");

        HttpResponse<String> first = ca.send(this.client, HttpRequest.newBuilder(uri).GET(), "get", uri,
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, first.statusCode());
        assertEquals(2, this.server.hits("/resource"));            // challenge, then the retry
        assertEquals("rs-nonce-1", this.acceptedProofs.get(0).get("nonce"));
        assertEquals("GET", this.acceptedProofs.get(0).get("htm"));

        // The nonce is remembered for the origin: the next request needs no challenge round trip.
        HttpResponse<String> second = ca.send(this.client, HttpRequest.newBuilder(uri).GET(), "GET", uri,
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, second.statusCode());
        assertEquals(3, this.server.hits("/resource"));
        assertNotEquals(this.acceptedProofs.get(0).get("jti"), this.acceptedProofs.get(1).get("jti"));

        // One token, presented with the DPoP scheme.
        assertEquals(1, this.server.hits("/token"));
        assertEquals("DPoP AT-1", ca.authorizationHeader().get("Authorization"));
        assertTrue(this.resourceAuthorizations.stream().allMatch("DPoP AT-1"::equals));
        // The attester challenge rode as the token-endpoint proof's nonce.
        assertEquals("chal-1", claims(this.tokenEndpointProofs.get(0)).get("nonce"));
    }

    @Test
    void a400UseDpopNonceWithAByteBodyIsAlsoRetried() throws Exception {
        this.resourceUses400 = true;
        ClientAttestation ca = dpopClient();
        URI uri = URI.create(this.server.url("/resource"));
        HttpResponse<byte[]> resp = ca.send(this.client,
                HttpRequest.newBuilder(uri).POST(HttpRequest.BodyPublishers.ofString("x=1")), "POST", uri,
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(200, resp.statusCode());
        assertEquals(2, this.server.hits("/resource"));
        assertEquals("x=1", this.server.lastBodies.get("/resource"));   // the body was re-sent
        assertEquals("POST", this.acceptedProofs.get(0).get("htm"));
    }

    @Test
    void rotatedNoncesAreFollowed() throws Exception {
        ClientAttestation ca = dpopClient();
        URI uri = URI.create(this.server.url("/resource"));
        // Prime: succeed once with rs-nonce-1.
        assertEquals(200, ca.send(this.client, HttpRequest.newBuilder(uri).GET(), "GET", uri,
                HttpResponse.BodyHandlers.ofString()).statusCode());
        int before = this.server.hits("/resource");

        // The server rotates its nonce: one challenge, one retry, success.
        this.resourceNonce = "rs-nonce-2";
        assertEquals(200, ca.send(this.client, HttpRequest.newBuilder(uri).GET(), "GET", uri,
                HttpResponse.BodyHandlers.ofString()).statusCode());
        assertEquals(before + 2, this.server.hits("/resource"));

        // A nonce supplied on a successful response is used next time, with no challenge round trip.
        this.rotateNonceTo = "rs-nonce-3";
        assertEquals(200, ca.send(this.client, HttpRequest.newBuilder(uri).GET(), "GET", uri,
                HttpResponse.BodyHandlers.ofString()).statusCode());
        assertEquals(before + 3, this.server.hits("/resource"));
        assertEquals(200, ca.send(this.client, HttpRequest.newBuilder(uri).GET(), "GET", uri,
                HttpResponse.BodyHandlers.ofString()).statusCode());
        assertEquals(before + 4, this.server.hits("/resource"));
        assertEquals("rs-nonce-3", this.acceptedProofs.get(this.acceptedProofs.size() - 1).get("nonce"));

        // A body handler that cannot be inspected still sees a 401 header challenge.
        this.resourceNonce = "rs-nonce-4";
        assertEquals(200, ca.send(this.client, HttpRequest.newBuilder(uri).GET(), "GET", uri,
                HttpResponse.BodyHandlers.discarding()).statusCode());
        assertEquals(before + 6, this.server.hits("/resource"));
    }

    @Test
    void aPersistentNonceChallengeIsRetriedOnlyOnce() throws Exception {
        this.alwaysChallenge = true;
        ClientAttestation ca = dpopClient();
        URI uri = URI.create(this.server.url("/resource"));
        HttpResponse<String> resp = ca.send(this.client, HttpRequest.newBuilder(uri).GET(), "GET", uri,
                HttpResponse.BodyHandlers.ofString());
        assertEquals(401, resp.statusCode());
        assertEquals(2, this.server.hits("/resource"));
    }

    @Test
    void requestHeadersAndAuthorizeOverloadCarryABoundProof() throws Exception {
        ClientAttestation ca = dpopClient();
        String url = this.server.url("/resource") + "?q=1";
        Map<String, String> headers = ca.requestHeaders("post", url);
        assertEquals("DPoP AT-1", headers.get("Authorization"));
        Map<String, Object> proof = claims(headers.get("DPoP"));
        assertEquals("POST", proof.get("htm"));
        assertEquals(this.server.url("/resource"), proof.get("htu"));
        assertEquals(DpopProofBuilder.accessTokenHash("AT-1"), proof.get("ath"));
        assertFalse(proof.containsKey("nonce"));                     // no nonce learned yet
        assertEquals(this.boundThumbprints.get("AT-1"), verifiedThumbprint(headers.get("DPoP")));

        HttpRequest req = ca.authorize(HttpRequest.newBuilder(URI.create(url)).GET(), "GET", URI.create(url))
                .build();
        assertEquals("DPoP AT-1", req.headers().firstValue("Authorization").orElseThrow());
        assertEquals(this.boundThumbprints.get("AT-1"),
                verifiedThumbprint(req.headers().firstValue("DPoP").orElseThrow()));
        // The one-arg authorize only sets the scheme (the proof needs the method and URL).
        HttpRequest bare = ca.authorize(HttpRequest.newBuilder(URI.create(url))).build();
        assertEquals("DPoP AT-1", bare.headers().firstValue("Authorization").orElseThrow());
    }

    @Test
    void theBoundKeySurvivesWhileCachedAndChangesOnForcedRefresh() throws Exception {
        ClientAttestation ca = dpopClient();
        String url = this.server.url("/resource");
        String k1 = verifiedThumbprint(ca.requestHeaders("GET", url).get("DPoP"));
        String k2 = verifiedThumbprint(ca.requestHeaders("GET", url).get("DPoP"));
        assertEquals(k1, k2);
        assertEquals(this.boundThumbprints.get("AT-1"), k1);
        assertEquals(1, this.server.hits("/token"));

        assertEquals("AT-2", ca.token(true));
        Map<String, String> headers = ca.requestHeaders("GET", url);
        assertEquals("DPoP AT-2", headers.get("Authorization"));
        String k3 = verifiedThumbprint(headers.get("DPoP"));
        assertNotEquals(k1, k3);
        assertEquals(this.boundThumbprints.get("AT-2"), k3);

        // ...and the resource accepts the new pairing.
        URI uri = URI.create(url);
        assertEquals(200, ca.send(this.client, HttpRequest.newBuilder(uri).GET(), "GET", uri,
                HttpResponse.BodyHandlers.ofString()).statusCode());
    }

    @Test
    void tokenEndpointUseDpopNonceIsRetriedWithTheServersNonce() {
        this.asDemandsNonce = true;
        ClientAttestation ca = dpopClient();
        assertEquals("AT-1", ca.token());
        assertEquals(2, this.server.hits("/token"));
        assertEquals("chal-1", claims(this.tokenEndpointProofs.get(0)).get("nonce"));
        assertEquals("as-nonce", claims(this.tokenEndpointProofs.get(1)).get("nonce"));
        assertEquals(1, this.server.hits("/attest"));               // the attestation is reused for the retry
    }

    @Test
    void tokenEndpointUseDpopNonceWithoutANonceHeaderIsNotRetried() {
        this.asDemandsNonce = true;
        this.asSendsNonceHeader = false;
        ClientAttestation.ClientAttestationException e = assertThrows(
                ClientAttestation.ClientAttestationException.class, () -> dpopClient().token());
        assertEquals(400, e.status());
        assertEquals(1, this.server.hits("/token"));
    }

    @Test
    void popModeDoesNotRetryTheTokenEndpointOnAUseDpopNonceAnswer() {
        this.asDemandsNonce = true;
        ClientAttestation ca = ClientAttestation.builder(this.server.url(""))
                .evidence(new SvidSource.Static("svid")).build();
        assertThrows(ClientAttestation.ClientAttestationException.class, ca::token);
        assertEquals(1, this.server.hits("/token"));
    }

    @Test
    void bearerTokensAreUnchanged() throws Exception {
        for (String type : new String[] {"Bearer", "bearer", null}) {
            this.tokenType = type;
            ClientAttestation ca = dpopClient();
            String token = ca.token();
            assertEquals("Bearer " + token, ca.authorizationHeader().get("Authorization"));
            Map<String, String> headers = ca.requestHeaders("GET", this.server.url("/resource"));
            assertEquals(Map.of("Authorization", "Bearer " + token), headers);
            assertEquals("Bearer " + token, ca.authorize(HttpRequest.newBuilder(URI.create(
                    this.server.url("/resource")))).build().headers().firstValue("Authorization").orElseThrow());
        }
        // A Bearer request is sent once, even if the resource answers with a DPoP nonce challenge.
        int before = this.server.hits("/resource");
        URI uri = URI.create(this.server.url("/resource"));
        HttpResponse<String> resp = dpopClient().send(this.client, HttpRequest.newBuilder(uri).GET(), "GET", uri,
                HttpResponse.BodyHandlers.ofString());
        assertEquals(401, resp.statusCode());
        assertEquals(before + 1, this.server.hits("/resource"));
        assertNull(this.server.lastHeaders.get("/resource").getFirst("DPoP"));
    }

    @Test
    void dpopTokenTypeIsCaseInsensitive() {
        this.tokenType = "dpop";
        ClientAttestation ca = dpopClient();
        assertTrue(ca.requestHeaders("GET", this.server.url("/resource")).containsKey("DPoP"));
    }

    @Test
    void nonceChallengeDetection() {
        assertTrue(ClientAttestation.isNonceChallenge(401,
                headers("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"", "DPoP-Nonce", "n"), null));
        assertTrue(ClientAttestation.isNonceChallenge(401,
                headers("WWW-Authenticate", "Bearer realm=\"x\", DPoP algs=\"ES256\", error=\"use_dpop_nonce\"",
                        "DPoP-Nonce", "n"), null));
        assertTrue(ClientAttestation.isNonceChallenge(400, headers("DPoP-Nonce", "n"),
                "{\"error\":\"use_dpop_nonce\"}"));
        // No nonce header, wrong scheme, wrong error, wrong status, bad JSON.
        assertFalse(ClientAttestation.isNonceChallenge(401,
                headers("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\""), null));
        assertFalse(ClientAttestation.isNonceChallenge(401,
                headers("WWW-Authenticate", "Bearer error=\"use_dpop_nonce\"", "DPoP-Nonce", "n"), null));
        assertFalse(ClientAttestation.isNonceChallenge(401,
                headers("WWW-Authenticate", "DPoP error=\"invalid_token\"", "DPoP-Nonce", "n"), null));
        assertFalse(ClientAttestation.isNonceChallenge(401, headers("DPoP-Nonce", "n"), null));
        assertFalse(ClientAttestation.isNonceChallenge(400, headers("DPoP-Nonce", "n"), "{\"error\":\"x\"}"));
        assertFalse(ClientAttestation.isNonceChallenge(400, headers("DPoP-Nonce", "n"), "<html/>"));
        assertFalse(ClientAttestation.isNonceChallenge(400, headers("DPoP-Nonce", "n"), null));
        assertFalse(ClientAttestation.isNonceChallenge(403, headers("DPoP-Nonce", "n"),
                "{\"error\":\"use_dpop_nonce\"}"));
    }

    // ── helpers ─────────────────────────────────────────────────────────────────────────────────────

    private static HttpHeaders headers(String... kv) {
        Map<String, List<String>> map = new java.util.HashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            map.put(kv[i], List.of(kv[i + 1]));
        }
        return HttpHeaders.of(map, (a, b) -> true);
    }

    private static Map<String, Object> claims(String jwt) {
        try {
            return JwtTestSupport.claims(jwt);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Verifies a DPoP proof's signature with its embedded jwk and returns that jwk's RFC 7638 thumbprint. */
    @SuppressWarnings("unchecked")
    private static String verifiedThumbprint(String proof) {
        try {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(proof);
            Map<String, Object> jwk = (Map<String, Object>) JsonUtil.parseJson(jws.getHeaders().getFullHeaderAsJsonString())
                    .get("jwk");
            PublicJsonWebKey key = PublicJsonWebKey.Factory.newPublicJwk(jwk);
            jws.setKey(key.getPublicKey());
            if (!jws.verifySignature() || !DpopProofBuilder.TYP.equals(jws.getHeader("typ"))) {
                throw new IllegalStateException("bad DPoP proof");
            }
            return key.calculateBase64urlEncodedThumbprint("SHA-256");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
