package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Flow;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
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
    /** The evidence_audience the fake attester's discovery document names. */
    private static final String AUD = "https://attester.example.com";

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
                + "\"evidence_audience\":\"" + AUD + "\"}");
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
        return ClientAttestation.builder(this.server.url("")).evidence(new SvidSource.Static("svid")).evidenceAudience(AUD)
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

    @Test
    void refusesARequestOnAnotherOriginThanTheCredentialsAreBuiltFor() {
        URI uri = URI.create(this.server.url("/resource"));
        URI elsewhere = URI.create("https://elsewhere.example/resource");
        assertThrows(IllegalArgumentException.class, () -> dpopClient().send(this.client,
                HttpRequest.newBuilder(elsewhere).GET(), "GET", uri, HttpResponse.BodyHandlers.ofString()));
        assertEquals(0, this.issued.get());
    }

    @Test
    void refusesAPlainHttpResourceUnlessLoopbackOrAllowInsecure() {
        ClientAttestation ca = dpopClient();
        ClientAttestation.ClientAttestationException e = assertThrows(ClientAttestation.ClientAttestationException.class,
                () -> ca.requestHeaders("GET", "http://api.example.com/things"));
        assertTrue(e.getMessage().contains("resource URL must use https"), e.getMessage());
        URI plain = URI.create("http://api.example.com/things");
        assertThrows(ClientAttestation.ClientAttestationException.class, () -> ca.send(this.client,
                HttpRequest.newBuilder(plain).GET(), "GET", plain, HttpResponse.BodyHandlers.ofString()));
        assertThrows(ClientAttestation.ClientAttestationException.class,
                () -> ca.authorize(HttpRequest.newBuilder(plain), "GET", plain));
        assertEquals(0, this.issued.get());

        assertTrue(ca.requestHeaders("GET", this.server.url("/resource")).containsKey("DPoP"));
        ClientAttestation insecure = ClientAttestation.builder(this.server.url("")).evidence(new SvidSource.Static("svid"))
                .popMethod("dpop_combined").evidenceAudience(AUD).allowInsecure(true).build();
        assertTrue(insecure.requestHeaders("GET", "http://api.example.com/things").containsKey("DPoP"));
    }

    @Test
    void httpsRuleReadsUrlsThatUriCreateRefuses() {
        // Unencoded `|`, `{`, `}`, `"`, `^` or a space in the query: other HTTP clients send these as-is
        ClientAttestation ca = dpopClient();
        assertTrue(ca.requestHeaders("GET", "https://api.example.com/graphql?q={a|b}").containsKey("DPoP"));
        assertTrue(ca.requestHeaders("GET", "http://localhost:8080/q?x=a|b").containsKey("DPoP"));
        assertTrue(ca.requestHeaders("GET", "http://[::1]:8080/q?x=a b").containsKey("DPoP"));
        ClientAttestation.ClientAttestationException e = assertThrows(ClientAttestation.ClientAttestationException.class,
                () -> ca.requestHeaders("GET", "http://api.example.com/q?x=a|b"));
        assertTrue(e.getMessage().contains("resource URL must use https"), e.getMessage());
        assertThrows(ClientAttestation.ClientAttestationException.class,
                () -> ca.requestHeaders("GET", "not a url|at all"));
    }

    // ── fake AS ─────────────────────────────────────────────────────────────────────────────────────

    private void tokenEndpoint(HttpExchange exchange) throws IOException {
        String dpop = exchange.getRequestHeaders().getFirst("DPoP");
        String proof = dpop != null ? dpop : exchange.getRequestHeaders().getFirst(ClientAttestation.POP_HEADER);
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
        // attestation_pop_jwt mode sends no DPoP proof: a DPoP token issued then is bound to no proof key.
        this.boundThumbprints.put(token, dpop != null ? verifiedThumbprint(proof) : "none");
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
                .evidence(new SvidSource.Static("svid")).evidenceAudience(AUD).build();
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

    // ── the nonce memory and the retry's nonce ──────────────────────────────────────────────────────

    @Test
    void aChallengeWithAnOverLongNonceIsNotAnsweredOrRemembered() throws Exception {
        this.resourceNonce = "n".repeat(ClientAttestation.MAX_DPOP_NONCE_LENGTH + 1);
        ClientAttestation ca = dpopClient();
        URI uri = URI.create(this.server.url("/resource"));
        HttpResponse<String> resp = ca.send(this.client, HttpRequest.newBuilder(uri).GET(), "GET", uri,
                HttpResponse.BodyHandlers.ofString());
        assertEquals(401, resp.statusCode());
        assertEquals(1, this.server.hits("/resource"));
        assertNull(ca.nonceFor(uri.toString()));
    }

    @Test
    void theNonceMemoryKeepsAtMost256OriginsDroppingTheOldest() {
        ClientAttestation ca = dpopClient();
        int count = ClientAttestation.MAX_DPOP_NONCE_ORIGINS + 44;
        for (int i = 0; i < count; i++) {
            ca.rememberNonce("https://h" + i + ".example/p" + i, "n" + i);
            ca.rememberNonce("https://h1.example/", "n1");             // kept fresh, so never the oldest
        }
        assertNull(ca.nonceFor("https://h0.example/"));
        assertEquals("n1", ca.nonceFor("https://h1.example/"));
        assertEquals("n" + (count - 1), ca.nonceFor("https://h" + (count - 1) + ".example/"));
    }

    @Test
    void noncesAreKeyedByOriginEvenWhenUriFindsNoHost() {
        // URI has no host for a name with '_'; the key is still the authority, never the path.
        assertEquals("https://my_host.example.com", ClientAttestation.nonceKey("https://my_host.example.com/a?x"));
        assertEquals("https://my_host.example.com",
                ClientAttestation.nonceKey("https://user@MY_HOST.example.com:443/b/c"));
        assertEquals("https://my_host.example.com:8443",
                ClientAttestation.nonceKey("https://my_host.example.com:8443/b"));
        assertEquals("https://as.example", ClientAttestation.nonceKey("https://as.example/a|b"));   // URI refuses it
        assertEquals("https://as.example", ClientAttestation.nonceKey("HTTPS://AS.example:443/x"));
    }

    @Test
    void theRetryCarriesTheChallengesNonceEvenIfAnotherResponseStoredOne() throws Exception {
        String url = this.server.url("/resource");
        AtomicReference<ClientAttestation> ref = new AtomicReference<>();
        // Between the challenge and the retry, another response for the origin stores a different nonce.
        System.Logger logger = new System.Logger() {
            @Override
            public String getName() {
                return ClientAttestation.LOGGER_NAME;
            }

            @Override
            public boolean isLoggable(Level level) {
                return true;
            }

            @Override
            public void log(Level level, ResourceBundle bundle, String msg, Throwable thrown) {
                if (msg.startsWith("dpop.nonce_retry")) {
                    ref.get().rememberNonce(url, "other-nonce");
                }
            }

            @Override
            public void log(Level level, ResourceBundle bundle, String format, Object... params) {
                log(level, bundle, format, (Throwable) null);
            }
        };
        ClientAttestation ca = ClientAttestation.builder(this.server.url("")).evidence(new SvidSource.Static("svid")).evidenceAudience(AUD)
                .popMethod("dpop_combined").logger(logger).build();
        ref.set(ca);
        URI uri = URI.create(url);
        HttpResponse<String> resp = ca.send(this.client, HttpRequest.newBuilder(uri).GET(), "GET", uri,
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());
        assertEquals("rs-nonce-1", this.acceptedProofs.get(0).get("nonce"));
    }

    // ── streamed body handlers ──────────────────────────────────────────────────────────────────────

    @Test
    void a400ChallengeIsSeenThroughAStreamingBodyHandler() throws Exception {
        this.resourceUses400 = true;
        ClientAttestation ca = dpopClient();
        URI uri = URI.create(this.server.url("/resource"));
        HttpResponse<InputStream> resp = ca.send(this.client, HttpRequest.newBuilder(uri).GET(), "GET", uri,
                HttpResponse.BodyHandlers.ofInputStream());
        assertEquals(200, resp.statusCode());
        assertEquals("{\"ok\":true}", new String(resp.body().readAllBytes(), StandardCharsets.UTF_8));
        assertEquals(2, this.server.hits("/resource"));
    }

    @Test
    void a400ThatIsNotAChallengeReachesAStreamingHandlerWhole() throws Exception {
        String big = "{\"error\":\"use_dpop_nonce\"}" + " ".repeat(ClientAttestation.MAX_NONCE_CHALLENGE_BODY);
        this.server.route("/big", exchange -> {
            exchange.getResponseHeaders().set("DPoP-Nonce", "n");
            StubHttpServer.send(exchange, 400, big);
        });
        this.server.route("/other", exchange -> {
            exchange.getResponseHeaders().set("DPoP-Nonce", "n");
            StubHttpServer.send(exchange, 400, "{\"error\":\"invalid_request\"}");
        });
        ClientAttestation ca = dpopClient();
        for (String path : List.of("/big", "/other")) {
            URI uri = URI.create(this.server.url(path));
            HttpResponse<InputStream> streamed = ca.send(this.client, HttpRequest.newBuilder(uri).GET(), "GET", uri,
                    HttpResponse.BodyHandlers.ofInputStream());
            String expected = path.equals("/big") ? big : "{\"error\":\"invalid_request\"}";
            assertEquals(400, streamed.statusCode());
            assertEquals(expected, new String(streamed.body().readAllBytes(), StandardCharsets.UTF_8));
            assertEquals(expected, ca.send(this.client, HttpRequest.newBuilder(uri).GET(), "GET", uri,
                    HttpResponse.BodyHandlers.ofString()).body());
            assertEquals(2, this.server.hits(path));                      // never retried
        }
    }

    @Test
    void aStreamedChallengeBodyIsReleasedBeforeTheRetry() throws Exception {
        ClientAttestation ca = dpopClient();
        URI uri = URI.create(this.server.url("/resource"));
        List<AtomicBoolean> closed = Collections.synchronizedList(new ArrayList<>());
        HttpResponse<InputStream> resp = ca.send(this.client, HttpRequest.newBuilder(uri).GET(), "GET", uri,
                info -> HttpResponse.BodySubscribers.mapping(HttpResponse.BodySubscribers.ofInputStream(), in -> {
                    AtomicBoolean flag = new AtomicBoolean();
                    closed.add(flag);
                    return new FilterInputStream(in) {
                        @Override
                        public void close() throws IOException {
                            flag.set(true);
                            super.close();
                        }
                    };
                }));
        assertEquals(200, resp.statusCode());
        assertEquals(List.of(true, false), closed.stream().map(AtomicBoolean::get).toList());
        resp.body().close();

        this.resourceNonce = "rs-nonce-2";                               // challenge again
        List<AtomicBoolean> cancelled = Collections.synchronizedList(new ArrayList<>());
        HttpResponse<Flow.Publisher<List<ByteBuffer>>> published = ca.send(this.client,
                HttpRequest.newBuilder(uri).GET(), "GET", uri,
                info -> HttpResponse.BodySubscribers.mapping(HttpResponse.BodySubscribers.ofPublisher(), p -> {
                    AtomicBoolean flag = new AtomicBoolean();
                    cancelled.add(flag);
                    return subscriber -> p.subscribe(new Flow.Subscriber<List<ByteBuffer>>() {
                        @Override
                        public void onSubscribe(Flow.Subscription subscription) {
                            subscriber.onSubscribe(new Flow.Subscription() {
                                @Override
                                public void request(long n) {
                                    subscription.request(n);
                                }

                                @Override
                                public void cancel() {
                                    flag.set(true);
                                    subscription.cancel();
                                }
                            });
                        }

                        @Override
                        public void onNext(List<ByteBuffer> item) {
                            subscriber.onNext(item);
                        }

                        @Override
                        public void onError(Throwable throwable) {
                            subscriber.onError(throwable);
                        }

                        @Override
                        public void onComplete() {
                            subscriber.onComplete();
                        }
                    });
                }));
        assertEquals(200, published.statusCode());
        assertEquals(2, cancelled.size());
        assertTrue(cancelled.get(0).get(), "the challenge's body was not released");
    }

    // ── URLs that parsers disagree on ───────────────────────────────────────────────────────────────

    @Test
    void urlsThatParsersDisagreeOnAreRefused() throws Exception {
        ClientAttestation ca = dpopClient();
        SigningKeyPair key = SigningKeyPair.generate("ES256");
        for (String url : List.of("https://evil.example\\@as.example/t", "https://as.example/a\\b",
                " https://as.example/t", "https://as.example/t ", "https://as.example\t/t", "https://as.example/t\n",
                "https://as.example/\u0000t", "https://as.example/\u007ft")) {
            assertThrows(ClientAttestation.ClientAttestationException.class, () -> ca.requestHeaders("GET", url), url);
            assertThrows(IllegalArgumentException.class, () -> new DpopProofBuilder(key).uri(url).build(), url);
        }
        assertEquals(0, this.server.hits("/token"));
        // What follows the path never becomes htu, so it is left alone.
        assertEquals("https://as.example/t",
                claims(new DpopProofBuilder(key).uri("https://as.example/t?q=a\\b c#a b").build()).get("htu"));
    }

    private static final List<String> NO_HTU = List.of("https://b\u00fccher.example/t");

    @Test
    void aDpopClientRefusesAUrlWithNoHtuBeforeTheTokenIsFetched() {
        for (String type : List.of("DPoP", "Bearer")) {
            this.tokenType = type;
            ClientAttestation ca = dpopClient();
            for (String url : NO_HTU) {
                ClientAttestation.ClientAttestationException e = assertThrows(
                        ClientAttestation.ClientAttestationException.class, () -> ca.requestHeaders("GET", url), url);
                assertTrue(e.getMessage().startsWith("uri (htu) "), e.getMessage());
            }
        }
        // A cold cache every time, yet no mint and no token request.
        assertEquals(0, this.server.hits("/attest"));
        assertEquals(0, this.server.hits("/token"));
    }

    @Test
    void aClientNotConfiguredForDpopSendsABearerTokenToAnyUrl() {
        this.tokenType = "Bearer";
        ClientAttestation ca = ClientAttestation.builder(this.server.url("")).evidence(new SvidSource.Static("svid"))
                .evidenceAudience(AUD).build();
        for (String url : NO_HTU) {
            assertEquals(Map.of("Authorization", "Bearer AT-1"), ca.requestHeaders("GET", url), url);
        }
    }

    @Test
    void aDpopTokenTheAsChoseStillRefusesAUrlWithNoHtu() {
        this.tokenType = "DPoP";
        ClientAttestation ca = ClientAttestation.builder(this.server.url("")).evidence(new SvidSource.Static("svid"))
                .evidenceAudience(AUD).build();
        for (String url : NO_HTU) {
            ClientAttestation.ClientAttestationException e = assertThrows(
                    ClientAttestation.ClientAttestationException.class, () -> ca.requestHeaders("GET", url), url);
            assertTrue(e.getMessage().startsWith("uri (htu) "), e.getMessage());
        }
        assertEquals(1, this.server.hits("/token"));
    }

    /**
     * send() signs the request target the JDK client sends: the htu is what the resource received, which a
     * conforming RS (RFC 9449 section 4.3) compares after RFC 3986 section 6.2.2 normalisation, decoding only
     * unreserved characters. {@code java.net.URI} cannot hold a raw {@code [}, {@code ]}, {@code |} or lone
     * {@code %}, so they are given escaped (as the multi-argument constructor writes them), with a non-ASCII
     * character the client encodes itself.
     */
    @Test
    void sendSignsTheRequestTargetItSends() throws Exception {
        List<String[]> seen = Collections.synchronizedList(new ArrayList<>());
        this.server.route("/odd", exchange -> {
            String proof = exchange.getRequestHeaders().getFirst("DPoP");
            verifiedThumbprint(proof);
            seen.add(new String[] {this.server.url(exchange.getRequestURI().getRawPath()),
                    (String) claims(proof).get("htu")});
            StubHttpServer.send(exchange, 200, "{}");
        });
        ClientAttestation ca = dpopClient();
        URI built = new URI("http", null, "127.0.0.1", URI.create(this.server.url("")).getPort(),
                "/odd/items[0]/a|b/caf\u00e9", "q=1", null);
        for (URI uri : List.of(built, URI.create(this.server.url("/odd/a%5Bb%5D%7Cc%25")))) {
            assertEquals(200, ca.send(this.client, HttpRequest.newBuilder(uri).GET(), "GET", uri,
                    HttpResponse.BodyHandlers.ofString()).statusCode(), uri.toString());
        }
        assertEquals(2, seen.size());
        assertEquals(this.server.url("/odd/items%5B0%5D/a%7Cb/caf%C3%A9"), seen.get(0)[0]);
        for (String[] targetAndHtu : seen) {
            assertEquals(targetAndHtu[0], targetAndHtu[1]);
        }
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

    @Test
    void sendTreatsAUrlTheHtuRuleRefusesAsOneOrigin() {
        // an IPv6 zone literal is refused by the htu rule (so it is its own nonce key), but two requests to it
        // with different paths, queries or userinfo are still on one origin; another port is not
        URI a = URI.create("https://User@[FE80::1%25eth0]:8443/a?x=1");
        assertTrue(ClientAttestation.sameOrigin(a, URI.create("https://[fe80::1%25eth0]:8443/b")));
        assertFalse(ClientAttestation.sameOrigin(a, URI.create("https://[fe80::1%25eth0]:9443/a?x=1")));
        assertTrue(ClientAttestation.sameOrigin(URI.create("https://as.example/a"), URI.create("https://AS.example:443/b")));
        assertFalse(ClientAttestation.sameOrigin(URI.create("https://as.example/a"), URI.create("https://other.example/a")));
    }

    @Test
    void sameOriginNormalisesThePortOnlyToTheSchemesOwnDefaultAndRefusesAnyOtherPort() {
        String z = "[fe80::1%25eth0]";
        Object[][] cases = {
            // the scheme's own default port is the same as none; a leading zero is the same number
            {"https://as.example/a", "https://as.example:443/b", true},
            {"https://as.example:0443/a", "https://AS.example/b", true},
            {"http://as.example/a", "http://as.example:80/b", true},
            {"http://as.example:080/a", "http://as.example/b", true},
            {"https://as.example:08443/a", "https://as.example:8443/b", true},
            {"https://u@as.example:00008443/a", "https://as.example:8443", true},
            {"https://as.example:1/", "https://as.example:01/", true},
            {"https://as.example:65535/", "https://as.example:65535/", true},
            {"https://" + z + "/a", "https://" + z + ":443/b", true},
            {"https://User@[FE80::1%25eth0]:08443/a?x=1", "https://" + z + ":8443/b", true},
            {"http://" + z + ":80/a", "http://" + z + "/b", true},
            // a default port belongs to its own scheme only
            {"https://as.example:80/", "http://as.example/", false},
            {"https://as.example:80/", "http://as.example:80/", false},
            {"https://as.example:80/", "https://as.example/", false},
            {"http://as.example:443/", "https://as.example/", false},
            {"http://as.example:443/", "https://as.example:443/", false},
            {"http://as.example:443/", "http://as.example/", false},
            {"https://" + z + ":80/", "http://" + z + "/", false},
            {"http://" + z + ":443/", "https://" + z + "/", false},
            // other ports, hosts and zones
            {"https://as.example:8443/", "https://as.example:9443/", false},
            {"https://as.example:8443/", "https://as.example/", false},
            {"https://" + z + ":8443/", "https://[fe80::1%25eth1]:8443/", false},
            {"https://" + z + ":8443/", "https://[fe80::1%25ETH0]:8443/", false},
            {"https://" + z + ":8443/", "https://[fe80::1]:8443/", false},
            {"https://" + z + ":8443/", "https://[fe80::2%25eth0]:8443/", false},
        };
        for (Object[] c : cases) {
            URI a = URI.create((String) c[0]);
            URI b = URI.create((String) c[1]);
            assertEquals(c[2], ClientAttestation.sameOrigin(a, b), c[0] + " vs " + c[1]);
            assertEquals(c[2], ClientAttestation.sameOrigin(b, a), c[1] + " vs " + c[0]);
        }
        // A port that is not a number from 1 to 65535 puts the URI on no origin: not even the identical
        // string is the same origin, nor the URI without the port. (A raw space or sign is not a valid URI
        // port either; whitespace can only reach a URI percent-encoded.)
        String[] badPorts = {"0", "00", "65536", "065536", "99999", "4294967739", "4294967296", "99999999999999999999",
            "", "+443", "-1", "-0", "%20443", "443%20", "0x1bb", "44a", "\u0661"};
        for (String host : new String[] {"as.example", "AS.example", z, "[::1]"}) {
            for (String scheme : new String[] {"https", "http"}) {
                for (String port : badPorts) {
                    String text = scheme + "://" + host + ":" + port + "/a";
                    URI bad;
                    try {
                        bad = URI.create(text);
                    } catch (IllegalArgumentException e) {
                        continue;   // not a URI at all, so it never reaches the guard
                    }
                    assertFalse(ClientAttestation.sameOrigin(bad, URI.create(text)), text + " vs itself");
                    assertFalse(ClientAttestation.sameOrigin(bad, bad), text + " vs the same URI");
                    URI bare = URI.create(scheme + "://" + host + "/a");
                    assertFalse(ClientAttestation.sameOrigin(bad, bare), text + " vs no port");
                    assertFalse(ClientAttestation.sameOrigin(bare, bad), "no port vs " + text);
                }
            }
        }
    }

    @Test
    void sendGuardsAnIpv6ZoneLiteralByItsOrigin() throws Exception {
        // send() itself, with a zone literal (which the htu rule refuses), against a local server: a request on
        // the same origin (another path or query, the port written with leading zeros) is sent; one on another
        // port, zone or scheme, or with a port that is no port, is refused before any connection is made.
        java.net.NetworkInterface loopback = java.net.NetworkInterface.networkInterfaces()
                .filter(nif -> {
                    try {
                        return nif.isLoopback() && nif.isUp();
                    } catch (java.net.SocketException e) {
                        return false;
                    }
                })
                .findFirst().orElse(null);
        org.junit.jupiter.api.Assumptions.assumeTrue(loopback != null, "no loopback interface");
        com.sun.net.httpserver.HttpServer zoneServer;
        try {
            zoneServer = com.sun.net.httpserver.HttpServer.create(
                    new java.net.InetSocketAddress(java.net.InetAddress.getByName("::1"), 0), 0);
        } catch (IOException e) {
            org.junit.jupiter.api.Assumptions.abort("no IPv6 loopback: " + e);
            return;
        }
        AtomicInteger hits = new AtomicInteger();
        AtomicReference<String> authorization = new AtomicReference<>();
        zoneServer.createContext("/zone", exchange -> {
            hits.incrementAndGet();
            authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        zoneServer.start();
        try {
            this.tokenType = "Bearer";
            ClientAttestation ca = ClientAttestation.builder(this.server.url("")).evidence(new SvidSource.Static("svid"))
                    .evidenceAudience(AUD).allowInsecure(true).build();   // Bearer: a zone literal has no htu
            int port = zoneServer.getAddress().getPort();
            // The JDK's URI takes the zone ID unescaped ([::1%lo0]); that is the form HttpClient connects to.
            String origin = "http://[::1%" + loopback.getName() + "]:" + port;
            URI uri = URI.create(origin + "/zone?x=1");
            HttpResponse<Void> resp = ca.send(this.client, HttpRequest.newBuilder(URI.create(origin + "/zone")).GET(),
                    "GET", uri, HttpResponse.BodyHandlers.discarding());
            assertEquals(204, resp.statusCode());
            assertEquals(1, hits.get());
            assertEquals("Bearer " + ca.token(), authorization.get());
            // the same origin with the port written with leading zeros is still sent
            resp = ca.send(this.client, HttpRequest.newBuilder(URI.create(origin.replace("]:", "]:00") + "/zone")).GET(),
                    "GET", uri, HttpResponse.BodyHandlers.discarding());
            assertEquals(204, resp.statusCode());
            assertEquals(2, hits.get());

            String[] elsewhere = {
                "http://[::1%" + loopback.getName() + "]:" + (port == 65535 ? port - 1 : port + 1) + "/zone",
                "http://[::1%" + loopback.getName() + "x]:" + port + "/zone",
                "http://[::1]:" + port + "/zone",
                "https://[::1%" + loopback.getName() + "]:" + port + "/zone",
            };
            for (String other : elsewhere) {
                IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> ca.send(this.client,
                        HttpRequest.newBuilder(URI.create(other)).GET(), "GET", uri, HttpResponse.BodyHandlers.discarding()),
                        other);
                assertTrue(e.getMessage().contains("another origin"), e.getMessage());
            }
            // a port that is no port is on no origin, even when the request and the credentials name it alike
            URI noPort = URI.create("http://[::1%" + loopback.getName() + "]:0/zone");
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> ca.send(this.client,
                    HttpRequest.newBuilder(noPort).GET(), "GET", noPort, HttpResponse.BodyHandlers.discarding()));
            assertTrue(e.getMessage().contains("another origin"), e.getMessage());
            assertEquals(2, hits.get());
        } finally {
            zoneServer.stop(0);
        }
    }
}
