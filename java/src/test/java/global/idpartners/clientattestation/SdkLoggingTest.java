package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Logging (docs/logging.md): the events a full flow emits at the most verbose level, that none of them
 * carries a credential, and that nothing is logged unless a logger is configured. Loopback fakes only.
 */
class SdkLoggingTest {

    private static final String CHALLENGE = "chal-do-not-log-42";
    private static final String SVID = jwt("{\"sub\":\"spiffe://example.org/workload\"}");
    private static final String ATTESTATION = jwt("{\"sub\":\"demo-client\",\"cnf\":{}}");
    private static final String ACCESS_TOKEN = jwt("{\"sub\":\"demo-client\",\"scope\":\"read\"}");

    private StubHttpServer server;
    private final HttpClient client = HttpClient.newHttpClient();
    private final RecordingLogger logger = new RecordingLogger();
    private final List<String> privateDs = Collections.synchronizedList(new ArrayList<>());
    private volatile String discoveryBody;

    @BeforeEach
    void start() throws Exception {
        this.server = new StubHttpServer();
        discover("/attest", "/challenge", "/token");
        this.server.route("/.well-known/client-attester",
                exchange -> StubHttpServer.send(exchange, 200, this.discoveryBody));
        this.server.respond("/challenge", 200, "{\"attestation_challenge\":\"" + CHALLENGE + "\"}");
        this.server.respond("/attest", 200, "{\"attestation\":\"" + ATTESTATION + "\"}");
        this.server.route("/token", this::tokenEndpoint);
        this.server.route("/resource", this::resource);
    }

    @AfterEach
    void stop() {
        this.server.close();
    }

    /** Point discovery at these paths (null leaves the member out); a path may carry a query string. */
    private void discover(String attest, String challenge, String token) {
        StringBuilder b = new StringBuilder("{\"evidence_audience\":\"https://attester.example.com\"");
        b.append(",\"attestation_endpoint\":\"").append(this.server.url(attest)).append('"');
        if (challenge != null) {
            b.append(",\"challenge_endpoint\":\"").append(this.server.url(challenge)).append('"');
        }
        if (token != null) {
            b.append(",\"token_endpoint\":\"").append(this.server.url(token)).append('"');
        }
        this.discoveryBody = b.append('}').toString();
    }

    private static String jwt(String payload) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        return b64.encodeToString("{\"alg\":\"ES256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8)) + "."
                + b64.encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + ".c2lnbmF0dXJl";
    }

    /** DPoP mode: demands its own nonce once (400 use_dpop_nonce); PoP mode: issues straight away. */
    private void tokenEndpoint(HttpExchange exchange) throws IOException {
        String dpop = exchange.getRequestHeaders().getFirst("DPoP");
        if (dpop != null) {
            try {
                Object nonce = JwtTestSupport.claims(dpop).get("nonce");
                Object jwk = JwtTestSupport.header(dpop).get("jwk");
                if (jwk instanceof Map<?, ?> m && m.get("d") != null) {
                    this.privateDs.add(String.valueOf(m.get("d")));
                }
                if (!"as-nonce".equals(nonce)) {
                    exchange.getResponseHeaders().set("DPoP-Nonce", "as-nonce");
                    StubHttpServer.send(exchange, 400, "{\"error\":\"use_dpop_nonce\"}");
                    return;
                }
            } catch (Exception e) {
                StubHttpServer.send(exchange, 400, "{\"error\":\"invalid_dpop_proof\"}");
                return;
            }
        }
        String type = dpop != null ? "DPoP" : "Bearer";
        StubHttpServer.send(exchange, 200, "{\"access_token\":\"" + ACCESS_TOKEN
                + "\",\"expires_in\":3600,\"token_type\":\"" + type + "\"}");
    }

    private void resource(HttpExchange exchange) throws IOException {
        String proof = exchange.getRequestHeaders().getFirst("DPoP");
        Object nonce;
        try {
            nonce = proof == null ? null : JwtTestSupport.claims(proof).get("nonce");
        } catch (Exception e) {
            nonce = null;
        }
        if (!"rs-nonce".equals(nonce)) {
            exchange.getResponseHeaders().set("DPoP-Nonce", "rs-nonce");
            exchange.getResponseHeaders().set("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"");
            StubHttpServer.send(exchange, 401, "{}");
            return;
        }
        StubHttpServer.send(exchange, 200, "{\"ok\":true}");
    }

    private ClientAttestation.Builder builder() {
        return ClientAttestation.builder(this.server.url("")).evidence(new SvidSource.Static(SVID))
                .logger(this.logger);
    }

    // ── happy paths ─────────────────────────────────────────────────────────────────────────────────

    @Test
    void popFlowLogsTheLifecycleAndNoCredential() {
        ClientAttestation ca = builder().build();
        assertEquals(ACCESS_TOKEN, ca.token());
        ca.token();                       // cache hit
        ca.token(true);                   // forced refresh: discovery is reused
        ca.requestHeaders("GET", this.server.url("/resource?secret=1"));

        List<String> events = this.logger.events();
        assertEquals(List.of("token.refreshing", "discovery.fetched", "evidence.obtained", "challenge.fetched",
                "attestation.minted", "token.obtained", "token.cache_hit", "token.refreshing", "discovery.cached",
                "evidence.obtained", "challenge.fetched", "attestation.minted", "token.obtained",
                "token.cache_hit"), events);
        assertTrue(this.logger.text().contains("token.refreshing reason=initial"));
        assertTrue(this.logger.text().contains("token.refreshing reason=forced"));
        assertTrue(this.logger.text().contains("evidence.obtained source=Static"));
        assertTrue(this.logger.text().contains("attestation.minted host=127.0.0.1:"));
        assertTrue(this.logger.text().contains("client_id=demo-client alg=ES256"));
        assertTrue(this.logger.text().contains(
                "token_type=Bearer expires_in=3600 pop_method=attestation_pop_jwt"));
        assertEquals(System.Logger.Level.INFO, this.logger.levelOf("token.obtained"));
        assertEquals(System.Logger.Level.DEBUG, this.logger.levelOf("token.cache_hit"));
        assertNoSecrets();
    }

    @Test
    void dpopFlowLogsBothNonceRetriesAndNoCredential() throws Exception {
        ClientAttestation ca = builder().popMethod("dpop_combined").build();
        URI uri = URI.create(this.server.url("/resource") + "?q=hidden#frag");
        HttpResponse<String> resp = ca.send(this.client, HttpRequest.newBuilder(uri).GET(), "GET", uri,
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());

        String text = this.logger.text();
        assertTrue(text.contains("dpop.nonce_retry host=127.0.0.1:"));
        assertTrue(text.contains("status=400 at=token_endpoint"));
        assertTrue(text.contains("status=401 at=resource"));
        assertTrue(text.contains("token_type=DPoP"));
        assertTrue(text.contains("pop_method=dpop_combined"));
        assertFalse(text.contains("http.failed"), "a nonce challenge that is retried is not a failure");
        assertFalse(text.contains("hidden"));
        assertNoSecrets();
    }

    private void assertNoSecrets() {
        String text = this.logger.text();
        assertFalse(text.contains("eyJ"), text);
        assertFalse(text.contains(CHALLENGE), text);
        assertFalse(text.contains("c2lnbmF0dXJl"), text);
        assertFalse(text.contains("\"d\""), text);
        assertFalse(text.contains("as-nonce"), text);
        assertFalse(text.contains("rs-nonce"), text);
        for (String d : this.privateDs) {
            assertFalse(text.contains(d), text);
        }
        assertFalse(this.logger.records.isEmpty());
    }

    // ── failures ────────────────────────────────────────────────────────────────────────────────────

    @Test
    void anHttpErrorIsLoggedWithStepHostPathAndStatus() {
        this.server.respond("/attest-broken", 503, "{\"error\":\"down\"}");
        discover("/attest-broken?k=v", null, null);
        ClientAttestation ca = builder().build();
        assertThrows(ClientAttestation.ClientAttestationException.class, ca::token);
        String text = this.logger.text();
        assertTrue(text.contains("http.failed step=mint method=POST host=127.0.0.1:"), text);
        assertTrue(text.contains("path=/attest-broken status=503 reason=status"), text);
        assertFalse(text.contains("k=v"));
        assertEquals(System.Logger.Level.WARNING, this.logger.levelOf("http.failed"));
    }

    @Test
    void aTokenEndpointErrorAndAMalformedBodyAreLogged() {
        this.server.respond("/token401", 401, "{\"error\":\"invalid_client\"}");
        discover("/attest", "/challenge", "/token401");
        assertThrows(ClientAttestation.ClientAttestationException.class, () -> builder().build().token());
        assertTrue(this.logger.text().contains("http.failed step=token method=POST"));
        assertTrue(this.logger.text().contains("status=401 reason=status"));

        this.server.respond("/token2", 200, "not json");
        this.logger.records.clear();
        discover("/attest", null, "/token2");
        assertThrows(ClientAttestation.ClientAttestationException.class, () -> builder().build().token());
        assertTrue(this.logger.text().contains("step=token method=POST host=127.0.0.1:"), this.logger.text());
        assertTrue(this.logger.text().contains("status=200 reason=malformed"), this.logger.text());
    }

    @Test
    void aMalformedJsonResponseIsLogged() {
        this.server.respond("/challenge-bad", 200, "[not an object");
        discover("/attest", "/challenge-bad", "/token");
        assertThrows(ClientAttestation.ClientAttestationException.class, () -> builder().build().token());
        assertTrue(this.logger.text().contains("http.failed step=challenge method=POST"), this.logger.text());
        assertTrue(this.logger.text().contains("reason=malformed"));
    }

    @Test
    void aSkippedChallengeIsAWarning() {
        this.server.respond("/challenge-500", 500, "{}");
        discover("/attest", "/challenge-500", "/token");
        builder().requireChallenge(false).build().token();
        assertEquals(System.Logger.Level.WARNING, this.logger.levelOf("challenge.skipped"));
        assertTrue(this.logger.events().contains("token.obtained"));
    }

    @Test
    void aRedirectAndATimeoutAreClassified() {
        this.server.redirect("/challenge-moved", "https://elsewhere.example/");
        discover("/attest", "/challenge-moved", "/token");
        assertThrows(ClientAttestation.ClientAttestationException.class, () -> builder().build().token());
        assertTrue(this.logger.text().contains("step=challenge"));
        assertTrue(this.logger.text().contains("status=302 reason=redirect"), this.logger.text());

        this.logger.records.clear();
        this.server.slow("/attest-slow", 2_000);
        discover("/attest-slow", null, null);
        assertThrows(ClientAttestation.ClientAttestationException.class,
                () -> builder().timeout(Duration.ofMillis(200)).build().token());
        assertTrue(this.logger.text().contains("step=mint method=POST"), this.logger.text());
        assertTrue(this.logger.text().contains("reason=timeout"), this.logger.text());
    }

    @Test
    void failureReasonsCoverTheTransportCases() {
        assertEquals("timeout", ClientAttestation.failureReason(
                new TransportException("x", 0, null, new TimeoutException())));
        assertEquals("timeout", ClientAttestation.failureReason(
                new TransportException("x", 0, null, new java.net.http.HttpTimeoutException("t"))));
        assertEquals("redirect", ClientAttestation.failureReason(new TransportException("x", 301, null)));
        assertEquals("too_large", ClientAttestation.failureReason(
                new TransportException("GET u response body exceeds 10 bytes", 0, null)));
        assertEquals("network", ClientAttestation.failureReason(
                new TransportException("GET u failed: refused", 0, null, new IOException())));
        assertEquals("network", ClientAttestation.failureReason(new TransportException("x", 500, null)));
    }

    // ── the default and the formatter ───────────────────────────────────────────────────────────────

    @Test
    void theDefaultIsSilent() {
        for (System.Logger.Level level : System.Logger.Level.values()) {
            assertFalse(SdkLogging.NOOP.isLoggable(level));
        }
        SdkLogging.NOOP.log(System.Logger.Level.ERROR, (ResourceBundle) null, "dropped", (Throwable) null);
        SdkLogging.NOOP.log(System.Logger.Level.ERROR, (ResourceBundle) null, "dropped {0}", "x");
        assertEquals(SdkLogging.LOGGER_NAME, SdkLogging.NOOP.getName());
        assertEquals("global.idpartners.clientattestation", SdkLogging.LOGGER_NAME);
        // a client with no logger configured runs the whole flow (and logs nowhere)
        assertEquals(ACCESS_TOKEN, ClientAttestation.builder(this.server.url(""))
                .evidence(new SvidSource.Static(SVID)).build().token());
        new SdkLogging(null).warn("http.failed", "host", "h");
        assertTrue(this.logger.records.isEmpty());
    }

    @Test
    void nothingIsFormattedBelowTheConfiguredLevel() {
        RecordingLogger infoOnly = new RecordingLogger();
        infoOnly.min = System.Logger.Level.INFO;
        SdkLogging log = new SdkLogging(infoOnly);
        log.debug("token.cache_hit", "expires_in", 10);
        log.info("token.obtained", "host", "h");
        assertEquals(List.of("token.obtained"), infoOnly.events());
    }

    @Test
    void formatDropsNullsQuotesAndRedactsJwtLookingValues() {
        assertEquals("e a=1 c=\"x y\" d=\"\" q=\"say \\\"hi\\\"\\n\"",
                SdkLogging.format("e", "a", 1, "b", null, "c", "x y", "d", "", "q", "say \"hi\"\n"));
        assertEquals("e v=\"<redacted:" + ACCESS_TOKEN.length() + " bytes>\"", SdkLogging.format("e", "v", ACCESS_TOKEN));
        assertEquals("e host=pf.example.com", SdkLogging.format("e", "host", "pf.example.com"));
        assertEquals("pf.example.com", SdkLogging.host("https://pf.example.com/x?y=1"));
        assertEquals("pf.example.com:8443", SdkLogging.host("https://pf.example.com:8443/x"));
        assertNull(SdkLogging.host("not a url"));
        assertNull(SdkLogging.host("mailto:x@example.com"));
        assertEquals("/as/token.oauth2", SdkLogging.path("https://pf.example.com/as/token.oauth2?a=b#c"));
        assertEquals("/", SdkLogging.path("https://pf.example.com"));
        assertNull(SdkLogging.path("not a url"));
    }

    /** Records every message at every level (or from {@code min} up). */
    static final class RecordingLogger implements System.Logger {
        record Entry(Level level, String message) {
        }

        final List<Entry> records = Collections.synchronizedList(new ArrayList<>());
        Level min = Level.ALL;

        @Override
        public String getName() {
            return SdkLogging.LOGGER_NAME;
        }

        @Override
        public boolean isLoggable(Level level) {
            return level.getSeverity() >= this.min.getSeverity();
        }

        @Override
        public void log(Level level, ResourceBundle bundle, String msg, Throwable thrown) {
            this.records.add(new Entry(level, msg));
        }

        @Override
        public void log(Level level, ResourceBundle bundle, String format, Object... params) {
            this.records.add(new Entry(level, params == null || params.length == 0 ? format
                    : MessageFormat.format(format, params)));
        }

        List<String> events() {
            synchronized (this.records) {
                return this.records.stream().map(e -> e.message().split(" ", 2)[0]).toList();
            }
        }

        String text() {
            synchronized (this.records) {
                return String.join("\n", this.records.stream().map(Entry::message).toList());
            }
        }

        Level levelOf(String event) {
            synchronized (this.records) {
                return this.records.stream().filter(e -> e.message().split(" ", 2)[0].equals(event))
                        .map(Entry::level).findFirst().orElse(null);
            }
        }
    }
}
