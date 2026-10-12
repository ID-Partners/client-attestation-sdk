package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import global.idpartners.clientattestation.internal.HttpTransport;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The shared transport helper: timeouts, no redirects, body cap, non-2xx and JSON handling. */
class HttpTransportTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private StubHttpServer server;
    private HttpClient client;

    @BeforeEach
    void start() throws Exception {
        this.server = new StubHttpServer();
        this.client = HttpTransport.client(TIMEOUT);
    }

    @AfterEach
    void stop() {
        this.server.close();
    }

    private HttpRequest.Builder get(String path) {
        return HttpRequest.newBuilder(URI.create(this.server.url(path))).GET();
    }

    @Test
    void clientNeverFollowsRedirects() {
        assertEquals(HttpClient.Redirect.NEVER, this.client.followRedirects());
        assertTrue(this.client.connectTimeout().isPresent());
    }

    @Test
    void okResponseIsReturnedWithStatusHeadersAndBody() {
        this.server.respond("/ok", 200, "{\"a\":1}");
        HttpTransport.Response r = HttpTransport.send(this.client, get("/ok"), TIMEOUT);
        assertEquals(200, r.status());
        assertTrue(r.ok());
        assertEquals("application/json", r.headers().firstValue("content-type").orElseThrow());
        assertEquals(Map.of("a", 1L), HttpTransport.jsonOk(r));
    }

    @Test
    void redirectIsRefusedAndTheTargetIsNotContacted() {
        this.server.respond("/target", 200, "{\"stolen\":true}");
        this.server.redirect("/hop", this.server.url("/target"));
        TransportException e = assertThrows(TransportException.class, () -> HttpTransport.send(this.client,
                get("/hop").header("Authorization", "Bearer secret"), TIMEOUT));
        assertEquals(302, e.status());
        assertTrue(e.getMessage().contains("redirect"));
        assertEquals(1, this.server.hits("/hop"));
        assertEquals(0, this.server.hits("/target"));
    }

    @Test
    void oversizeBodyWithContentLengthIsRefused() {
        this.server.respond("/big", 200, "x".repeat(2048));
        TransportException e = assertThrows(TransportException.class,
                () -> HttpTransport.send(this.client, get("/big"), TIMEOUT, 1024));
        assertTrue(e.getMessage().contains("exceeds 1024 bytes"), e.getMessage());
    }

    @Test
    void refusesRedirectFollowingClientBeforeSendingCredentials() {
        for (HttpClient.Redirect policy : new HttpClient.Redirect[]{HttpClient.Redirect.NORMAL, HttpClient.Redirect.ALWAYS}) {
            HttpClient following = HttpClient.newBuilder().followRedirects(policy).build();
            assertThrows(IllegalArgumentException.class, () -> HttpTransport.send(following,
                    get("/hop").header("Authorization", "Bearer secret"), TIMEOUT));
        }
        assertEquals(0, this.server.hits("/hop"));
    }

    @Test
    void oversizeChunkedBodyIsRefusedWhileStreaming() {
        // No Content-Length: the cap must trip while reading, not after buffering the whole stream.
        this.server.route("/stream", exchange -> {
            exchange.sendResponseHeaders(200, 0);
            byte[] chunk = new byte[64 * 1024];
            try (OutputStream out = exchange.getResponseBody()) {
                for (int i = 0; i < 64; i++) {      // 4 MiB offered
                    out.write(chunk);
                    out.flush();
                }
            } catch (java.io.IOException ignored) {
                // the client cancelled — expected
            }
        });
        TransportException e = assertThrows(TransportException.class,
                () -> HttpTransport.send(this.client, get("/stream"), TIMEOUT));
        assertTrue(e.getMessage().contains("exceeds " + HttpTransport.DEFAULT_MAX_BYTES), e.getMessage());
    }

    @Test
    void bodyExactlyAtTheCapIsAccepted() {
        this.server.respond("/edge", 200, "y".repeat(1024));
        assertEquals(1024, HttpTransport.send(this.client, get("/edge"), TIMEOUT, 1024).body().length());
    }

    @Test
    void non2xxIsReturnedNotThrown() {
        this.server.respond("/denied", 401, "{\"error\":\"invalid_client\"}");
        HttpTransport.Response r = HttpTransport.send(this.client, get("/denied"), TIMEOUT);
        assertEquals(401, r.status());
        assertFalse(r.ok());
        assertEquals("{\"error\":\"invalid_client\"}", r.body());
    }

    @Test
    void jsonOkThrowsForNon2xxWithStatusAndAtMost512CharsOfBody() {
        this.server.respond("/boom", 503, "z".repeat(5000));
        HttpTransport.Response r = HttpTransport.send(this.client, get("/boom"), TIMEOUT);
        TransportException e = assertThrows(TransportException.class, () -> HttpTransport.jsonOk(r));
        assertEquals(503, e.status());
        assertTrue(e.getMessage().startsWith("HTTP 503: "));
        assertEquals("z".repeat(512), e.body());
        assertEquals("HTTP 503: " + "z".repeat(512), e.getMessage());
    }

    @Test
    void malformedJsonIsATypedError() {
        this.server.respond("/garbage", 200, "<html>not json</html>");
        HttpTransport.Response r = HttpTransport.send(this.client, get("/garbage"), TIMEOUT);
        TransportException e = assertThrows(TransportException.class, () -> HttpTransport.jsonOk(r));
        assertEquals(200, e.status());
        assertTrue(e.getMessage().contains("not a JSON object"));
    }

    @Test
    void nonObjectJsonIsATypedError() {
        assertThrows(TransportException.class, () -> HttpTransport.parseObject("[1,2,3]", 200));
        assertThrows(TransportException.class, () -> HttpTransport.parseObject("\"str\"", 200));
        assertThrows(TransportException.class, () -> HttpTransport.parseObject("", 200));
    }

    @Test
    void slowResponseTimesOut() {
        this.server.slow("/slow", 3000);
        long start = System.nanoTime();
        TransportException e = assertThrows(TransportException.class,
                () -> HttpTransport.send(this.client, get("/slow"), Duration.ofMillis(200)));
        assertTrue(e.getMessage().contains("timed out"), e.getMessage());
        assertTrue(Duration.ofNanos(System.nanoTime() - start).toMillis() < 2500);
        assertEquals(0, e.status());
    }

    @Test
    void slowBodyAfterHeadersTimesOut() {
        // Headers arrive promptly, then the body stalls: the deadline must cover the body too.
        this.server.route("/drip", exchange -> {
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write("{".getBytes(StandardCharsets.UTF_8));
                out.flush();
                Thread.sleep(3000);
            } catch (Exception ignored) {
                // the client gave up — expected
            }
        });
        TransportException e = assertThrows(TransportException.class,
                () -> HttpTransport.send(this.client, get("/drip"), Duration.ofMillis(300)));
        assertTrue(e.getMessage().contains("timed out"), e.getMessage());
    }

    @Test
    void connectionRefusedIsATypedError() throws Exception {
        int port;
        try (ServerSocket s = new ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
            port = s.getLocalPort();
        }
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/")).GET();
        TransportException e = assertThrows(TransportException.class,
                () -> HttpTransport.send(this.client, req, TIMEOUT));
        assertEquals(0, e.status());
        assertTrue(e.getMessage().contains("failed"), e.getMessage());
    }

    @Test
    void interruptIsATypedErrorAndRestoresTheFlag() {
        this.server.slow("/slow-int", 2000);
        Thread.currentThread().interrupt();
        try {
            TransportException e = assertThrows(TransportException.class,
                    () -> HttpTransport.send(this.client, get("/slow-int"), TIMEOUT));
            assertInstanceOf(InterruptedException.class, e.getCause());
        } finally {
            assertTrue(Thread.interrupted(), "interrupt flag must be restored");
        }
    }

    @Test
    void truncateCapsAt512Chars() {
        assertEquals("", HttpTransport.truncate(null));
        assertEquals("short", HttpTransport.truncate("short"));
        assertEquals("q".repeat(512), HttpTransport.truncate("q".repeat(2000)));
        assertEquals("r".repeat(512), HttpTransport.truncate("r".repeat(512)));
    }

    @Test
    void userinfoUrlIsRefusedWithoutNamingItOrContactingTheHost() {
        this.server.respond("/x", 200, "{}");
        String withUser = this.server.url("/x").replace("://", "://alice:s3cret@") + "?q=1";
        for (String target : new String[] {withUser, "https://alice:s3cret@example.invalid/x",
                "https://alice@example.invalid/x"}) {
            TransportException e = assertThrows(TransportException.class, () -> HttpTransport.send(this.client,
                    HttpRequest.newBuilder(URI.create(target)).GET(), TIMEOUT));
            assertTrue(e.getMessage().contains("userinfo"), e.getMessage());
            assertFalse(e.getMessage().contains("s3cret") || e.getMessage().contains("alice"), e.getMessage());
        }
        assertEquals(0, this.server.hits("/x"));
    }

    @Test
    void errorsOmitTheQuery() throws Exception {
        int port;
        try (ServerSocket s = new ServerSocket(0)) {
            port = s.getLocalPort();
        }
        String target = "http://127.0.0.1:" + port + "/token?client_secret=s3cret#f";
        TransportException e = assertThrows(TransportException.class, () -> HttpTransport.send(this.client,
                HttpRequest.newBuilder(URI.create(target)).GET(), TIMEOUT));
        assertTrue(e.getMessage().startsWith("GET http://127.0.0.1:" + port + "/token "), e.getMessage());
        assertFalse(e.getMessage().contains("s3cret"), e.getMessage());
        assertEquals("https://as.example.com:8443/a%2Fb",
                HttpTransport.display(URI.create("https://u:p@as.example.com:8443/a%2Fb?x=1#f")));
    }

    @Test
    void neverProxiedHosts() {
        for (String host : new String[] {"127.0.0.1", "127.8.0.1", "::1", "[::1]", "localhost", "LocalHost.",
                "vault.localhost", "::ffff:127.0.0.1", "0.0.0.0", "169.254.169.254", "fe80::1", "fe80::1%en0",
                "fd00:ec2::254", "metadata.google.internal", "metadata"}) {
            assertTrue(HttpTransport.neverProxied(host), host);
        }
        for (String host : new String[] {"as.example.com", "10.0.0.1", "8.8.8.8", "2001:db8::1", "", "999.1.1.1"}) {
            assertFalse(HttpTransport.neverProxied(host), host);
        }
        assertFalse(HttpTransport.neverProxied(null));
    }

    @Test
    void proxyOnlyForHttpsToRemoteHosts() {
        java.net.ProxySelector saved = java.net.ProxySelector.getDefault();
        java.net.Proxy proxy = new java.net.Proxy(java.net.Proxy.Type.HTTP,
                java.net.InetSocketAddress.createUnresolved("proxy.example", 3128));
        int[] failures = {0};
        java.net.ProxySelector.setDefault(new java.net.ProxySelector() {
            @Override
            public java.util.List<java.net.Proxy> select(URI uri) {
                return java.util.List.of(proxy);
            }

            @Override
            public void connectFailed(URI uri, java.net.SocketAddress sa, java.io.IOException e) {
                failures[0]++;
            }
        });
        try {
            java.net.ProxySelector sdk = this.client.proxy().orElseThrow();
            assertEquals(java.util.List.of(proxy), sdk.select(URI.create("https://as.example.com/token")));
            for (String direct : new String[] {"http://vault.example.com/v1/transit/keys/k",
                    "http://metadata.google.internal/x", "https://169.254.169.254/x", "https://127.0.0.1:8443/x",
                    "https://[fe80::1]/x", "https://localhost/x"}) {
                assertEquals(java.util.List.of(java.net.Proxy.NO_PROXY), sdk.select(URI.create(direct)), direct);
            }
            sdk.connectFailed(URI.create("https://as.example.com/"), null, new java.io.IOException("x"));
            assertEquals(1, failures[0]);
            java.net.ProxySelector.setDefault(null);
            assertEquals(java.util.List.of(java.net.Proxy.NO_PROXY), sdk.select(URI.create("https://as.example.com/")));
            sdk.connectFailed(URI.create("https://as.example.com/"), null, new java.io.IOException("x"));
        } finally {
            java.net.ProxySelector.setDefault(saved);
        }
    }
}
