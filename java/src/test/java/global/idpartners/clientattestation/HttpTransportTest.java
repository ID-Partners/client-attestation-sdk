package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
        assertTrue(e.body().length() <= HttpTransport.ERROR_BODY_CHARS + 3);
        assertTrue(e.getMessage().length() < 600);
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
        assertEquals(512 + 3, HttpTransport.truncate("q".repeat(2000)).length());
    }
}
