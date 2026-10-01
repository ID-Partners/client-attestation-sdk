package global.idpartners.clientattestation;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Loopback-only scriptable HTTP server for transport tests (127.0.0.1, ephemeral port, no external network).
 * Each route counts its hits so a test can assert an endpoint was NOT contacted (e.g. a redirect target).
 */
final class StubHttpServer implements Closeable {

    private final HttpServer server;
    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final Map<String, AtomicInteger> hits = new ConcurrentHashMap<>();
    final Map<String, String> lastBodies = new ConcurrentHashMap<>();
    final Map<String, com.sun.net.httpserver.Headers> lastHeaders = new ConcurrentHashMap<>();

    StubHttpServer() throws IOException {
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        this.server.setExecutor(this.executor);
        this.server.start();
    }

    String url(String path) {
        return "http://127.0.0.1:" + this.server.getAddress().getPort() + path;
    }

    int hits(String path) {
        AtomicInteger n = this.hits.get(path);
        return n == null ? 0 : n.get();
    }

    /** Register {@code handler} at exactly {@code path}, recording hits, request body and headers. */
    StubHttpServer route(String path, HttpHandler handler) {
        this.hits.put(path, new AtomicInteger());
        this.server.createContext(path, exchange -> {
            this.hits.get(path).incrementAndGet();
            this.lastBodies.put(path, new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            this.lastHeaders.put(path, exchange.getRequestHeaders());
            handler.handle(exchange);
        });
        return this;
    }

    /** A canned response. */
    StubHttpServer respond(String path, int status, String body) {
        return route(path, exchange -> send(exchange, status, body));
    }

    /** A 302 to {@code location}. */
    StubHttpServer redirect(String path, String location) {
        return route(path, exchange -> {
            exchange.getResponseHeaders().set("Location", location);
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
    }

    /** Waits {@code millis} before answering 200 {@code {}}. */
    StubHttpServer slow(String path, long millis) {
        return route(path, exchange -> {
            try {
                Thread.sleep(millis);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            try {
                send(exchange, 200, "{}");
            } catch (IOException ignored) {
                // the client gave up — expected
            }
        });
    }

    static void send(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    @Override
    public void close() {
        this.server.stop(0);
        this.executor.shutdownNow();
    }
}
