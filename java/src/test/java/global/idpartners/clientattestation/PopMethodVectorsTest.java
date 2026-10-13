package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The one-call client's PoP method setting against the shared vectors (vectors/pop-method.json). Every port
 * must agree. An accepted value is checked by the header sent at the token endpoint; a refused one fails
 * {@code build()} before any request or evidence fetch. {@code Builder.popMethod} takes a String, so the
 * non-string cases can't be passed in Java.
 */
class PopMethodVectorsTest {

    /** Each request: path, DPoP header, PoP header. */
    private final List<String[]> seen = new CopyOnWriteArrayList<>();
    private HttpServer server;
    private String baseUrl;

    @BeforeEach
    void start() throws IOException {
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        this.server.createContext("/", exchange -> {
            exchange.getRequestBody().readAllBytes();
            String path = exchange.getRequestURI().getPath();
            this.seen.add(new String[] {path, exchange.getRequestHeaders().getFirst("DPoP"),
                exchange.getRequestHeaders().getFirst("OAuth-Client-Attestation-PoP")});
            if (path.equals("/mint")) {
                String sub = Base64.getUrlEncoder().withoutPadding()
                        .encodeToString("{\"sub\":\"c-1\"}".getBytes(StandardCharsets.UTF_8));
                send(exchange, "{\"attestation\":\"h." + sub + ".s\"}");
            } else {
                send(exchange, "{\"access_token\":\"AT\",\"token_type\":\"Bearer\",\"expires_in\":3600}");
            }
        });
        this.server.start();
        this.baseUrl = "http://127.0.0.1:" + this.server.getAddress().getPort();
    }

    @AfterEach
    void stop() {
        this.server.stop(0);
    }

    private static void send(HttpExchange exchange, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private ClientAttestation.Builder builder(SvidSource evidence) {
        return ClientAttestation.builder()
                .metadata(AttesterMetadata.of("aud", this.baseUrl + "/mint", this.baseUrl + "/token"))
                .evidence(evidence);
    }

    private List<String[]> tokenRequests() {
        return this.seen.stream().filter(r -> r[0].equals("/token")).toList();
    }

    @SuppressWarnings("unchecked")
    static Stream<Arguments> cases() throws Exception {
        Map<String, Object> file = JsonUtil.parseJson(Files.readString(Path.of("..", "vectors", "pop-method.json")));
        return ((List<Map<String, Object>>) file.get("cases")).stream().map(c -> Arguments.of(c.get("name"), c));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    void vector(String name, Map<String, Object> c) throws Exception {
        Object value = c.get("pop_method");
        assumeTrue(value == null || value instanceof String, "Builder.popMethod takes only a String");
        AtomicInteger fetches = new AtomicInteger();
        ClientAttestation.Builder b = builder(audience -> {
            fetches.incrementAndGet();
            return "svid";
        }).popMethod((String) value);
        if (c.get("expect").equals("refused")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, b::build);
            assertEquals("popMethod must be \"attestation_pop_jwt\" or \"dpop_combined\", got \"" + value + "\"",
                    e.getMessage());
            assertEquals(List.of(), this.seen);
            assertEquals(0, fetches.get());
            return;
        }
        b.build().token();
        List<String[]> token = tokenRequests();
        assertEquals(1, token.size());
        if (c.get("expect").equals("dpop_combined")) {
            assertNotNull(token.get(0)[1]);
            assertNull(token.get(0)[2]);
        } else {
            assertNotNull(token.get(0)[2]);
            assertNull(token.get(0)[1]);
        }
    }

    @Test
    void leavingItOutIsTheDefault() throws Exception {
        builder(new SvidSource.Static("svid")).build().token();
        List<String[]> token = tokenRequests();
        assertEquals(1, token.size());
        assertTrue(token.get(0)[2] != null && token.get(0)[1] == null);
    }
}
