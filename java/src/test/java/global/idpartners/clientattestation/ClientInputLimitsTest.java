package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * How the token endpoint's {@code expires_in} decides caching (the same rule in every port), and the
 * expiry skew the builder accepts. A loopback attester on static metadata; no discovery, no challenge.
 */
class ClientInputLimitsTest {

    private HttpServer server;
    private String baseUrl;
    private final AtomicInteger tokenCalls = new AtomicInteger();
    /** Spliced into the token response as raw JSON; null leaves {@code expires_in} out. */
    private volatile String expiresIn;

    @BeforeEach
    void start() throws IOException {
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        this.server.createContext("/mint", exchange -> {
            exchange.getRequestBody().readAllBytes();
            String sub = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"sub\":\"c-1\"}".getBytes(StandardCharsets.UTF_8));
            send(exchange, "{\"attestation\":\"h." + sub + ".s\"}");
        });
        this.server.createContext("/token", exchange -> {
            exchange.getRequestBody().readAllBytes();
            int n = this.tokenCalls.incrementAndGet();
            String tail = this.expiresIn == null ? "" : ",\"expires_in\":" + this.expiresIn;
            send(exchange, "{\"access_token\":\"AT-" + n + "\",\"token_type\":\"Bearer\"" + tail + "}");
        });
        this.server.start();
        this.baseUrl = "http://127.0.0.1:" + this.server.getAddress().getPort();
    }

    @AfterEach
    void stop() {
        this.server.stop(0);
    }

    private static void send(com.sun.net.httpserver.HttpExchange exchange, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private ClientAttestation client() {
        return ClientAttestation.builder()
                .metadata(AttesterMetadata.of("aud", this.baseUrl + "/mint", this.baseUrl + "/token"))
                .evidence(new SvidSource.Static("svid"))
                .build();
    }

    @ParameterizedTest(name = "expires_in {0} cached={1}")
    @CsvSource(delimiter = '|', nullValues = "MISSING", value = {
        "3600|true",
        "3600.5|true",
        "'\"3600\"'|true",     // a numeric string, as some servers send
        "MISSING|false",       // no expiry: not cached
        "null|false",
        "0|false",
        "-60|false",
        "1e400|false",         // not finite
        "'\"soon\"'|false",
        "'\"1e3\"'|false",
        "true|false",
        "[3600]|false",
    })
    void expiresInIsParsedTheSameWayInEveryPort(String value, boolean cached) {
        this.expiresIn = value;
        ClientAttestation ca = client();
        String first = ca.token();
        String second = ca.token();
        assertEquals(cached, first.equals(second) && this.tokenCalls.get() == 1,
                "tokens " + first + ", " + second + " after " + this.tokenCalls.get() + " token calls");
    }

    @Test
    void tokenLifetimeRule() {
        assertEquals(3600L, ClientAttestation.tokenLifetime(3600L));
        assertEquals(3600L, ClientAttestation.tokenLifetime(3600.9));
        assertEquals(3600L, ClientAttestation.tokenLifetime("3600"));
        assertEquals(ClientAttestation.MAX_TOKEN_LIFETIME_SECONDS, ClientAttestation.tokenLifetime(1e15));
        assertEquals(ClientAttestation.MAX_TOKEN_LIFETIME_SECONDS, ClientAttestation.tokenLifetime(Long.MAX_VALUE));
        assertEquals(0L, ClientAttestation.tokenLifetime(Double.POSITIVE_INFINITY));
        assertEquals(0L, ClientAttestation.tokenLifetime(Double.NaN));
        assertEquals(0L, ClientAttestation.tokenLifetime(BigInteger.TEN.pow(400)));
        assertEquals(0L, ClientAttestation.tokenLifetime(" 3600"));
        assertEquals(0L, ClientAttestation.tokenLifetime(null));
    }

    @Test
    void aTokenIsCachedForAtMost24Hours() {
        this.expiresIn = "1e15";
        ClientAttestation ca = client();
        AtomicLong nanos = new AtomicLong();
        ca.nanoClock = nanos::get;
        ca.token();
        nanos.set(TimeUnit.HOURS.toNanos(23));
        ca.token();
        assertEquals(1, this.tokenCalls.get());
        nanos.set(TimeUnit.HOURS.toNanos(24) + TimeUnit.SECONDS.toNanos(1));
        ca.token();
        assertEquals(2, this.tokenCalls.get());
    }

    /**
     * The cache runs on {@code System.nanoTime()}, which a wall-clock step (NTP, an operator) does not move:
     * once that much monotonic time has passed the token is refreshed, whatever the wall clock says.
     */
    @Test
    void theTokenCacheFollowsTheMonotonicClock() {
        this.expiresIn = "300";                                        // cached for 270 seconds
        ClientAttestation ca = client();
        AtomicLong nanos = new AtomicLong(Long.MAX_VALUE - TimeUnit.SECONDS.toNanos(100));   // wraps around
        ca.nanoClock = nanos::get;
        ca.token();
        nanos.addAndGet(TimeUnit.SECONDS.toNanos(269));
        ca.token();
        assertEquals(1, this.tokenCalls.get());
        nanos.addAndGet(TimeUnit.SECONDS.toNanos(2));
        ca.token();
        assertEquals(2, this.tokenCalls.get());
    }

    @Test
    void forceRefreshWithAnInvalidExpiresInDoesNotKeepTheOldExpiry() {
        this.expiresIn = "3600";
        ClientAttestation ca = client();
        ca.token();
        this.expiresIn = "\"soon\"";
        String refreshed = ca.token(true);
        assertNotEquals(refreshed, ca.token());
        assertEquals(3, this.tokenCalls.get());
    }

    @Test
    void negativeExpirySkewIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> ClientAttestation.builder("https://attester.example")
                .expirySkewSeconds(-1));
        ClientAttestation.builder("https://attester.example").expirySkewSeconds(0).build();
    }
}
