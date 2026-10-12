package global.idpartners.clientattestation.tokenvalidator;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.EllipticCurves;

/** Shared test helpers: the shared vectors, throwaway signing keys, a loopback HTTP stub and a log recorder. */
final class Fixtures {

    static final String ISSUER = "https://issuer.test";
    static final String AUDIENCE = "https://api.test";

    private Fixtures() {
    }

    // ── shared vectors ──────────────────────────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    static Map<String, Object> vectors() {
        try {
            return JsonUtil.parseJson(Files.readString(Path.of("..", "validation", "tokens.json")));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> cases(Map<String, Object> v) {
        return (List<Map<String, Object>>) v.get("cases");
    }

    static String tokenNamed(Map<String, Object> v, String name) {
        for (Map<String, Object> c : cases(v)) {
            if (name.equals(c.get("name"))) {
                return (String) c.get("token");
            }
        }
        throw new IllegalArgumentException(name);
    }

    @SuppressWarnings("unchecked")
    static ValidatorConfig.Builder vectorConfig(Map<String, Object> v) {
        return ValidatorConfig.builder()
                .issuer((String) v.get("issuer"))
                .audiences((String) v.get("audience"))
                .jwks((Map<String, Object>) v.get("jwks"))
                .requiredScopes((List<String>) v.get("required_scopes"))
                .acceptedAlgorithms((List<String>) v.get("accepted_algorithms"));
    }

    /** Whether a case runs under the shared config, key set and the real clock. */
    static boolean shared(Map<String, Object> c) {
        return c.get("config") == null && c.get("now") == null && c.get("jwks") == null
                && c.get("jwks_fetch_error") == null;
    }

    /**
     * The validator a case asks for: the shared config plus its overrides (present wins), key set and clock. A
     * case with a fetch error gets a jwks_uri whose fetch fails with that message.
     */
    @SuppressWarnings("unchecked")
    static AccessTokenValidator validatorFor(Map<String, Object> v, Map<String, Object> c) {
        ValidatorConfig.Builder b = vectorConfig(v);
        Map<String, Object> o = (Map<String, Object>) c.get("config");
        if (o != null) {
            if (o.containsKey("accepted_algorithms")) {
                b.acceptedAlgorithms((List<String>) o.get("accepted_algorithms"));
            }
            if (o.containsKey("accepted_token_types")) {
                b.acceptedTokenTypes((List<String>) o.get("accepted_token_types"));
            }
            if (o.containsKey("leeway_seconds")) {
                b.leewaySeconds(((Number) o.get("leeway_seconds")).intValue());
            }
        }
        if (c.get("jwks") != null) {
            b.jwks((Map<String, Object>) c.get("jwks"));
        }
        String fetchError = (String) c.get("jwks_fetch_error");
        if (fetchError != null) {
            b.jwks((Map<String, Object>) null).jwksUri("https://keys.internal.example:8443/jwks");
        }
        AccessTokenValidator.Builder builder = AccessTokenValidator.builder(b.build()).httpGet(url -> {
            throw new IllegalStateException(fetchError);
        });
        if (c.get("now") != null) {
            long millis = ((Number) c.get("now")).longValue() * 1000L;
            builder.clock(() -> millis);
        }
        return builder.build();
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> introspectionCases() {
        try {
            return (List<Map<String, Object>>) JsonUtil.parseJson(
                    Files.readString(Path.of("..", "validation", "introspection.json"))).get("cases");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** validation/bearer.json: each case is an Authorization header and the token every port extracts. */
    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> bearerCases() {
        try {
            return (List<Map<String, Object>>) JsonUtil.parseJson(
                    Files.readString(Path.of("..", "validation", "bearer.json"))).get("cases");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ── keys and tokens ─────────────────────────────────────────────────────────────────────────────

    /** A P-256 signing key, with {@code kid} unless null. */
    static EllipticCurveJsonWebKey newKey(String kid) {
        try {
            EllipticCurveJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
            if (kid != null) {
                key.setKeyId(kid);
            }
            return key;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static Map<String, Object> publicJwk(JsonWebKey key) {
        return key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
    }

    static Map<String, Object> jwks(JsonWebKey... keys) {
        List<Object> list = new ArrayList<>();
        for (JsonWebKey k : keys) {
            list.add(publicJwk(k));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("keys", list);
        return out;
    }

    static String jwksJson(JsonWebKey... keys) {
        return JsonUtil.toJson(jwks(keys));
    }

    /** A config for {@link #ISSUER} / {@link #AUDIENCE} trusting {@code key}. */
    static ValidatorConfig.Builder config(JsonWebKey key) {
        return ValidatorConfig.builder().issuer(ISSUER).audiences(AUDIENCE).jwks(jwks(key));
    }

    static long now() {
        return System.currentTimeMillis() / 1000L;
    }

    /** Base claims (iss, aud, sub, scope, exp in 5 minutes) with {@code overrides} applied; null removes. */
    static Map<String, Object> claims(Object... overrides) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("iss", ISSUER);
        c.put("aud", AUDIENCE);
        c.put("sub", "agent-1");
        c.put("scope", "read write");
        c.put("exp", now() + 300);
        for (int i = 0; i + 1 < overrides.length; i += 2) {
            if (overrides[i + 1] == null) {
                c.remove((String) overrides[i]);
            } else {
                c.put((String) overrides[i], overrides[i + 1]);
            }
        }
        return c;
    }

    /** ES256 over {@code claims}, typ at+jwt, the key's kid. */
    static String sign(EllipticCurveJsonWebKey key, Map<String, Object> claims) {
        return signRaw(key, JsonUtil.toJson(claims), "ES256", "at+jwt", key.getKeyId());
    }

    /** Sign {@code payload} with the key's private half; {@code typ} and {@code kid} are left out when null. */
    static String signRaw(EllipticCurveJsonWebKey key, String payload, String alg, String typ, String kid) {
        return signRaw(key.getPrivateKey(), payload, alg, typ, kid);
    }

    /** Sign {@code payload} with {@code alg}; {@code typ} and {@code kid} are left out when null. */
    static String signRaw(java.security.Key key, String payload, String alg, String typ, String kid) {
        try {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setPayload(payload);
            jws.setAlgorithmHeaderValue(alg);
            if (typ != null) {
                jws.setHeader("typ", typ);
            }
            if (kid != null) {
                jws.setKeyIdHeaderValue(kid);
            }
            jws.setKey(key);
            return jws.getCompactSerialization();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** base64url(JSON) for hand-built (unsigned) tokens. */
    static String b64(String text) {
        return java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(text.getBytes(StandardCharsets.UTF_8));
    }

    // ── loopback HTTP ───────────────────────────────────────────────────────────────────────────────

    /** Loopback-only scriptable HTTP server (127.0.0.1, ephemeral port). */
    static final class Stub implements Closeable {
        private final HttpServer server;
        private final ExecutorService executor = Executors.newCachedThreadPool();
        final Map<String, AtomicInteger> hits = new java.util.concurrent.ConcurrentHashMap<>();
        final Map<String, String> bodies = new java.util.concurrent.ConcurrentHashMap<>();
        final Map<String, com.sun.net.httpserver.Headers> headers = new java.util.concurrent.ConcurrentHashMap<>();

        Stub() throws IOException {
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

        Stub route(String path, HttpHandler handler) {
            this.hits.put(path, new AtomicInteger());
            this.server.createContext(path, exchange -> {
                this.hits.get(path).incrementAndGet();
                this.bodies.put(path, new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                this.headers.put(path, exchange.getRequestHeaders());
                handler.handle(exchange);
            });
            return this;
        }

        Stub respond(String path, int status, String body) {
            return route(path, exchange -> send(exchange, status, body));
        }

        Stub redirect(String path, String location) {
            return route(path, exchange -> {
                exchange.getResponseHeaders().set("Location", location);
                exchange.sendResponseHeaders(302, -1);
                exchange.close();
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

    // ── logging ─────────────────────────────────────────────────────────────────────────────────────

    /** Records every message at every level. */
    static final class RecordingLogger implements System.Logger {
        final List<String> lines = Collections.synchronizedList(new ArrayList<>());
        final List<Level> levels = Collections.synchronizedList(new ArrayList<>());

        @Override
        public String getName() {
            return "test";
        }

        @Override
        public boolean isLoggable(Level level) {
            return true;
        }

        @Override
        public void log(Level level, ResourceBundle bundle, String msg, Throwable thrown) {
            this.lines.add(msg);
            this.levels.add(level);
        }

        @Override
        public void log(Level level, ResourceBundle bundle, String format, Object... params) {
            this.lines.add(format);
            this.levels.add(level);
        }

        List<String> named(String event) {
            List<String> out = new ArrayList<>();
            synchronized (this.lines) {
                for (String l : this.lines) {
                    if (l.equals(event) || l.startsWith(event + " ")) {
                        out.add(l);
                    }
                }
            }
            return out;
        }

        String all() {
            synchronized (this.lines) {
                return String.join("\n", this.lines);
            }
        }
    }
}
