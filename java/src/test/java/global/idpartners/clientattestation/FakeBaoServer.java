package global.idpartners.clientattestation;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.Base64;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jws.EcdsaUsingShaAlgorithm;
import org.jose4j.keys.EllipticCurves;

/**
 * In-process fake of the OpenBao transit API surface {@link OpenBaoTransitSigner} uses:
 * {@code GET /v1/transit/keys/<name>} and {@code POST /v1/transit/sign/<name>} with
 * {@code marshaling_algorithm=jws}. Holds a real local P-256 key so produced signatures
 * genuinely verify.
 */
final class FakeBaoServer implements Closeable {

    static final String KEY_NAME = "attestation-es256";

    private final HttpServer server;
    private final String token;
    final EllipticCurveJsonWebKey key;

    FakeBaoServer(String token) throws Exception {
        this.token = token;
        this.key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        this.server.createContext("/v1/transit/keys/" + KEY_NAME, this::handleKeys);
        this.server.createContext("/v1/transit/sign/" + KEY_NAME, this::handleSign);
        this.server.start();
    }

    String url() {
        return "http://127.0.0.1:" + this.server.getAddress().getPort();
    }

    @Override
    public void close() {
        this.server.stop(0);
    }

    private void handleKeys(HttpExchange exchange) throws IOException {
        if (this.rejectBadToken(exchange)) {
            return;
        }
        String pem = "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(this.key.getPublicKey().getEncoded())
                + "\n-----END PUBLIC KEY-----\n";
        String body = JsonUtil.toJson(Map.of("data", Map.of(
                "type", "ecdsa-p256",
                "latest_version", 1L,
                "keys", Map.of("1", Map.of("public_key", pem)))));
        respond(exchange, 200, body);
    }

    private void handleSign(HttpExchange exchange) throws IOException {
        if (this.rejectBadToken(exchange)) {
            return;
        }
        try {
            Map<String, Object> request = JsonUtil.parseJson(
                    new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            if (!"jws".equals(request.get("marshaling_algorithm"))) {
                respond(exchange, 400, "{\"errors\":[\"expected marshaling_algorithm=jws\"]}");
                return;
            }
            byte[] input = Base64.getDecoder().decode((String) request.get("input"));
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(this.key.getPrivateKey());
            signature.update(input);
            byte[] concat = EcdsaUsingShaAlgorithm.convertDerToConcatenated(signature.sign(), 64);
            String envelope = "vault:v1:" + Base64.getUrlEncoder().withoutPadding().encodeToString(concat);
            respond(exchange, 200, JsonUtil.toJson(Map.of("data", Map.of("signature", envelope, "key_version", 1L))));
        } catch (Exception e) {
            respond(exchange, 500, "{\"errors\":[\"" + e.getMessage() + "\"]}");
        }
    }

    private boolean rejectBadToken(HttpExchange exchange) throws IOException {
        if (this.token.equals(exchange.getRequestHeaders().getFirst("X-Vault-Token"))) {
            return false;
        }
        respond(exchange, 403, "{\"errors\":[\"permission denied\"]}");
        return true;
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
