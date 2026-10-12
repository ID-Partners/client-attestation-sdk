package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;

/**
 * {@link OpenBaoTransitSigner} failure modes and non-P-256 curves against a scriptable in-process stub of
 * the transit API: unsupported key types, malformed metadata, malformed sign responses and vault errors
 * must all fail closed as {@link IllegalStateException}.
 */
class OpenBaoTransitSignerFailureTest {

    private static final String TOKEN = "unit-test-token";
    private static final String KEY_NAME = "attestation-key";

    /** Minimal scriptable transit stub: canned responses for the keys and sign endpoints. */
    private static final class StubBao implements Closeable {
        private final HttpServer server;

        StubBao(int keysStatus, String keysBody, int signStatus, String signBody) throws IOException {
            this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            this.server.createContext("/v1/transit/keys/", canned(keysStatus, keysBody));
            this.server.createContext("/v1/transit/sign/", canned(signStatus, signBody));
            this.server.start();
        }

        String url() {
            return "http://127.0.0.1:" + this.server.getAddress().getPort();
        }

        @Override
        public void close() {
            this.server.stop(0);
        }

        private static com.sun.net.httpserver.HttpHandler canned(int status, String body) {
            return (HttpExchange exchange) -> {
                byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(status, bytes.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(bytes);
                }
            };
        }
    }

    private static String pem(PublicKey key) {
        return "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(key.getEncoded())
                + "\n-----END PUBLIC KEY-----\n";
    }

    private static String keysResponse(String type, String publicKeyPem) {
        Map<String, Object> version = publicKeyPem == null ? Map.of() : Map.of("public_key", publicKeyPem);
        return JsonUtil.toJson(Map.of("data", Map.of(
                "type", type,
                "latest_version", 1L,
                "keys", Map.of("1", version))));
    }

    private static String validP256Keys() throws Exception {
        return keysResponse("ecdsa-p256", pem(EcJwkGenerator.generateJwk(EllipticCurves.P256).getPublicKey()));
    }

    private static IllegalStateException expectConstructorFailure(String keysBody) throws Exception {
        return expectConstructorFailure(200, keysBody);
    }

    private static IllegalStateException expectConstructorFailure(int keysStatus, String keysBody) throws Exception {
        try (StubBao bao = new StubBao(keysStatus, keysBody, 200, "{}")) {
            return assertThrows(IllegalStateException.class,
                    () -> new OpenBaoTransitSigner(bao.url(), TOKEN, KEY_NAME));
        }
    }

    private static IllegalStateException expectSignFailure(int signStatus, String signBody) throws Exception {
        try (StubBao bao = new StubBao(200, validP256Keys(), signStatus, signBody)) {
            OpenBaoTransitSigner signer = new OpenBaoTransitSigner(bao.url(), TOKEN, KEY_NAME);
            return assertThrows(IllegalStateException.class,
                    () -> signer.sign("signing-input".getBytes(StandardCharsets.US_ASCII)));
        }
    }

    @Test
    void publicKeyOnAnotherCurveThanTheKeyTypeIsRefused() throws Exception {
        String keys = keysResponse("ecdsa-p256", pem(EcJwkGenerator.generateJwk(EllipticCurves.P384).getPublicKey()));
        IllegalStateException e = expectConstructorFailure(keys);
        assertTrue(e.getMessage().contains("P-384"), e.getMessage());
    }

    @Test
    void es384TransitKeyMapsToEs384() throws Exception {
        String keys = keysResponse("ecdsa-p384", pem(EcJwkGenerator.generateJwk(EllipticCurves.P384).getPublicKey()));
        try (StubBao bao = new StubBao(200, keys, 200, "{}")) {
            OpenBaoTransitSigner signer = new OpenBaoTransitSigner(bao.url(), TOKEN, KEY_NAME);
            assertEquals("ES384", signer.algorithm());
            assertEquals("P-384", signer.publicJwk().get("crv"));
            assertEquals("ES384", signer.publicJwk().get("alg"));
        }
    }

    @Test
    void es512TransitKeyMapsToEs512() throws Exception {
        String keys = keysResponse("ecdsa-p521", pem(EcJwkGenerator.generateJwk(EllipticCurves.P521).getPublicKey()));
        try (StubBao bao = new StubBao(200, keys, 200, "{}")) {
            OpenBaoTransitSigner signer = new OpenBaoTransitSigner(bao.url(), TOKEN, KEY_NAME);
            assertEquals("ES512", signer.algorithm());
            assertEquals("P-521", signer.publicJwk().get("crv"));
            assertEquals(signer.keyId(), signer.publicJwk().get("kid"));
        }
    }

    @Test
    void shortCoordinatesArePaddedToFieldWidth() throws Exception {
        // Find a P-521 key with at least one coordinate shorter than the 66-byte field width, so the
        // JWK conversion must left-pad. P(short coordinate per key) is about 7/16, so this terminates fast.
        org.jose4j.jwk.EllipticCurveJsonWebKey key = null;
        for (int i = 0; i < 1000; i++) {
            org.jose4j.jwk.EllipticCurveJsonWebKey candidate = EcJwkGenerator.generateJwk(EllipticCurves.P521);
            java.security.interfaces.ECPublicKey pub = (java.security.interfaces.ECPublicKey) candidate.getPublicKey();
            if (pub.getW().getAffineX().toByteArray().length < 66
                    || pub.getW().getAffineY().toByteArray().length < 66) {
                key = candidate;
                break;
            }
        }
        assertTrue(key != null, "no P-521 key with a short coordinate found in 1000 tries");
        try (StubBao bao = new StubBao(200, keysResponse("ecdsa-p521", pem(key.getPublicKey())), 200, "{}")) {
            OpenBaoTransitSigner signer = new OpenBaoTransitSigner(bao.url(), TOKEN, KEY_NAME);
            Map<String, Object> jwk = signer.publicJwk();
            assertEquals(66, Base64.getUrlDecoder().decode((String) jwk.get("x")).length);
            assertEquals(66, Base64.getUrlDecoder().decode((String) jwk.get("y")).length);
            Map<String, Object> expected = key.toParams(org.jose4j.jwk.JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
            assertEquals(expected.get("x"), jwk.get("x"));
            assertEquals(expected.get("y"), jwk.get("y"));
        }
    }

    @Test
    void trailingSlashesInBaoAddrAreTolerated() throws Exception {
        try (StubBao bao = new StubBao(200, validP256Keys(), 200, "{}")) {
            OpenBaoTransitSigner signer = new OpenBaoTransitSigner(bao.url() + "//", TOKEN, KEY_NAME);
            assertEquals("ES256", signer.algorithm());
        }
    }

    @Test
    void unsupportedTransitKeyTypeIsRejected() throws Exception {
        String keys = JsonUtil.toJson(Map.of("data", Map.of("type", "rsa-2048")));
        IllegalStateException e = expectConstructorFailure(keys);
        assertTrue(e.getMessage().contains("unsupported type"));
        assertTrue(e.getMessage().contains("rsa-2048"));
    }

    @Test
    void missingTransitKeyTypeIsRejected() throws Exception {
        String keys = JsonUtil.toJson(Map.of("data", Map.of("latest_version", 1L)));
        IllegalStateException e = expectConstructorFailure(keys);
        assertTrue(e.getMessage().contains("unsupported type"));
    }

    @Test
    void missingPublicKeyInMetadataIsRejected() throws Exception {
        IllegalStateException e = expectConstructorFailure(keysResponse("ecdsa-p256", null));
        assertTrue(e.getMessage().contains("no public_key"));
    }

    @Test
    void blankPublicKeyInMetadataIsRejected() throws Exception {
        IllegalStateException e = expectConstructorFailure(keysResponse("ecdsa-p256", "  "));
        assertTrue(e.getMessage().contains("no public_key"));
    }

    @Test
    void garbagePemIsRejected() throws Exception {
        String keys = keysResponse("ecdsa-p256",
                "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n");
        IllegalStateException e = expectConstructorFailure(keys);
        assertTrue(e.getMessage().contains("Unparseable transit public key"));
    }

    @Test
    void responseWithoutDataIsRejected() throws Exception {
        IllegalStateException e = expectConstructorFailure("{\"ok\":true}");
        assertTrue(e.getMessage().contains("no data"));
    }

    @Test
    void unparseableJsonResponseIsRejected() throws Exception {
        IllegalStateException e = expectConstructorFailure("not-json-at-all");
        assertTrue(e.getMessage().contains("Unparseable OpenBao response"));
    }

    @Test
    void non200MetadataResponseIsRejected() throws Exception {
        IllegalStateException e = expectConstructorFailure(503, "{\"errors\":[\"sealed\"]}");
        assertTrue(e.getMessage().contains("HTTP 503"));
    }

    @Test
    void non200SignResponseIsRejected() throws Exception {
        IllegalStateException e = expectSignFailure(500, "{\"errors\":[\"boom\"]}");
        assertTrue(e.getMessage().contains("HTTP 500"));
    }

    @Test
    void signResponseWithoutSignatureIsRejected() throws Exception {
        IllegalStateException e = expectSignFailure(200, "{\"data\":{\"key_version\":1}}");
        assertTrue(e.getMessage().contains("no signature"));
    }

    @Test
    void signResponseWithMalformedEnvelopeIsRejected() throws Exception {
        IllegalStateException e = expectSignFailure(200, "{\"data\":{\"signature\":\"no-envelope-separator\"}}");
        assertTrue(e.getMessage().contains("Unexpected transit signature format"));
    }

    @Test
    void interruptedSignFailsClosedAndRestoresTheFlag() throws Exception {
        try (StubBao bao = new StubBao(200, validP256Keys(), 200, "{}")) {
            OpenBaoTransitSigner signer = new OpenBaoTransitSigner(bao.url(), TOKEN, KEY_NAME);
            Thread.currentThread().interrupt();
            try {
                IllegalStateException e = assertThrows(IllegalStateException.class,
                        () -> signer.sign("signing-input".getBytes(StandardCharsets.US_ASCII)));
                assertTrue(e.getMessage().contains("Interrupted"));
            } finally {
                assertTrue(Thread.interrupted(), "the interrupt flag must be restored (and is cleared here)");
            }
        }
    }
}
