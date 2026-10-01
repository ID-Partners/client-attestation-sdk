package global.idpartners.clientattestation;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.jose4j.json.JsonUtil;

/**
 * {@link JwsSigner} backed by an OpenBao (or HashiCorp Vault) transit engine: the attestation is signed
 * inside the vault ({@code POST /v1/transit/sign/<key>} with {@code marshaling_algorithm=jws}, which
 * returns the fixed-width {@code r||s} signature RFC 7515 requires) and the private key never leaves it.
 *
 * <p>Supports ECDSA transit keys ({@code ecdsa-p256/384/521} → {@code ES256/384/512}). On first use the
 * signer reads the key's metadata ({@code GET /v1/transit/keys/<key>}) to pin the latest key version,
 * derive the public JWK and compute its RFC 7638 thumbprint {@code kid}; signatures then always request
 * that pinned version so a concurrent key rotation cannot make the emitted {@code kid} lie.
 *
 * <p>Dependency-free (JDK {@link HttpClient}). Instances are immutable after initialization and safe to
 * share. Vault errors surface as {@link IllegalStateException} with the HTTP status.
 */
public final class OpenBaoTransitSigner implements JwsSigner {

    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private final HttpClient http;
    private final String baseUrl;
    private final String token;
    private final String keyName;
    private final String algorithm;
    private final String hashAlgorithm;
    private final long keyVersion;
    private final String keyId;
    private final Map<String, Object> publicJwk;

    /**
     * @param baoAddr address of the vault, e.g. {@code http://openbao.railway.internal:8200}
     * @param token   a token permitted to read {@code transit/keys/<keyName>} and write {@code transit/sign/<keyName>}
     * @param keyName the transit key name, e.g. {@code attestation-es256}
     */
    public OpenBaoTransitSigner(String baoAddr, String token, String keyName) {
        this.http = HttpTransport.client(TIMEOUT);
        this.baseUrl = Objects.requireNonNull(baoAddr, "baoAddr").replaceAll("/+$", "");
        this.token = Objects.requireNonNull(token, "token");
        this.keyName = Objects.requireNonNull(keyName, "keyName");

        Map<String, Object> data = data(this.get("/v1/transit/keys/" + keyName));
        String keyType = data.get("type") instanceof String t ? t : null;
        this.algorithm = switch (keyType == null ? "" : keyType) {
            case "ecdsa-p256" -> "ES256";
            case "ecdsa-p384" -> "ES384";
            case "ecdsa-p521" -> "ES512";
            default -> throw new IllegalStateException(
                    "Transit key '" + keyName + "' has unsupported type for JWS signing: " + keyType);
        };
        this.hashAlgorithm = switch (this.algorithm) {
            case "ES256" -> "sha2-256";
            case "ES384" -> "sha2-384";
            default -> "sha2-512";
        };
        if (!(data.get("latest_version") instanceof Number latestVersion)) {
            throw new IllegalStateException("Transit key metadata carried no latest_version");
        }
        this.keyVersion = latestVersion.longValue();
        if (!(data.get("keys") instanceof Map<?, ?> versions)
                || !(versions.get(Long.toString(this.keyVersion)) instanceof Map<?, ?> latest)) {
            throw new IllegalStateException("Transit key metadata carried no keys entry for version " + this.keyVersion);
        }
        this.publicJwk = toEcJwk(latest.get("public_key") instanceof String pem ? pem : null);
        try {
            this.keyId = Jwks.thumbprint(this.publicJwk);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to compute transit key thumbprint", e);
        }
        this.publicJwk.put("kid", this.keyId);
        this.publicJwk.put("alg", this.algorithm);
    }

    @Override
    public String algorithm() {
        return this.algorithm;
    }

    @Override
    public String keyId() {
        return this.keyId;
    }

    @Override
    public Map<String, Object> publicJwk() {
        return new LinkedHashMap<>(this.publicJwk);
    }

    @Override
    public byte[] sign(byte[] signingInput) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("input", Base64.getEncoder().encodeToString(signingInput));
        body.put("marshaling_algorithm", "jws");
        body.put("hash_algorithm", this.hashAlgorithm);
        body.put("key_version", this.keyVersion);
        Map<String, Object> data = data(this.post("/v1/transit/sign/" + this.keyName, JsonUtil.toJson(body)));
        String signature = data.get("signature") instanceof String sig ? sig : null;
        if (signature == null) {
            throw new IllegalStateException("Transit sign response carried no signature");
        }
        // Envelope is "vault:v<keyVersion>:<base64url(r||s)>".
        int sep = signature.lastIndexOf(':');
        if (sep < 0) {
            throw new IllegalStateException("Unexpected transit signature format");
        }
        return Base64.getUrlDecoder().decode(signature.substring(sep + 1));
    }

    private String get(String path) {
        return this.send(path, HttpRequest.newBuilder(URI.create(this.baseUrl + path))
                .header("X-Vault-Token", this.token)
                .GET());
    }

    private String post(String path, String json) {
        return this.send(path, HttpRequest.newBuilder(URI.create(this.baseUrl + path))
                .header("X-Vault-Token", this.token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json)));
    }

    private String send(String path, HttpRequest.Builder request) {
        HttpTransport.Response response;
        try {
            response = HttpTransport.send(this.http, request, TIMEOUT);
        } catch (TransportException e) {
            if (e.getCause() instanceof InterruptedException) {
                throw new IllegalStateException("Interrupted talking to OpenBao", e);   // flag already restored
            }
            if (e.status() != 0) {   // a refused redirect
                throw new IllegalStateException("OpenBao returned HTTP " + e.status() + " (redirects are not followed)", e);
            }
            throw new IllegalStateException("OpenBao unreachable at " + this.baseUrl + ": " + e.getMessage(), e);
        }
        if (response.status() != 200) {
            throw new IllegalStateException("OpenBao returned HTTP " + response.status() + " for " + path);
        }
        return response.body();
    }

    private static Map<String, Object> data(String responseJson) {
        Map<String, Object> parsed;
        try {
            parsed = HttpTransport.parseObject(responseJson, 200);
        } catch (TransportException e) {
            throw new IllegalStateException("Unparseable OpenBao response", e);
        }
        if (!(parsed.get("data") instanceof Map<?, ?> raw)) {
            throw new IllegalStateException("OpenBao response carried no data");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) raw;
        return data;
    }

    /** Converts a transit {@code public_key} PEM (SubjectPublicKeyInfo) into an EC public JWK map. */
    private static Map<String, Object> toEcJwk(String pem) {
        if (pem == null || pem.isBlank()) {
            throw new IllegalStateException("Transit key metadata carried no public_key");
        }
        byte[] der = Base64.getMimeDecoder().decode(
                pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", ""));
        ECPublicKey key;
        try {
            key = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalStateException("Unparseable transit public key", e);
        }
        int fieldBytes = (key.getParams().getCurve().getField().getFieldSize() + 7) / 8;
        String crv = switch (fieldBytes) {
            case 32 -> "P-256";
            case 48 -> "P-384";
            case 66 -> "P-521";
            default -> throw new IllegalStateException("Unsupported EC field size: " + fieldBytes);
        };
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "EC");
        jwk.put("crv", crv);
        jwk.put("x", fixedWidthB64Url(key.getW().getAffineX().toByteArray(), fieldBytes));
        jwk.put("y", fixedWidthB64Url(key.getW().getAffineY().toByteArray(), fieldBytes));
        return jwk;
    }

    private static String fixedWidthB64Url(byte[] unsigned, int width) {
        byte[] fixed = new byte[width];
        int src = unsigned.length > width ? unsigned.length - width : 0;
        int dst = unsigned.length < width ? width - unsigned.length : 0;
        System.arraycopy(unsigned, src, fixed, dst, unsigned.length - src);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(fixed);
    }
}
