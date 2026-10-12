package global.idpartners.clientattestation;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

/**
 * Internal helper: signs a JSON payload into a compact JWS with an explicit {@code typ} header, keyed by a
 * {@link SigningKeyPair}. When {@code embedPublicJwk} is set the public key (without {@code kid}) is carried
 * in a {@code jwk} header (as DPoP requires); otherwise the key's thumbprint {@code kid} is set.
 */
final class Jws {

    private Jws() {
    }

    /**
     * Signs via an external {@link JwsSigner} (vault/HSM-held key): the compact JWS is assembled here and
     * only the raw signature is produced remotely. Header carries {@code alg}, {@code typ} and the
     * signer's {@code kid} (external signers hold issuing keys, which are referenced by id, never embedded).
     * The signer's algorithm must be one the SDK signs with (never {@code none}), and its signature must not
     * be empty and, for ES*, must be the fixed-width {@code r||s} (not DER, not truncated).
     */
    static String sign(String payloadJson, JwsSigner signer, String typ) {
        String alg = signer.algorithm();
        if (alg == null || !SigningKeyPair.SIGNING_ALGORITHMS.contains(alg)) {
            throw new IllegalArgumentException("External signer algorithm '" + alg
                    + "' is not allowed: use ES256/384/512, RS256/384/512 or PS256/384/512");
        }
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", alg);
        header.put("typ", typ);
        header.put("kid", signer.keyId());
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String signingInput = b64.encodeToString(JsonUtil.toJson(header).getBytes(StandardCharsets.UTF_8))
                + "." + b64.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        byte[] signature = signer.sign(signingInput.getBytes(StandardCharsets.US_ASCII));
        if (signature == null || signature.length == 0) {
            throw new IllegalStateException("External signer returned an empty signature");
        }
        int want = switch (alg) {
            case "ES256" -> 64;
            case "ES384" -> 96;
            case "ES512" -> 132;
            default -> -1;
        };
        if (want > 0 && signature.length != want) {
            throw new IllegalStateException("External signer returned a " + signature.length + "-byte " + alg
                    + " signature; want the " + want + "-byte raw r||s");
        }
        return signingInput + "." + b64.encodeToString(signature);
    }

    static String sign(String payloadJson, SigningKeyPair key, String typ, boolean embedPublicJwk) {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(payloadJson);
        jws.setAlgorithmHeaderValue(key.algorithm());
        jws.setHeader("typ", typ);
        if (embedPublicJwk) {
            // The canonical public members only, without kid (as the Go, Python and TypeScript ports emit):
            // a DPoP proof identifies its key by the embedded jwk, never by a key id.
            Map<String, Object> publicJwk = key.publicJwk();
            publicJwk.remove("kid");
            jws.getHeaders().setObjectHeaderValue("jwk", publicJwk);
        } else {
            jws.setKeyIdHeaderValue(key.keyId());
        }
        jws.setKey(key.privateKey());
        try {
            return jws.getCompactSerialization();
        } catch (JoseException e) {
            throw new IllegalStateException("JWS signing failed", e);
        }
    }
}
