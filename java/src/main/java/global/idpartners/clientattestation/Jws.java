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
 * {@link SigningKeyPair}. When {@code embedPublicJwk} is set the public key is carried in a {@code jwk}
 * header (as DPoP requires); otherwise the key's thumbprint {@code kid} is set.
 */
final class Jws {

    private Jws() {
    }

    /**
     * Signs via an external {@link JwsSigner} (vault/HSM-held key): the compact JWS is assembled here and
     * only the raw signature is produced remotely. Header carries {@code alg}, {@code typ} and the
     * signer's {@code kid} (external signers hold issuing keys, which are referenced by id, never embedded).
     */
    static String sign(String payloadJson, JwsSigner signer, String typ) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", signer.algorithm());
        header.put("typ", typ);
        header.put("kid", signer.keyId());
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String signingInput = b64.encodeToString(JsonUtil.toJson(header).getBytes(StandardCharsets.UTF_8))
                + "." + b64.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        byte[] signature = signer.sign(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + b64.encodeToString(signature);
    }

    static String sign(String payloadJson, SigningKeyPair key, String typ, boolean embedPublicJwk) {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(payloadJson);
        jws.setAlgorithmHeaderValue(key.algorithm());
        jws.setHeader("typ", typ);
        if (embedPublicJwk) {
            jws.getHeaders().setJwkHeaderValue("jwk", key.publicJsonWebKey());
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
