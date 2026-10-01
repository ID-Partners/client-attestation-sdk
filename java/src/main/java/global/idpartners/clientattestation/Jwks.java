package global.idpartners.clientattestation;

import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.lang.JoseException;

/** The two JWK helpers the SDK needs: map to jose4j key, and the RFC 7638 SHA-256 thumbprint. */
final class Jwks {

    private Jwks() {
    }

    static JsonWebKey fromMap(Map<String, Object> jwk) throws JoseException {
        if (jwk == null || jwk.isEmpty()) {
            throw new IllegalArgumentException("jwk is missing or empty");
        }
        return JsonWebKey.Factory.newJwk(jwk);
    }

    static String thumbprint(Map<String, Object> jwk) throws JoseException {
        return fromMap(jwk).calculateBase64urlEncodedThumbprint("SHA-256");
    }
}
