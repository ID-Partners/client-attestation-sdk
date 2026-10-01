package global.idpartners.clientattestation;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;

/** Test helper: decodes compact-JWS parts without verifying, for claim/header assertions. */
final class JwtTestSupport {

    private JwtTestSupport() {
    }

    static Map<String, Object> header(String jwt) throws JoseException {
        return part(jwt, 0);
    }

    static Map<String, Object> claims(String jwt) throws JoseException {
        return part(jwt, 1);
    }

    private static Map<String, Object> part(String jwt, int index) throws JoseException {
        String[] parts = jwt.split("\\.");
        return JsonUtil.parseJson(new String(Base64.getUrlDecoder().decode(parts[index]), StandardCharsets.UTF_8));
    }
}
