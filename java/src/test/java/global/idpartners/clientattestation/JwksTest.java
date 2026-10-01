package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import org.junit.jupiter.api.Test;

class JwksTest {

    /** RFC 7638 section 3.1: the worked example key and its SHA-256 thumbprint. */
    @Test
    void thumbprintMatchesRfc7638Example() throws Exception {
        Map<String, Object> jwk = Map.of(
                "kty", "RSA",
                "n", "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECP"
                        + "ebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q"
                        + "vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQF"
                        + "h6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e", "AQAB",
                "alg", "RS256",
                "kid", "2011-04-29");
        assertEquals("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", Jwks.thumbprint(jwk));
    }

    @Test
    void emptyJwkIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> Jwks.fromMap(Map.of()));
    }
}
