package global.idpartners.clientattestation.tokenvalidator;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

/** Config-time checks: the https rule for the validator's own endpoints, and the leeway range. */
class ValidatorConfigTest {

    private static final List<String> INSECURE = List.of(
            "http://issuer.example.com/jwks",
            "http://127.0.0.2/jwks",
            "http://localhost.attacker.example/jwks",
            "http://localhost@attacker.example/jwks",
            "issuer.example.com/jwks");

    private static final List<String> SECURE = List.of(
            "https://issuer.example.com/jwks",
            "HTTPS://issuer.example.com/jwks",
            "http://localhost:8080/jwks",
            "http://LOCALHOST/jwks",
            "http://127.0.0.1:9000/jwks",
            "http://[::1]:8080/jwks");

    private static ValidatorConfig.Builder base() {
        return ValidatorConfig.builder().issuer(Fixtures.ISSUER).audiences(Fixtures.AUDIENCE);
    }

    /**
     * A plain-http jwks_uri lets anyone on the path serve their own keys and forge any token; a plain-http
     * introspection endpoint hands them the resource server's client secret.
     */
    @Test
    void refusesInsecureEndpoints() {
        for (String url : INSECURE) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> base().jwksUri(url).build(), url);
            assertTrue(e.getMessage().contains("jwks_uri"), e.getMessage());
            e = assertThrows(IllegalArgumentException.class,
                    () -> base().introspection(new IntrospectionConfig(url, "rs", "s3cret")).build(), url);
            assertTrue(e.getMessage().contains("introspection endpoint"), e.getMessage());
            assertFalse(e.getMessage().contains("s3cret"), e.getMessage());
        }
    }

    @Test
    void allowInsecureOptsOut() {
        for (String url : INSECURE) {
            ValidatorConfig c = base().jwksUri(url).introspection(new IntrospectionConfig(url, "rs", "s"))
                    .allowInsecure(true).build();
            assertTrue(c.allowInsecure());
        }
    }

    @Test
    void acceptsHttpsAndLoopback() {
        for (String url : SECURE) {
            ValidatorConfig c = assertDoesNotThrow(() -> base().jwksUri(url)
                    .introspection(new IntrospectionConfig(url, "rs", "s")).build(), url);
            assertFalse(c.allowInsecure());
        }
    }

    /** A negative leeway expires every token early; it is a mistake, not a policy. */
    @Test
    void refusesNegativeLeeway() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> base().leewaySeconds(-1).build());
        assertTrue(e.getMessage().contains("leewaySeconds"), e.getMessage());
        assertDoesNotThrow(() -> base().leewaySeconds(0).build());
    }
}
