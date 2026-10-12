package global.idpartners.clientattestation.tokenvalidator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import global.idpartners.clientattestation.TransportException;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Authorization-server metadata discovery (RFC 8414). */
class DiscoveryTest {

    private static final String WELL_KNOWN = "https://issuer.example.com/.well-known/oauth-authorization-server";

    private static final String METADATA = "{\"issuer\":\"https://issuer.example.com\","
            + "\"jwks_uri\":\"https://issuer.example.com/jwks\","
            + "\"introspection_endpoint\":\"https://issuer.example.com/introspect\"}";

    private static String metadata(String issuer, String jwksUri) {
        return "{\"issuer\":\"" + issuer + "\",\"jwks_uri\":\"" + jwksUri + "\"}";
    }

    @Test
    void fetchesTheMetadataDocument() throws Exception {
        try (Fixtures.Stub stub = new Fixtures.Stub()) {
            String issuer = stub.url("");
            stub.respond("/.well-known/oauth-authorization-server", 200, metadata(issuer, issuer + "/jwks"));
            Map<String, Object> md = Discovery.discover(stub.url("/.well-known/oauth-authorization-server"));
            assertEquals(issuer + "/jwks", md.get("jwks_uri"));
            assertEquals(issuer, md.get("issuer"));
        }
    }

    @Test
    void injectedTransport() {
        Map<String, Object> md = Discovery.discover(WELL_KNOWN, url -> METADATA);
        assertEquals("https://issuer.example.com/introspect", md.get("introspection_endpoint"));
        assertThrows(TransportException.class, () -> Discovery.discover(WELL_KNOWN, url -> "not json"));
    }

    @Test
    void refusesErrorsAndRedirects() throws Exception {
        try (Fixtures.Stub stub = new Fixtures.Stub()) {
            stub.respond("/404", 404, "{}");
            stub.respond("/target", 200, METADATA);
            stub.redirect("/redirect", stub.url("/target"));
            String issuer = "https://issuer.example.com";
            assertThrows(TransportException.class, () -> Discovery.discover(stub.url("/404"), issuer, null));
            assertThrows(TransportException.class, () -> Discovery.discover(stub.url("/redirect"), issuer, null));
            assertEquals(0, stub.hits("/target"));
        }
    }

    /**
     * RFC 8414 section 3.3: metadata naming another issuer must not be used. Otherwise whoever answers for
     * the metadata URL chooses the issuer, and the keys, the validator trusts.
     */
    @Test
    void refusesAnotherIssuer() {
        TransportException e = assertThrows(TransportException.class, () -> Discovery.discover(WELL_KNOWN,
                url -> metadata("https://attacker.example", "https://attacker.example/jwks")));
        assertTrue(e.getMessage().contains("https://attacker.example"), e.getMessage());
        assertThrows(TransportException.class, () -> Discovery.discover(WELL_KNOWN,
                url -> "{\"jwks_uri\":\"https://issuer.example.com/jwks\"}"));
        assertThrows(TransportException.class, () -> Discovery.discover(WELL_KNOWN,
                url -> "{\"issuer\":7}"));
        // an explicit issuer is compared exactly
        assertThrows(TransportException.class, () -> Discovery.discover(WELL_KNOWN, "https://other.example",
                url -> METADATA));
        assertEquals("https://issuer.example.com", Discovery.discover("https://meta.example/config",
                "https://issuer.example.com", url -> METADATA).get("issuer"));
    }

    @Test
    void derivesTheExpectedIssuer() {
        assertEquals("https://as.example", Discovery.expectedIssuer(
                "https://as.example/.well-known/oauth-authorization-server"));
        assertEquals("https://as.example/tenant/1", Discovery.expectedIssuer(
                "https://as.example/.well-known/oauth-authorization-server/tenant/1"));
        assertEquals("https://as.example/tenant", Discovery.expectedIssuer(
                "https://as.example/.well-known/openid-configuration/tenant"));
        assertEquals("https://as.example/realms/x", Discovery.expectedIssuer(
                "https://as.example/realms/x/.well-known/openid-configuration"));
        assertEquals("https://as.example:8443/realms/x", Discovery.expectedIssuer(
                "HTTPS://as.example:8443/realms/x/.well-known/oauth-authorization-server"));
        assertNull(Discovery.expectedIssuer("https://as.example/metadata"));
        assertNull(Discovery.expectedIssuer("https://as.example/.well-known/oauth-authorization-serverx"));
        assertNull(Discovery.expectedIssuer("https://as.example/.well-known/openid-configuration?x=1"));
        // a terminating "/" dropped from the issuer when the URL was built is accepted back
        assertEquals("https://as.example/", Discovery.discover("https://as.example/.well-known/openid-configuration",
                url -> "{\"issuer\":\"https://as.example/\"}").get("issuer"));
        // anything else names no issuer: the caller must say which one
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Discovery.discover("https://as.example/metadata", url -> METADATA));
        assertTrue(e.getMessage().contains("expected issuer"), e.getMessage());
    }

    @Test
    void requiresHttps() {
        int[] calls = {0};
        assertThrows(IllegalArgumentException.class, () -> Discovery.discover(
                "http://issuer.example.com/.well-known/oauth-authorization-server", url -> {
                    calls[0]++;
                    return metadata("http://issuer.example.com", "https://issuer.example.com/jwks");
                }));
        assertEquals(0, calls[0]);
        assertThrows(TransportException.class, () -> Discovery.discover(WELL_KNOWN,
                url -> metadata("https://issuer.example.com", "http://issuer.example.com/jwks")));
        assertThrows(TransportException.class, () -> Discovery.discover(WELL_KNOWN,
                url -> "{\"issuer\":\"https://issuer.example.com\","
                        + "\"introspection_endpoint\":\"http://issuer.example.com/introspect\"}"));
        assertThrows(TransportException.class, () -> Discovery.discover(WELL_KNOWN,
                url -> "{\"issuer\":\"https://issuer.example.com\",\"jwks_uri\":[\"https://x\"]}"));
        Map<String, Object> md = Discovery.discover("http://issuer.example.com/.well-known/oauth-authorization-server",
                null, url -> metadata("http://issuer.example.com", "http://issuer.example.com/jwks"), true);
        assertEquals("http://issuer.example.com/jwks", md.get("jwks_uri"));
    }

    /** The document is read with the strict parser: one JSON object, no duplicates, bounded depth. */
    @Test
    void parsesStrictly() {
        for (String body : new String[] {
            "[" + METADATA + "]",
            "{\"issuer\":\"https://issuer.example.com\",\"issuer\":\"https://attacker.example\"}",
            "{\"issuer\":\"https://issuer.example.com\",}",
            "{\"issuer\":\"https://issuer.example.com\",\"x\":" + "[".repeat(100) + "]".repeat(100) + "}",
        }) {
            assertThrows(TransportException.class, () -> Discovery.discover(WELL_KNOWN, url -> body), body);
        }
    }
}
