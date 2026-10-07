package global.idpartners.clientattestation.tokenvalidator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import global.idpartners.clientattestation.TransportException;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Authorization-server metadata discovery (RFC 8414). */
class DiscoveryTest {

    private static final String METADATA = "{\"issuer\":\"https://issuer.example.com\","
            + "\"jwks_uri\":\"https://issuer.example.com/jwks\","
            + "\"introspection_endpoint\":\"https://issuer.example.com/introspect\"}";

    @Test
    void fetchesTheMetadataDocument() throws Exception {
        try (Fixtures.Stub stub = new Fixtures.Stub()) {
            stub.respond("/.well-known/oauth-authorization-server", 200, METADATA);
            Map<String, Object> md = Discovery.discover(stub.url("/.well-known/oauth-authorization-server"));
            assertEquals("https://issuer.example.com/jwks", md.get("jwks_uri"));
            assertEquals("https://issuer.example.com", md.get("issuer"));
        }
    }

    @Test
    void injectedTransport() {
        Map<String, Object> md = Discovery.discover("https://issuer.example.com/.well-known/oauth-authorization-server",
                url -> METADATA);
        assertEquals("https://issuer.example.com/introspect", md.get("introspection_endpoint"));
        assertThrows(TransportException.class, () -> Discovery.discover("https://x", url -> "not json"));
    }

    @Test
    void refusesErrorsAndRedirects() throws Exception {
        try (Fixtures.Stub stub = new Fixtures.Stub()) {
            stub.respond("/404", 404, "{}");
            stub.respond("/target", 200, METADATA);
            stub.redirect("/redirect", stub.url("/target"));
            assertThrows(TransportException.class, () -> Discovery.discover(stub.url("/404")));
            assertThrows(TransportException.class, () -> Discovery.discover(stub.url("/redirect")));
            assertEquals(0, stub.hits("/target"));
        }
    }
}
