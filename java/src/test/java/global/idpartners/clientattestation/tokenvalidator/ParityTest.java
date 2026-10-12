package global.idpartners.clientattestation.tokenvalidator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import global.idpartners.clientattestation.TransportException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The decisions validation/SEMANTICS.md pins for every port, beyond what the shared token vectors reach: the
 * shared introspection vectors, the default introspection transport's cap and strict parsing, and the strict
 * JSON reader's edges.
 */
class ParityTest {

    @Test
    @SuppressWarnings("unchecked")
    void introspectionVectorsMatchExpected() {
        Map<String, Object> v = Fixtures.vectors();
        for (Map<String, Object> c : Fixtures.introspectionCases()) {
            ValidatorConfig.Builder config = Fixtures.vectorConfig(v);
            if (!Boolean.TRUE.equals(c.get("no_endpoint"))) {
                config.introspection(new IntrospectionConfig("https://as.test/introspect", "rs", "s"));
            }
            AccessTokenValidator val = AccessTokenValidator.builder(config.build())
                    .httpPost((u, b, h) -> {
                        if (Boolean.TRUE.equals(c.get("transport_error"))) {
                            throw new IllegalStateException("introspection endpoint returned HTTP 503");
                        }
                        return (Map<String, Object>) c.get("response");
                    }).build();
            String got;
            try {
                ValidationResult r = val.validateActive("opaque");
                got = r.valid() ? ErrorCodes.VALID : r.error();
            } catch (RuntimeException e) {
                got = "raises";
            }
            assertEquals(c.get("expect"), got, (String) c.get("name"));
        }
    }

    private static AccessTokenValidator against(Fixtures.Stub stub) {
        return new AccessTokenValidator(ValidatorConfig.builder().issuer(Fixtures.ISSUER).audiences(Fixtures.AUDIENCE)
                .introspection(new IntrospectionConfig(stub.url("/introspect"), "rs", "s")).build());
    }

    @Test
    void defaultIntrospectionRefusesWhatEveryPortRefuses() throws Exception {
        String big = "{\"active\": true, \"x\": \"" + "a".repeat((int) AccessTokenValidator.MAX_INTROSPECTION_BYTES) + "\"}";
        Map<String, String> bodies = Map.of(
                "{\"active\": true, \"active\": false}", "duplicate member name",
                "[true]", "not a JSON object",
                "{\"active\": true,}", "not JSON",
                big, "exceeds");
        for (Map.Entry<String, String> e : bodies.entrySet()) {
            try (Fixtures.Stub stub = new Fixtures.Stub()) {
                stub.respond("/introspect", 200, e.getKey());
                TransportException err = assertThrows(TransportException.class, () -> against(stub).validateActive("t"));
                assertTrue(err.getMessage().contains(e.getValue()), err.getMessage());
            }
        }
    }

    @Test
    void defaultIntrospectionReadsAStrictObject() throws Exception {
        try (Fixtures.Stub stub = new Fixtures.Stub()) {
            stub.respond("/introspect", 200, "{\"active\": true, \"scope\": \"read\", \"sub\": \"agent-1\"}");
            ValidationResult r = against(stub).validateActive("t");
            assertTrue(r.valid());
            assertEquals("agent-1", r.subject());
        }
    }

    @Test
    void injectedTransportReturningNothingRaises() {
        AccessTokenValidator v = AccessTokenValidator.builder(ValidatorConfig.builder().issuer(Fixtures.ISSUER)
                .audiences(Fixtures.AUDIENCE).introspection(new IntrospectionConfig("https://as.test/i", "rs", "s"))
                .build()).httpPost((u, b, h) -> null).build();
        assertThrows(IllegalStateException.class, () -> v.validateActive("t"));
    }

    private static Map<String, Object> parse(String json) throws Strict.Malformed {
        return Strict.parseObject(json.getBytes(StandardCharsets.UTF_8), "payload");
    }

    @Test
    void strictReaderReadsWhatRfc8259Allows() throws Exception {
        Map<String, Object> o = parse(" {\"s\": \"q\\\"b\\\\s\\/f\\bn\\fr\\nt\\rt\\tu\\u00e9\\u0041\", \"t\": true, \"f\": false,"
                + " \"n\": null, \"a\": [], \"o\": {}, \"i\": -0, \"l\": 12, \"b\": 9999999999999999999,"
                + " \"d\": 1.5e-3, \"e\": 2E+2, \"x\": [1, [2], {\"y\": \"z\"}]}\r\n");
        assertEquals("q\"b\\s/f\bn\fr\nt\rt\tu\u00e9A", o.get("s"));
        assertEquals(Boolean.TRUE, o.get("t"));
        assertEquals(Boolean.FALSE, o.get("f"));
        assertTrue(o.containsKey("n") && o.get("n") == null);
        assertEquals(List.of(), o.get("a"));
        assertEquals(Map.of(), o.get("o"));
        assertEquals(0L, o.get("i"));
        assertEquals(12L, o.get("l"));
        assertEquals(new BigInteger("9999999999999999999"), o.get("b"));
        assertEquals(1.5e-3, o.get("d"));
        assertEquals(200.0, o.get("e"));
        assertEquals(Double.POSITIVE_INFINITY, parse("{\"e\": 1e400}").get("e"));
    }

    @Test
    void strictReaderReadsALongIntegerAsADouble() throws Exception {
        // past 19 digits an integer is a double, as in Go and TypeScript (Python past 4000): new BigInteger is
        // quadratic in the digits, and the reader runs on the unauthenticated header
        assertEquals(1e20, parse("{\"n\": 100000000000000000000}").get("n"));
        assertEquals(-1e20, parse("{\"n\": -100000000000000000000}").get("n"));
        assertEquals(Double.POSITIVE_INFINITY, parse("{\"n\": " + "9".repeat(1_000_000) + "}").get("n"));
        assertThrows(Strict.Malformed.class,
                () -> Strict.numericDate(parse("{\"exp\": 100000000000000000000}"), "exp"));
    }

    @Test
    void strictReaderRefusesWhatJose4jWouldTake() {
        for (String bad : List.of("{\"a\":1,}", "{\"a\":[1,]}", "{\"a\":01}", "{\"a\":\"\u0001\"}", "{\"a\":1} x",
                "{\"a\":NaN}", "{\"a\":-}", "{\"a\":1.}", "{\"a\":1e}", "{\"a\":tru}", "{\"a\":\"\\x\"}",
                "{\"a\":\"\\u12\"}", "{\"a\":\"\\u12G4\"}", "{\"a\":\"\\u\u0660\u066041\"}",
                "{\"a\":\"\\u00\uff21\uff21\"}", "{\"a\":\"open", "{a:1}", "{\"a\" 1}", "{\"a\":1 \"b\":2}",
                "[1 2]", "", "\"s\"", "{\"a\":{\"b\":1,\"b\":2}}", "{\"a\":" + "[".repeat(70) + "]".repeat(70) + "}")) {
            assertThrows(Strict.Malformed.class, () -> parse(bad), bad);
        }
        assertThrows(Strict.Malformed.class,
                () -> Strict.parseObject(new byte[] {'{', '"', 'a', '"', ':', '"', (byte) 0xff, '"', '}'}, "payload"));
    }

    @Test
    void claimShapes() throws Exception {
        assertEquals(List.of("a"), Strict.audience(Map.of("aud", "a")));
        assertThrows(Strict.Malformed.class, () -> Strict.audience(Map.of("aud", Map.of())));
        assertThrows(Strict.Malformed.class, () -> Strict.scopes(Map.of("scope", List.of("read"))));
        assertEquals(List.of("read"), Strict.scopes(Map.of("scp", List.of("read"))));
        assertNull(Strict.subject(Map.of()));
        assertThrows(Strict.Malformed.class, () -> Strict.splitCompact(null));
    }
}
