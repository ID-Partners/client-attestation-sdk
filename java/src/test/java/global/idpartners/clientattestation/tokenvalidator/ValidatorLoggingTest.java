package global.idpartners.clientattestation.tokenvalidator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import global.idpartners.clientattestation.TransportException;
import global.idpartners.clientattestation.internal.HttpTransport;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.Test;

/**
 * Validator logging (docs/logging.md): the events at the most verbose level, that none of them carries a
 * token, secret or key, and that nothing is logged unless a logger is configured.
 */
class ValidatorLoggingTest {

    private static final Map<String, Object> V = Fixtures.vectors();

    private static void assertNoSecrets(Fixtures.RecordingLogger log) {
        for (String bad : new String[] {"eyJ", "SECRET", "\"d\":", "opaque-token"}) {
            assertFalse(log.all().contains(bad), "log output contains " + bad + ":\n" + log.all());
        }
    }

    @Test
    void validatorNeverLogsTokens() throws Exception {
        Fixtures.RecordingLogger log = new Fixtures.RecordingLogger();
        try (Fixtures.Stub stub = new Fixtures.Stub()) {
            @SuppressWarnings("unchecked")
            Map<String, Object> jwks = (Map<String, Object>) V.get("jwks");
            stub.respond("/jwks", 200, JsonUtil.toJson(jwks));
            AccessTokenValidator val = AccessTokenValidator.builder(Fixtures.vectorConfig(V).jwks((Map<String, Object>) null)
                    .jwksUri(stub.url("/jwks?SECRET=1"))
                    .introspection(new IntrospectionConfig("https://as.example/introspect?SECRET=1", "rs",
                            "SECRET-client-secret")).build())
                    .logger(log)
                    .httpPost((u, b, h) -> Map.of("active", true, "scope", "read", "aud", V.get("audience")))
                    .build();
            List<Map<String, Object>> cases = new java.util.ArrayList<>();
            for (Map<String, Object> c : Fixtures.cases(V)) {
                if (Fixtures.shared(c)) {
                    cases.add(c);
                }
            }
            for (Map<String, Object> c : cases) {
                val.validate((String) c.get("token"));
            }
            // an unknown kid inside the cooldown is throttled, not fetched
            val.jwksProvider().resolve("unknown-kid", null);
            val.validateActive("opaque-token");

            List<String> verdicts = log.named("token.validated");
            assertEquals(cases.size() + 1, verdicts.size(), log.all());
            for (int i = 0; i < cases.size(); i++) {
                assertEquals("token.validated result=" + cases.get(i).get("expect") + " mode=jwt", verdicts.get(i));
            }
            assertEquals("token.validated result=valid mode=introspection", verdicts.get(verdicts.size() - 1));
            assertEquals(List.of("jwks.fetched host=127.0.0.1:" + stub.url("").split(":")[2] + " keys=1"),
                    log.named("jwks.fetched"));
            assertEquals(1, stub.hits("/jwks"));
            assertFalse(log.named("jwks.refetch_throttled").isEmpty(), log.all());
            assertNoSecrets(log);
        }
        // levels: debug for valid, info for a refusal
        int firstValid = log.lines.indexOf("token.validated result=valid mode=jwt");
        int firstExpired = log.lines.indexOf("token.validated result=expired mode=jwt");
        assertEquals(System.Logger.Level.DEBUG, log.levels.get(firstValid));
        assertEquals(System.Logger.Level.INFO, log.levels.get(firstExpired));
    }

    @Test
    void jwksFetchFailuresAreClassified() throws Exception {
        try (Fixtures.Stub stub = new Fixtures.Stub()) {
            stub.respond("/503", 503, "{}");
            stub.redirect("/redirect", stub.url("/503"));
            stub.respond("/big", 200, "x".repeat((int) AccessTokenValidator.MAX_JWKS_BYTES + 1));
            stub.respond("/notjson", 200, "not json");
            Object[][] cases = {
                {stub.url("/503"), "status", " status=503"},
                {stub.url("/redirect"), "redirect", " status=302"},
                {stub.url("/big"), "too_large", ""},
                {stub.url("/notjson"), "malformed", ""},
                {"http://127.0.0.1:1/jwks", "network", ""},
            };
            for (Object[] c : cases) {
                Fixtures.RecordingLogger log = new Fixtures.RecordingLogger();
                AccessTokenValidator v = AccessTokenValidator.builder(ValidatorConfig.builder()
                        .issuer(Fixtures.ISSUER).audiences(Fixtures.AUDIENCE).jwksUri((String) c[0]).build())
                        .logger(log).build();
                v.validate((String) Fixtures.tokenNamed(V, "valid"));
                List<String> failed = log.named("jwks.fetch_failed");
                assertEquals(1, failed.size(), log.all());
                assertTrue(failed.get(0).startsWith("jwks.fetch_failed host=127.0.0.1:"), failed.get(0));
                assertTrue(failed.get(0).endsWith(" reason=" + c[1] + c[2]), failed.get(0));
                int at = log.lines.indexOf(failed.get(0));
                assertEquals(System.Logger.Level.WARNING, log.levels.get(at));
                assertNoSecrets(log);
            }
        }
    }

    @Test
    void injectedGetterFailuresAreClassified() {
        AtomicLong clock = new AtomicLong();
        Fixtures.RecordingLogger log = new Fixtures.RecordingLogger();
        JwksProvider p = new JwksProvider(null, "https://as.test/jwks", url -> {
            throw new IllegalStateException("connection refused");
        }, clock::get, new ValidatorLog(log));
        p.resolve("k", null);
        assertEquals(List.of("jwks.fetch_failed host=as.test reason=network"), log.named("jwks.fetch_failed"));
        JwksProvider big = new JwksProvider(null, "https://as.test/jwks",
                url -> "x".repeat((int) AccessTokenValidator.MAX_JWKS_BYTES + 1), clock::get, new ValidatorLog(log));
        big.resolve("k", null);
        assertTrue(log.named("jwks.fetch_failed").get(1).endsWith("reason=too_large"));
    }

    @Test
    void introspectionFailureLogsHttpFailed() throws Exception {
        try (Fixtures.Stub stub = new Fixtures.Stub()) {
            stub.respond("/introspect", 401, "{\"error\":\"invalid_client\"}");
            Fixtures.RecordingLogger log = new Fixtures.RecordingLogger();
            AccessTokenValidator v = AccessTokenValidator.builder(Fixtures.vectorConfig(V)
                    .introspection(new IntrospectionConfig(stub.url("/introspect?SECRET=1"), "rs", "SECRET")).build())
                    .logger(log).build();
            assertThrows(TransportException.class, () -> v.validateActive(Fixtures.tokenNamed(V, "valid")));
            List<String> failed = log.named("http.failed");
            assertEquals(1, failed.size(), log.all());
            assertTrue(failed.get(0).startsWith("http.failed step=introspection method=POST host=127.0.0.1:"),
                    failed.get(0));
            assertTrue(failed.get(0).endsWith(" path=/introspect status=401 reason=status"), failed.get(0));
            assertTrue(log.named("token.validated").isEmpty(), "no verdict when introspection throws");
            assertNoSecrets(log);
        }
        Fixtures.RecordingLogger log = new Fixtures.RecordingLogger();
        AccessTokenValidator injected = AccessTokenValidator.builder(Fixtures.vectorConfig(V)
                .introspection(new IntrospectionConfig("https://as.example/introspect", "rs", "SECRET")).build())
                .logger(log).httpPost((u, b, h) -> {
                    throw new IllegalStateException("down");
                }).build();
        assertThrows(IllegalStateException.class, () -> injected.introspect("t"));
        assertEquals(List.of("http.failed step=introspection method=POST host=as.example path=/introspect "
                + "reason=network"), log.named("http.failed"));
    }

    @Test
    void failureReasonClassifies() {
        assertEquals("network", HttpTransport.failureReason(new IllegalStateException("x")));
    }

    @Test
    void silentByDefault() {
        Logger root = Logger.getLogger("");
        java.util.logging.Level previous = root.getLevel();
        StringBuilder seen = new StringBuilder();
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                seen.append(record.getMessage()).append('\n');
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        root.addHandler(handler);
        root.setLevel(java.util.logging.Level.ALL);
        try {
            AccessTokenValidator v = new AccessTokenValidator(Fixtures.vectorConfig(V).build());
            v.validate(Fixtures.tokenNamed(V, "valid"));
            v.validate(Fixtures.tokenNamed(V, "expired"));
            AccessTokenValidator.builder(Fixtures.vectorConfig(V).build()).logger(null).build()
                    .validate(Fixtures.tokenNamed(V, "valid"));
        } finally {
            root.removeHandler(handler);
            root.setLevel(previous);
        }
        assertFalse(seen.toString().contains("token.validated"), seen.toString());
    }
}
