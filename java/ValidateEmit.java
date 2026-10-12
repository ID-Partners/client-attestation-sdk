import global.idpartners.clientattestation.tokenvalidator.AccessTokenValidator;
import global.idpartners.clientattestation.tokenvalidator.AuthDecision;
import global.idpartners.clientattestation.tokenvalidator.IntrospectionConfig;
import global.idpartners.clientattestation.tokenvalidator.ProtectedResource;
import global.idpartners.clientattestation.tokenvalidator.ValidationResult;
import global.idpartners.clientattestation.tokenvalidator.ValidatorConfig;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;

/**
 * Validate every shared vector (tokens.json, introspection.json, config.json) and emit this port's verdicts, for the
 * cross-language agreement check. Run by verify-validation.sh (source-file mode, with the SDK and jose4j on
 * the classpath) from java/.
 */
public final class ValidateEmit {

    private static Map<String, Object> vectors;

    /** What a case with a fetch error is given instead of a static key set. */
    private static final String JWKS_URI = "https://keys.internal.example:8443/jwks";

    /** The shared config, with a case's overrides; an override key that is present wins even when empty. */
    @SuppressWarnings("unchecked")
    private static ValidatorConfig.Builder configFor(Map<String, Object> overrides) {
        ValidatorConfig.Builder b = ValidatorConfig.builder()
                .issuer((String) vectors.get("issuer"))
                .audiences((String) vectors.get("audience"))
                .jwks((Map<String, Object>) vectors.get("jwks"))
                .requiredScopes((List<String>) vectors.get("required_scopes"))
                .acceptedAlgorithms((List<String>) vectors.get("accepted_algorithms"));
        if (overrides != null) {
            if (overrides.containsKey("accepted_algorithms")) {
                b.acceptedAlgorithms((List<String>) overrides.get("accepted_algorithms"));
            }
            if (overrides.containsKey("accepted_token_types")) {
                b.acceptedTokenTypes((List<String>) overrides.get("accepted_token_types"));   // null: check off
            }
            if (overrides.containsKey("leeway_seconds")) {
                b.leewaySeconds(((Number) overrides.get("leeway_seconds")).intValue());
            }
        }
        return b;
    }

    private static Map<String, Object> row(Object name, boolean valid, String error) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("name", name);
        row.put("valid", valid);
        row.put("error", error);
        return row;
    }

    private static Map<String, Object> row(Object name, ValidationResult result) {
        Map<String, Object> row = row(name, result.valid(), result.error());
        row.put("description", result.errorDescription());
        return row;
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        Path validation = Path.of("..", "validation").toAbsolutePath().normalize();
        vectors = JsonUtil.parseJson(Files.readString(validation.resolve("tokens.json"), StandardCharsets.UTF_8));

        List<Map<String, Object>> results = new ArrayList<>();
        for (Map<String, Object> c : (List<Map<String, Object>>) vectors.get("cases")) {
            // a case's own key set replaces the shared one; a case with a fetch error gets a jwks_uri instead
            ValidatorConfig.Builder config = configFor((Map<String, Object>) c.get("config"));
            if (c.containsKey("jwks")) {
                config.jwks((Map<String, Object>) c.get("jwks"));
            }
            String fetchError = (String) c.get("jwks_fetch_error");
            if (fetchError != null) {
                config.jwks((Map<String, Object>) null).jwksUri(JWKS_URI);
            }
            AccessTokenValidator.Builder builder = AccessTokenValidator.builder(config.build())
                    .httpGet(url -> {
                        throw new IllegalStateException(fetchError);
                    });
            if (c.get("now") != null) {
                long millis = ((Number) c.get("now")).longValue() * 1000L;
                builder.clock(() -> millis);
            }
            ValidationResult result = builder.build().validate((String) c.get("token"));
            results.add(row(c.get("name"), result));
        }

        Map<String, Object> introspection = JsonUtil.parseJson(
                Files.readString(validation.resolve("introspection.json"), StandardCharsets.UTF_8));
        List<Map<String, Object>> introspectionResults = new ArrayList<>();
        for (Map<String, Object> c : (List<Map<String, Object>>) introspection.get("cases")) {
            ValidatorConfig.Builder config = configFor(null);
            if (!Boolean.TRUE.equals(c.get("no_endpoint"))) {
                config.introspection(new IntrospectionConfig("https://issuer.example.com/introspect", "rs", "secret"));
            }
            AccessTokenValidator validator = AccessTokenValidator.builder(config.build())
                    .httpPost((url, body, headers) -> {
                        if (Boolean.TRUE.equals(c.get("transport_error"))) {
                            throw new IllegalStateException("introspection endpoint returned HTTP 503");
                        }
                        return (Map<String, Object>) c.get("response");
                    })
                    .build();
            try {
                ValidationResult result = validator.validateActive("opaque-token");
                introspectionResults.add(row(c.get("name"), result.valid(), result.error()));
            } catch (RuntimeException e) {
                introspectionResults.add(row(c.get("name"), false, "raises"));
            }
        }

        Map<String, Object> guard = (Map<String, Object>) introspection.get("guard");
        List<Map<String, Object>> guardResults = new ArrayList<>();
        for (Map<String, Object> c : (List<Map<String, Object>>) introspection.get("cases")) {
            ValidatorConfig.Builder config = configFor(null).audiences((List<String>) guard.get("audiences"));
            if (!Boolean.TRUE.equals(c.get("no_endpoint"))) {
                config.introspection(new IntrospectionConfig("https://issuer.example.com/introspect", "rs", "secret"));
            }
            AccessTokenValidator validator = AccessTokenValidator.builder(config.build())
                    .httpPost((url, body, headers) -> {
                        if (Boolean.TRUE.equals(c.get("transport_error"))) {
                            throw new IllegalStateException("introspection endpoint returned HTTP 503");
                        }
                        return (Map<String, Object>) c.get("response");
                    })
                    .build();
            ProtectedResource resource = new ProtectedResource((String) guard.get("resource"),
                    List.of((String) vectors.get("issuer")), validator);
            try {
                AuthDecision decision = resource.authenticateActive("Bearer opaque-token", null);
                guardResults.add(row(c.get("name"), decision.authorized(),
                        decision.authorized() ? null : decision.result().error()));
            } catch (RuntimeException e) {
                guardResults.add(row(c.get("name"), false, "raises"));
            }
        }

        Map<String, Object> configCases = JsonUtil.parseJson(
                Files.readString(validation.resolve("config.json"), StandardCharsets.UTF_8));
        List<Map<String, Object>> configResults = new ArrayList<>();
        for (Map<String, Object> c : (List<Map<String, Object>>) configCases.get("cases")) {
            Map<String, Object> cfg = (Map<String, Object>) c.get("config");
            ValidatorConfig.Builder config = configFor(null);
            if (cfg.containsKey("jwks_uri")) {
                config.jwks((Map<String, Object>) null).jwksUri((String) cfg.get("jwks_uri"));
            }
            if (cfg.containsKey("introspection_endpoint")) {
                config.introspection(
                        new IntrospectionConfig((String) cfg.get("introspection_endpoint"), "rs", "secret"));
            }
            if (cfg.containsKey("allow_insecure")) {
                config.allowInsecure((Boolean) cfg.get("allow_insecure"));
            }
            if (cfg.containsKey("leeway_seconds")) {
                config.leewaySeconds(((Number) cfg.get("leeway_seconds")).intValue());
            }
            try {
                AccessTokenValidator.builder(config.build()).build();
                configResults.add(row(c.get("name"), true, null));
            } catch (IllegalArgumentException e) {
                configResults.add(row(c.get("name"), false, "refused"));
            }
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("language", "java");
        out.put("results", results);
        out.put("introspection_results", introspectionResults);
        out.put("guard_results", guardResults);
        out.put("config_results", configResults);
        Files.createDirectories(validation.resolve("out"));
        Files.writeString(validation.resolve("out").resolve("java.json"), JsonUtil.toJson(out),
                StandardCharsets.UTF_8);
        System.out.println("wrote validation/out/java.json");
    }
}
