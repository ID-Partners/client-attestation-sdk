package global.idpartners.clientattestation.tokenvalidator;

import static global.idpartners.clientattestation.tokenvalidator.Fixtures.AUDIENCE;
import static global.idpartners.clientattestation.tokenvalidator.Fixtures.ISSUER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import global.idpartners.clientattestation.TransportException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/** RFC 7662 introspection and {@code validateActive}, with injected and real (loopback) transports. */
class IntrospectionTest {

    private static final String ENDPOINT = "https://as.test/introspect";

    private static ValidatorConfig.Builder config() {
        return ValidatorConfig.builder().issuer(ISSUER).audiences(AUDIENCE);
    }

    private static AccessTokenValidator withResponse(ValidatorConfig config, Map<String, Object> response) {
        return AccessTokenValidator.builder(config).httpPost((url, body, headers) -> response).build();
    }

    private static Map<String, String> form(String body) {
        Map<String, String> out = new HashMap<>();
        for (String pair : body.split("&")) {
            String[] kv = pair.split("=", 2);
            out.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8), URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
        }
        return out;
    }

    @Test
    void activeWithClientSecretBasic() {
        AtomicReference<String> url = new AtomicReference<>();
        AtomicReference<String> sent = new AtomicReference<>();
        AtomicReference<Map<String, String>> headers = new AtomicReference<>();
        AccessTokenValidator v = AccessTokenValidator.builder(config().requiredScopes("read")
                .introspection(new IntrospectionConfig(ENDPOINT, "rs-1", "s3cret")).build())
                .httpPost((u, body, h) -> {
                    url.set(u);
                    sent.set(body);
                    headers.set(h);
                    return Map.of("active", true, "scope", "read write", "sub", "agent-1", "aud", AUDIENCE,
                            "exp", 4102444800L);
                }).build();
        ValidationResult r = v.validateActive("opaque-token");
        assertTrue(r.valid(), String.valueOf(r));
        assertEquals("agent-1", r.subject());
        assertEquals(List.of("read", "write"), r.scopes());
        assertEquals(List.of(AUDIENCE), r.audience());
        assertEquals(4102444800L, r.expiresAt());
        assertEquals(ENDPOINT, url.get());
        String expected = "Basic " + Base64.getEncoder().encodeToString("rs-1:s3cret".getBytes(StandardCharsets.UTF_8));
        assertEquals(expected, headers.get().get("Authorization"));
        assertEquals("application/x-www-form-urlencoded", headers.get().get("Content-Type"));
        assertEquals("application/json", headers.get().get("Accept"));
        Map<String, String> f = form(sent.get());
        assertEquals("opaque-token", f.get("token"));
        assertEquals("access_token", f.get("token_type_hint"));
        assertFalse(f.containsKey("client_secret"));
    }

    @Test
    void clientSecretPostPutsCredentialsInTheForm() {
        AtomicReference<String> sent = new AtomicReference<>();
        AtomicReference<Map<String, String>> headers = new AtomicReference<>();
        AccessTokenValidator v = AccessTokenValidator.builder(config().introspection(new IntrospectionConfig(
                ENDPOINT, "rs 1", "s3cret&x", IntrospectionConfig.CLIENT_SECRET_POST)).build())
                .httpPost((u, body, h) -> {
                    sent.set(body);
                    headers.set(h);
                    return Map.of("active", true, "scp", List.of("read"), "aud", List.of(AUDIENCE));
                }).build();
        ValidationResult r = v.validateActive("opaque", List.of("read"));
        assertTrue(r.valid());
        assertFalse(headers.get().containsKey("Authorization"));
        Map<String, String> f = form(sent.get());
        assertEquals("rs 1", f.get("client_id"));
        assertEquals("s3cret&x", f.get("client_secret"));
        assertEquals(List.of("read"), r.scopes());
        assertEquals(List.of(AUDIENCE), r.audience());
    }

    @Test
    void introspectionConfigDefaultsAndRedacts() {
        IntrospectionConfig c = new IntrospectionConfig(ENDPOINT, "rs-1", "s3cret", null);
        assertEquals(IntrospectionConfig.CLIENT_SECRET_BASIC, c.authMethod());
        assertEquals(ENDPOINT, c.endpoint());
        assertEquals("rs-1", c.clientId());
        assertEquals("s3cret", c.clientSecret());
        assertFalse(c.toString().contains("s3cret"));
        assertThrows(NullPointerException.class, () -> new IntrospectionConfig(null, "a", "b"));
    }

    // F5: anything but the two methods used to be taken as client_secret_post, moving the secret into the form
    @Test
    void introspectionConfigAcceptsOnlyTheTwoAuthMethods() {
        for (String method : List.of(IntrospectionConfig.CLIENT_SECRET_BASIC, IntrospectionConfig.CLIENT_SECRET_POST)) {
            IntrospectionConfig c = new IntrospectionConfig(ENDPOINT, "rs", "s3cret", method);
            assertEquals(method, c.authMethod());
            AccessTokenValidator.builder(config().introspection(c).build()).build();
        }
        // unset (null or "", e.g. System.getenv with no variable) is the default, client_secret_basic
        for (String method : new String[] {null, ""}) {
            assertEquals(IntrospectionConfig.CLIENT_SECRET_BASIC,
                    new IntrospectionConfig(ENDPOINT, "rs", "s3cret", method).authMethod());
        }
        for (String method : new String[] {"client_secret_basci", "private_key_jwt", "client_secret_jwt",
            "CLIENT_SECRET_BASIC", " client_secret_basic", "none", " "}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> new IntrospectionConfig(ENDPOINT, "rs", "s3cret", method), method);
            assertTrue(e.getMessage().contains("authMethod"), e.getMessage());
            assertFalse(e.getMessage().contains("s3cret"), e.getMessage());
        }
    }

    // F6: the same fixture and header are in every port's tests and in validation/introspection.json
    @Test
    void clientSecretBasicFormEncodesTheCredentials() {
        String header = "Basic cnMlM0ExK2ElMkJiJTI1YzpzM2NyJTJBdH4tLl8lMjElMjclMjglMjklMkYlM0YlMjMlMjYlM0QlQzMl"
                + "QTklRjAlOUYlOTglODA=";
        for (String method : new String[] {null, "", IntrospectionConfig.CLIENT_SECRET_BASIC}) {
            AtomicReference<String> sent = new AtomicReference<>();
            AtomicReference<Map<String, String>> headers = new AtomicReference<>();
            AccessTokenValidator v = AccessTokenValidator.builder(config().introspection(new IntrospectionConfig(
                    ENDPOINT, "rs:1 a+b%c", "s3cr*t~-._!'()/?#&=\u00e9\uD83D\uDE00", method)).build())
                    .httpPost((u, body, h) -> {
                        sent.set(body);
                        headers.set(h);
                        return Map.of("active", true);
                    }).build();
            v.introspect("opaque");
            assertEquals(header, headers.get().get("Authorization"));
            assertFalse(form(sent.get()).containsKey("client_id"));
            assertFalse(form(sent.get()).containsKey("client_secret"));
        }
        assertEquals("Basic cnM6c2VjcmV0", AccessTokenValidator.basicAuthorization("rs", "secret"));
    }

    @Test
    void explicitTokenTypeHint() {
        AtomicReference<String> sent = new AtomicReference<>();
        AccessTokenValidator v = AccessTokenValidator.builder(config()
                .introspection(new IntrospectionConfig(ENDPOINT, "rs", "s")).build()).httpPost((u, body, h) -> {
                    sent.set(body);
                    return Map.of("active", false);
                }).build();
        v.introspect("t", "refresh_token");
        assertEquals("refresh_token", form(sent.get()).get("token_type_hint"));
        v.introspect("t", null);
        assertFalse(form(sent.get()).containsKey("token_type_hint"));
    }

    @Test
    void inactiveAndNonBooleanActive() {
        ValidatorConfig c = config().introspection(new IntrospectionConfig(ENDPOINT, "rs", "s")).build();
        assertEquals(ErrorCodes.INACTIVE, withResponse(c, Map.of("active", false)).validateActive("t").error());
        assertEquals(ErrorCodes.INACTIVE, withResponse(c, Map.of()).validateActive("t").error());
        assertEquals(ErrorCodes.INACTIVE, withResponse(c, Map.of("active", "true")).validateActive("t").error());
        ValidationResult r = withResponse(c, Map.of("active", false)).validateActive("t");
        assertEquals("token is not active", r.errorDescription());
    }

    @Test
    void validateActiveEnforcesScopes() {
        ValidatorConfig c = config().requiredScopes("admin")
                .introspection(new IntrospectionConfig(ENDPOINT, "rs", "s")).build();
        AccessTokenValidator v = withResponse(c, Map.of("active", true, "scope", "read", "aud", AUDIENCE));
        assertEquals(ErrorCodes.INSUFFICIENT_SCOPE, v.validateActive("t").error());
        assertEquals(ErrorCodes.INSUFFICIENT_SCOPE, v.validateActive("t", List.of("read", "x")).error());
        assertTrue(v.validateActive("t", List.of("read")).valid());
    }

    @Test
    void validateActiveEnforcesAudienceOnlyWhenPresent() {
        ValidatorConfig c = config().introspection(new IntrospectionConfig(ENDPOINT, "rs", "s")).build();
        assertEquals(ErrorCodes.INVALID_AUDIENCE,
                withResponse(c, Map.of("active", true, "aud", "https://other")).validateActive("t").error());
        ValidationResult none = withResponse(c, Map.of("active", true)).validateActive("t");
        assertTrue(none.valid());
        assertEquals(List.of(), none.audience());
        assertNull(none.subject());
        assertNull(none.expiresAt());
        assertEquals(ErrorCodes.INVALID_TOKEN,
                withResponse(c, Map.of("active", true, "sub", 5)).validateActive("t").error());
        assertNull(withResponse(c, Map.of("active", true, "exp", "soon")).validateActive("t").expiresAt());
    }

    @Test
    void introspectWithoutConfigurationThrows() {
        AccessTokenValidator v = new AccessTokenValidator(config().build());
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> v.introspect("t"));
        assertTrue(e.getMessage().contains("introspection"));
        assertThrows(IllegalStateException.class, () -> v.validateActive("t"));
    }

    @Test
    void transportFailurePropagates() {
        AccessTokenValidator v = AccessTokenValidator.builder(config()
                .introspection(new IntrospectionConfig(ENDPOINT, "rs", "s")).build())
                .httpPost((u, b, h) -> {
                    throw new IllegalStateException("down");
                }).build();
        assertThrows(IllegalStateException.class, () -> v.validateActive("t"));
        AccessTokenValidator nullResponse = AccessTokenValidator.builder(config()
                .introspection(new IntrospectionConfig(ENDPOINT, "rs", "s")).build())
                .httpPost((u, b, h) -> null).build();
        assertThrows(IllegalStateException.class, () -> nullResponse.introspect("t"));
    }

    @Test
    void defaultTransportPostsTheFormAndParsesJson() throws Exception {
        try (Fixtures.Stub stub = new Fixtures.Stub()) {
            stub.respond("/introspect", 200,
                    "{\"active\":true,\"scope\":\"read\",\"sub\":\"agent-1\",\"aud\":\"" + AUDIENCE + "\"}");
            AccessTokenValidator v = new AccessTokenValidator(config()
                    .introspection(new IntrospectionConfig(stub.url("/introspect"), "rs-1", "s3cret")).build());
            ValidationResult r = v.validateActive("opaque-token");
            assertTrue(r.valid());
            assertEquals("agent-1", r.subject());
            assertEquals("opaque-token", form(stub.bodies.get("/introspect")).get("token"));
            assertTrue(stub.headers.get("/introspect").getFirst("Authorization").startsWith("Basic "));
            assertEquals("application/x-www-form-urlencoded",
                    stub.headers.get("/introspect").getFirst("Content-Type"));
        }
    }

    @Test
    void defaultTransportRefusesErrorsRedirectsAndBadBodies() throws Exception {
        String dead;
        try (Fixtures.Stub stub = new Fixtures.Stub()) {
            stub.respond("/401", 401, "{\"error\":\"invalid_client\"}");
            stub.respond("/target", 200, "{\"active\":true}");
            stub.redirect("/redirect", stub.url("/target"));
            stub.respond("/notjson", 200, "not json");
            for (String path : new String[] {"/401", "/redirect", "/notjson"}) {
                AccessTokenValidator v = new AccessTokenValidator(config()
                        .introspection(new IntrospectionConfig(stub.url(path), "rs", "s")).build());
                TransportException e = assertThrows(TransportException.class, () -> v.validateActive("t"), path);
                if ("/401".equals(path)) {
                    assertEquals(401, e.status());
                }
            }
            assertEquals(0, stub.hits("/target"), "a redirect is never followed");
            dead = stub.url("/introspect");
        }
        AccessTokenValidator v = new AccessTokenValidator(config()
                .introspection(new IntrospectionConfig(dead, "rs", "s")).build());
        assertThrows(TransportException.class, () -> v.introspect("t"));
        // allowInsecure, so "://bad" reaches the transport
        AccessTokenValidator bad = new AccessTokenValidator(config()
                .introspection(new IntrospectionConfig("://bad", "rs", "s")).allowInsecure(true).build());
        assertThrows(IllegalArgumentException.class, () -> bad.introspect("t"));
    }

    // The client id and secret must be non-empty, and the error names the field, never the value
    @Test
    void credentialsMustBeNonEmpty() {
        for (String[] c : new String[][] {{null, "s3cret", "clientId"}, {"", "s3cret", "clientId"},
            {"rs", null, "clientSecret"}, {"rs", "", "clientSecret"}}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> new IntrospectionConfig(ENDPOINT, c[0], c[1]), c[2]);
            assertTrue(e.getMessage().contains(c[2]), e.getMessage());
            assertFalse(e.getMessage().contains("s3cret"), e.getMessage());
        }
    }

    // A bad authMethod is described, never echoed: a secret put in the wrong argument would be in the message
    @Test
    void authMethodRefusalDoesNotEchoTheValue() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> new IntrospectionConfig(ENDPOINT, "rs", "s3cret", "hunter2-secret"));
        assertFalse(e.getMessage().contains("hunter2"), e.getMessage());
        assertTrue(e.getMessage().contains("14 characters"), e.getMessage());
    }
}
