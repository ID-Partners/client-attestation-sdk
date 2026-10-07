package global.idpartners.clientattestation.tokenvalidator;

import static global.idpartners.clientattestation.tokenvalidator.Fixtures.AUDIENCE;
import static global.idpartners.clientattestation.tokenvalidator.Fixtures.ISSUER;
import static global.idpartners.clientattestation.tokenvalidator.Fixtures.b64;
import static global.idpartners.clientattestation.tokenvalidator.Fixtures.claims;
import static global.idpartners.clientattestation.tokenvalidator.Fixtures.config;
import static global.idpartners.clientattestation.tokenvalidator.Fixtures.newKey;
import static global.idpartners.clientattestation.tokenvalidator.Fixtures.now;
import static global.idpartners.clientattestation.tokenvalidator.Fixtures.sign;
import static global.idpartners.clientattestation.tokenvalidator.Fixtures.signRaw;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.keys.HmacKey;
import org.junit.jupiter.api.Test;

/**
 * Local JWT validation: the shared vectors, then each check in the contract order and the edge cases the
 * other ports' suites pin (Go validator_test / validator_extra_test, Python test_validator_edge_cases,
 * TypeScript validator-extra.test).
 */
class AccessTokenValidatorTest {

    private static final EllipticCurveJsonWebKey KEY = newKey("k1");

    private static AccessTokenValidator validator() {
        return new AccessTokenValidator(config(KEY).build());
    }

    private static String code(ValidationResult r) {
        return r.valid() ? ErrorCodes.VALID : r.error();
    }

    // ── shared vectors ──────────────────────────────────────────────────────────────────────────────

    @Test
    void vectorsMatchExpected() {
        Map<String, Object> v = Fixtures.vectors();
        for (Map<String, Object> c : Fixtures.cases(v)) {
            assertEquals(c.get("expect"), code(Fixtures.validatorFor(v, c).validate((String) c.get("token"))),
                    (String) c.get("name"));
        }
    }

    @Test
    void validExposesSubjectScopesAudienceAndExpiry() {
        Map<String, Object> v = Fixtures.vectors();
        ValidationResult r = new AccessTokenValidator(Fixtures.vectorConfig(v).build())
                .validate(Fixtures.tokenNamed(v, "valid"));
        assertTrue(r.valid());
        assertNull(r.error());
        assertNull(r.errorDescription());
        assertEquals("agent-1", r.subject());
        assertEquals(List.of("read", "write"), r.scopes());
        assertEquals(List.of(v.get("audience")), r.audience());
        assertEquals(4102444800L, r.expiresAt());
        assertEquals("https://rp.example.com", r.claims().get("client_id"));
        assertTrue(r.toString().contains("agent-1"));
    }

    @Test
    void requiredScopeOverride() {
        Map<String, Object> v = Fixtures.vectors();
        AccessTokenValidator val = new AccessTokenValidator(Fixtures.vectorConfig(v).build());
        ValidationResult r = val.validate(Fixtures.tokenNamed(v, "valid"), List.of("read", "admin"));
        assertEquals(ErrorCodes.INSUFFICIENT_SCOPE, r.error());
        assertEquals("missing scopes: admin", r.errorDescription());
        assertTrue(r.toString().contains("invalid") && r.toString().contains(ErrorCodes.INSUFFICIENT_SCOPE));
        assertTrue(val.validate(Fixtures.tokenNamed(v, "missing_scope"), List.of()).valid());
    }

    // ── config ──────────────────────────────────────────────────────────────────────────────────────

    @Test
    void issuerAndAudienceAreRequired() {
        assertThrows(IllegalArgumentException.class, () -> ValidatorConfig.builder().audiences(AUDIENCE).build());
        assertThrows(IllegalArgumentException.class, () -> ValidatorConfig.builder().issuer("").audiences(AUDIENCE)
                .build());
        assertThrows(IllegalArgumentException.class, () -> ValidatorConfig.builder().issuer(ISSUER).build());
        assertThrows(IllegalArgumentException.class,
                () -> ValidatorConfig.builder().issuer(ISSUER).audiences((List<String>) null).build());
    }

    @Test
    void configDefaults() {
        ValidatorConfig c = ValidatorConfig.builder().issuer(ISSUER).audiences(AUDIENCE).build();
        assertEquals(ValidatorConfig.DEFAULT_ALGORITHMS, c.acceptedAlgorithms());
        assertEquals(List.of("at+jwt"), c.acceptedTokenTypes());
        assertEquals(60, c.leewaySeconds());
        assertEquals(List.of(), c.requiredScopes());
        assertNull(c.jwks());
        assertNull(c.jwksUri());
        assertNull(c.introspection());
        assertEquals(ISSUER, c.issuer());
        ValidatorConfig custom = ValidatorConfig.builder().issuer(ISSUER).audiences(List.of(AUDIENCE, "b"))
                .acceptedAlgorithms((List<String>) null).requiredScopes((List<String>) null)
                .acceptedTokenTypes("Application/AT+JWT").leewaySeconds(0).build();
        assertEquals(ValidatorConfig.DEFAULT_ALGORITHMS, custom.acceptedAlgorithms());
        assertEquals(List.of("at+jwt"), custom.acceptedTokenTypes());
        assertEquals(List.of(AUDIENCE, "b"), custom.audiences());
        assertEquals(0, custom.leewaySeconds());
    }

    @Test
    void jwksAsJsonText() {
        ValidatorConfig c = ValidatorConfig.builder().issuer(ISSUER).audiences(AUDIENCE)
                .jwks(Fixtures.jwksJson(KEY)).build();
        assertTrue(new AccessTokenValidator(c).validate(sign(KEY, claims())).valid());
        assertThrows(IllegalArgumentException.class, () -> ValidatorConfig.builder().jwks("{"));
        assertThrows(IllegalArgumentException.class, () -> ValidatorConfig.builder().jwks("[1]"));
    }

    @Test
    void builderRefusesNoConfig() {
        assertThrows(IllegalArgumentException.class, () -> AccessTokenValidator.builder(null).build());
    }

    // ── structure and algorithm ─────────────────────────────────────────────────────────────────────

    @Test
    void malformedTokens() {
        AccessTokenValidator v = validator();
        for (String bad : new String[] {null, "", "garbage", "not-a-jwt", "a.b.c", "a.b.c.d.e"}) {
            ValidationResult r = v.validate(bad);
            assertEquals(ErrorCodes.INVALID_TOKEN, r.error(), String.valueOf(bad));
            assertEquals("malformed token", r.errorDescription());
        }
    }

    @Test
    void headerWithoutAlgOrNonStringAlg() {
        AccessTokenValidator v = validator();
        assertEquals(ErrorCodes.UNSUPPORTED_ALGORITHM, v.validate(b64("{\"kid\":\"k1\"}") + "." + b64("{}") + ".c2ln")
                .error());
        assertEquals(ErrorCodes.UNSUPPORTED_ALGORITHM, v.validate(b64("{\"alg\":5}") + "." + b64("{}") + ".c2ln")
                .error());
    }

    @Test
    void algorithmNotAccepted() {
        AccessTokenValidator v = new AccessTokenValidator(config(KEY).acceptedAlgorithms("RS256").build());
        ValidationResult r = v.validate(sign(KEY, claims()));
        assertEquals(ErrorCodes.UNSUPPORTED_ALGORITHM, r.error());
        assertEquals("algorithm not accepted", r.errorDescription());
        // an HMAC token against the default (asymmetric-only) list
        String hs = signRaw(new HmacKey("shared-secret-of-at-least-32-bytes!!".getBytes(StandardCharsets.UTF_8)),
                JsonUtil.toJson(claims()), "HS256", "at+jwt", "k1");
        assertEquals(ErrorCodes.UNSUPPORTED_ALGORITHM, validator().validate(hs).error());
    }

    @Test
    void algNoneFailsEvenWhenAccepted() {
        // a misconfigured validator accepting "none" (or an HMAC alg) still refuses it, before any key lookup
        AccessTokenValidator v = new AccessTokenValidator(
                config(KEY).acceptedAlgorithms("ES256", "none", "None", "HS256").build());
        for (String alg : List.of("none", "None", "HS256")) {
            String token = b64("{\"alg\":\"" + alg + "\",\"kid\":\"k1\"}") + "." + b64(JsonUtil.toJson(claims())) + ".";
            ValidationResult r = v.validate(token);
            assertFalse(r.valid());
            assertEquals(ErrorCodes.UNSUPPORTED_ALGORITHM, r.error(), alg);
        }
    }

    // ── keys ────────────────────────────────────────────────────────────────────────────────────────

    @Test
    void unknownKid() {
        ValidationResult r = validator().validate(signRaw(KEY, JsonUtil.toJson(claims()), "ES256", "at+jwt",
                "unknown-kid"));
        assertEquals(ErrorCodes.KEY_NOT_FOUND, r.error());
        assertEquals("no signing key for this kid", r.errorDescription());
    }

    @Test
    void nonStringKidIsKeyNotFound() {
        String token = b64("{\"alg\":\"ES256\",\"kid\":7}") + "." + b64(JsonUtil.toJson(claims())) + ".c2ln";
        assertEquals(ErrorCodes.KEY_NOT_FOUND, validator().validate(token).error());
    }

    @Test
    void singleKeySetMatchesTokenWithoutKid() {
        EllipticCurveJsonWebKey key = newKey(null);
        AccessTokenValidator v = new AccessTokenValidator(config(key).build());
        assertTrue(v.validate(signRaw(key, JsonUtil.toJson(claims()), "ES256", "at+jwt", null)).valid());
    }

    @Test
    void multiKeySetRejectsTokenWithoutKid() {
        EllipticCurveJsonWebKey key = newKey(null);
        AccessTokenValidator v = new AccessTokenValidator(ValidatorConfig.builder().issuer(ISSUER)
                .audiences(AUDIENCE).jwks(Fixtures.jwks(key, newKey("k2"))).build());
        assertEquals(ErrorCodes.KEY_NOT_FOUND,
                v.validate(signRaw(key, JsonUtil.toJson(claims()), "ES256", "at+jwt", null)).error());
    }

    @Test
    void noKeySourceConfigured() {
        AccessTokenValidator v = new AccessTokenValidator(ValidatorConfig.builder().issuer(ISSUER)
                .audiences(AUDIENCE).build());
        assertEquals(ErrorCodes.KEY_NOT_FOUND, v.validate(sign(KEY, claims())).error());
    }

    @Test
    void jwkDeclaredAlgBindsTheKey() {
        // the same EC key, published as ES384-only: an ES256 token signed with it must not resolve
        Map<String, Object> jwk = Fixtures.publicJwk(KEY);
        jwk.put("alg", "ES384");
        AccessTokenValidator v = new AccessTokenValidator(ValidatorConfig.builder().issuer(ISSUER)
                .audiences(AUDIENCE).jwks(Map.of("keys", List.of(jwk))).acceptedAlgorithms("ES256", "ES384")
                .build());
        assertEquals(ErrorCodes.KEY_NOT_FOUND, v.validate(sign(KEY, claims())).error());
        jwk.put("alg", "ES256");
        AccessTokenValidator ok = new AccessTokenValidator(ValidatorConfig.builder().issuer(ISSUER)
                .audiences(AUDIENCE).jwks(Map.of("keys", List.of(jwk))).build());
        assertTrue(ok.validate(sign(KEY, claims())).valid());
    }

    @Test
    void rsaAndPssTokensVerify() throws Exception {
        RsaJsonWebKey rsa = RsaJwkGenerator.generateJwk(2048);
        rsa.setKeyId("rsa");
        AccessTokenValidator v = new AccessTokenValidator(config(rsa).build());
        for (String alg : new String[] {"RS256", "PS256", "RS384", "PS512"}) {
            String token = signRaw(rsa.getPrivateKey(), JsonUtil.toJson(claims()), alg, "at+jwt", "rsa");
            assertTrue(v.validate(token).valid(), alg);
        }
    }

    @Test
    void keyOfTheWrongTypeIsInvalidSignature() throws Exception {
        // an RSA key under the token's kid, but an ES256 header: verification cannot succeed
        RsaJsonWebKey rsa = RsaJwkGenerator.generateJwk(2048);
        rsa.setKeyId("k1");
        AccessTokenValidator v = new AccessTokenValidator(config(rsa).build());
        assertEquals(ErrorCodes.INVALID_SIGNATURE, v.validate(sign(KEY, claims())).error());
    }

    // ── signature and payload ───────────────────────────────────────────────────────────────────────

    @Test
    void badSignature() {
        String token = sign(newKey("k1"), claims());   // same kid, different key
        ValidationResult r = validator().validate(token);
        assertEquals(ErrorCodes.INVALID_SIGNATURE, r.error());
        assertEquals("signature verification failed", r.errorDescription());
    }

    @Test
    void nonJsonPayloadIsInvalidToken() {
        // the signature verified: the token is malformed, not forged
        ValidationResult r = validator().validate(signRaw(KEY, "EVIL not json", "ES256", null, "k1"));
        assertEquals(ErrorCodes.INVALID_TOKEN, r.error());
        assertFalse(r.errorDescription().contains("EVIL"));
    }

    @Test
    void jsonThatIsNotAnObjectIsInvalidToken() {
        for (String payload : new String[] {"[1]", "\"x\"", "null", "42"}) {
            ValidationResult r = validator().validate(signRaw(KEY, payload, "ES256", null, "k1"));
            assertEquals(ErrorCodes.INVALID_TOKEN, r.error(), payload);
        }
    }

    // ── typ ─────────────────────────────────────────────────────────────────────────────────────────

    @Test
    void tokenTypeComparisonFollowsRfc7515() {
        AccessTokenValidator v = validator();
        String payload = JsonUtil.toJson(claims());
        assertTrue(v.validate(signRaw(KEY, payload, "ES256", "application/at+jwt", "k1")).valid());
        assertTrue(v.validate(signRaw(KEY, payload, "ES256", "AT+JWT", "k1")).valid());
        assertTrue(v.validate(signRaw(KEY, payload, "ES256", null, "k1")).valid());
        ValidationResult r = v.validate(signRaw(KEY, payload, "ES256", "JWT", "k1"));
        assertEquals(ErrorCodes.INVALID_TOKEN_TYPE, r.error());
        assertEquals("token is not a JWT access token", r.errorDescription());
    }

    @Test
    void tokenTypeCheckCanBeTurnedOff() {
        String token = signRaw(KEY, JsonUtil.toJson(claims()), "ES256", "JWT", "k1");
        assertTrue(new AccessTokenValidator(config(KEY).disableTokenTypeCheck().build()).validate(token).valid());
        assertTrue(new AccessTokenValidator(config(KEY).acceptedTokenTypes((List<String>) null).build())
                .validate(token).valid());
        assertTrue(new AccessTokenValidator(config(KEY).acceptedTokenTypes("jwt").build()).validate(token).valid());
    }

    @Test
    void typCheckedOnlyAfterTheSignature() {
        // a forged token with a wrong typ reports the signature, not the type
        String token = signRaw(newKey("k1"), JsonUtil.toJson(claims()), "ES256", "JWT", "k1");
        assertEquals(ErrorCodes.INVALID_SIGNATURE, validator().validate(token).error());
    }

    // ── issuer and time ─────────────────────────────────────────────────────────────────────────────

    @Test
    void wrongOrNonStringIssuer() {
        assertEquals(ErrorCodes.INVALID_ISSUER, validator().validate(sign(KEY, claims("iss", "https://evil")))
                .error());
        assertEquals(ErrorCodes.INVALID_ISSUER, validator().validate(sign(KEY, claims("iss", 5))).error());
        assertEquals(ErrorCodes.INVALID_ISSUER, validator().validate(sign(KEY, claims("iss", null))).error());
    }

    @Test
    void missingExpiry() {
        ValidationResult r = validator().validate(sign(KEY, claims("exp", null)));
        assertEquals(ErrorCodes.MISSING_EXPIRY, r.error());
        assertEquals("token has no exp claim", r.errorDescription());
    }

    @Test
    void nonNumericOrNonFiniteDatesAreMalformed() {
        AccessTokenValidator v = validator();
        assertEquals(ErrorCodes.INVALID_TOKEN, v.validate(sign(KEY, claims("exp", "4102444800"))).error());
        assertEquals(ErrorCodes.INVALID_TOKEN, v.validate(sign(KEY, claims("exp", true))).error());
        assertEquals(ErrorCodes.INVALID_TOKEN, v.validate(sign(KEY, claims("nbf", "soon"))).error());
        assertEquals(ErrorCodes.INVALID_TOKEN, v.validate(sign(KEY, claims("iat", List.of(1)))).error());
        String inf = JsonUtil.toJson(claims()).replaceFirst("\"exp\":\\d+", "\"exp\":1e400");
        assertEquals(ErrorCodes.INVALID_TOKEN, v.validate(signRaw(KEY, inf, "ES256", "at+jwt", "k1")).error());
        assertEquals("exp is not a NumericDate", v.validate(sign(KEY, claims("exp", "x"))).errorDescription());
    }

    @Test
    void fractionalDatesTruncateAndHugeOnesAreMalformed() {
        AccessTokenValidator v = validator();
        assertTrue(v.validate(sign(KEY, claims("exp", now() + 300.75))).valid());
        String huge = JsonUtil.toJson(claims()).replaceFirst("\"exp\":\\d+", "\"exp\":123456789012345678901234567890");
        ValidationResult r = v.validate(signRaw(KEY, huge, "ES256", "at+jwt", "k1"));
        assertEquals(ErrorCodes.INVALID_TOKEN, r.error());
        assertEquals("exp is out of range", r.errorDescription());
        String negative = JsonUtil.toJson(claims()).replaceFirst("\"exp\":\\d+", "\"exp\":-123456789012345678901234567890");
        assertEquals(ErrorCodes.INVALID_TOKEN, v.validate(signRaw(KEY, negative, "ES256", "at+jwt", "k1")).error());
        String decimal = JsonUtil.toJson(claims()).replaceFirst("\"exp\":\\d+", "\"exp\":" + (now() + 300) + ".5e0");
        assertTrue(v.validate(signRaw(KEY, decimal, "ES256", "at+jwt", "k1")).valid());
    }

    @Test
    void expiredAndLeeway() {
        long now = now();
        assertEquals(ErrorCodes.EXPIRED, validator().validate(sign(KEY, claims("exp", now - 120))).error());
        assertTrue(validator().validate(sign(KEY, claims("exp", now - 30))).valid());   // inside 60s default
        AccessTokenValidator wide = new AccessTokenValidator(config(KEY).leewaySeconds(300).build());
        assertTrue(wide.validate(sign(KEY, claims("exp", now - 60))).valid());
        AccessTokenValidator none = new AccessTokenValidator(config(KEY).leewaySeconds(0).build());
        assertEquals(ErrorCodes.EXPIRED, none.validate(sign(KEY, claims("exp", now - 5))).error());
    }

    @Test
    void notYetValidAndIssuedInFuture() {
        long now = now();
        assertEquals(ErrorCodes.NOT_YET_VALID,
                validator().validate(sign(KEY, claims("exp", now + 7200, "nbf", now + 3600))).error());
        assertTrue(validator().validate(sign(KEY, claims("nbf", now + 30))).valid());
        assertEquals(ErrorCodes.ISSUED_IN_FUTURE,
                validator().validate(sign(KEY, claims("exp", now + 7200, "iat", now + 3600))).error());
        assertTrue(validator().validate(sign(KEY, claims("iat", now + 30))).valid());
    }

    @Test
    void injectedClockDrivesTime() {
        long t = 2_000_000_000L;
        AccessTokenValidator v = AccessTokenValidator.builder(config(KEY).build()).clock(() -> t * 1000).build();
        assertTrue(v.validate(sign(KEY, claims("exp", t + 10))).valid());
        assertEquals(ErrorCodes.EXPIRED, v.validate(sign(KEY, claims("exp", t - 61))).error());
    }

    // ── audience and scope ──────────────────────────────────────────────────────────────────────────

    @Test
    void audienceAsListAndAnyMatch() {
        ValidationResult r = validator().validate(sign(KEY, claims("aud", List.of("https://other", AUDIENCE))));
        assertTrue(r.valid());
        assertEquals(List.of("https://other", AUDIENCE), r.audience());
        assertEquals(ErrorCodes.INVALID_TOKEN,
                validator().validate(sign(KEY, claims("aud", List.of(AUDIENCE, 7)))).error());
        assertEquals(ErrorCodes.INVALID_AUDIENCE,
                validator().validate(sign(KEY, claims("aud", "https://other"))).error());
        assertEquals(ErrorCodes.INVALID_AUDIENCE, validator().validate(sign(KEY, claims("aud", null))).error());
        assertEquals(ErrorCodes.INVALID_TOKEN, validator().validate(sign(KEY, claims("aud", 42))).error());
        AccessTokenValidator multi = new AccessTokenValidator(ValidatorConfig.builder().issuer(ISSUER)
                .audiences("https://a", AUDIENCE).jwks(Fixtures.jwks(KEY)).build());
        assertTrue(multi.validate(sign(KEY, claims())).valid());
    }

    @Test
    void scopesFromScpArray() {
        ValidationResult r = new AccessTokenValidator(config(KEY).requiredScopes("read").build())
                .validate(sign(KEY, claims("scope", null, "scp", List.of("read", "write"))));
        assertTrue(r.valid());
        assertEquals(List.of("read", "write"), r.scopes());
        assertEquals(ErrorCodes.INVALID_TOKEN,
                validator().validate(sign(KEY, claims("scope", null, "scp", List.of("read", 5)))).error());
    }

    @Test
    void scopeStringWithExtraWhitespace() {
        // RFC 6749 section 3.3: scope tokens are delimited by U+0020 only, so a tab is part of a token
        ValidationResult r = validator().validate(sign(KEY, claims("scope", "  read   write  ")));
        assertEquals(List.of("read", "write"), r.scopes());
        assertEquals(List.of("read\twrite"), validator().validate(sign(KEY, claims("scope", "read\twrite"))).scopes());
    }

    @Test
    void noScopeClaimAtAll() {
        String token = sign(KEY, claims("scope", null));
        ValidationResult r = new AccessTokenValidator(config(KEY).requiredScopes("read").build()).validate(token);
        assertEquals(ErrorCodes.INSUFFICIENT_SCOPE, r.error());
        assertEquals("missing scopes: read", r.errorDescription());
        ValidationResult relaxed = validator().validate(token);
        assertTrue(relaxed.valid());
        assertEquals(List.of(), relaxed.scopes());
    }

    @Test
    void nonStringSubjectIsMalformed() {
        ValidationResult r = validator().validate(sign(KEY, claims("sub", 5)));
        assertEquals(ErrorCodes.INVALID_TOKEN, r.error());
        ValidationResult none = validator().validate(sign(KEY, claims("sub", null)));
        assertNull(none.subject());
    }

    // ── no echo of unverified token data ────────────────────────────────────────────────────────────

    @Test
    void failureMessagesDoNotEchoTokenData() {
        String mark = "EVIL\r\nX-Injected: 1\u0000\u007f\"";
        String markJson = JsonUtil.toJson(Map.of("m", mark)).replace("{\"m\":", "").replace("}", "");
        AccessTokenValidator v = new AccessTokenValidator(config(KEY).requiredScopes("read").build());
        Map<String, String> tokens = new java.util.LinkedHashMap<>();
        tokens.put(ErrorCodes.UNSUPPORTED_ALGORITHM,
                b64("{\"alg\":" + markJson + ",\"kid\":\"k1\"}") + "." + b64("{\"iss\":" + markJson + "}") + ".sig");
        tokens.put(ErrorCodes.KEY_NOT_FOUND, signRaw(KEY, JsonUtil.toJson(claims()), "ES256", "at+jwt", mark));
        tokens.put(ErrorCodes.INVALID_ISSUER, sign(KEY, claims("iss", mark)));
        tokens.put(ErrorCodes.INVALID_AUDIENCE, sign(KEY, claims("aud", mark)));
        tokens.put(ErrorCodes.INVALID_TOKEN, b64("{\"alg\": " + markJson) + "." + b64("{}") + ".sig");
        tokens.put(ErrorCodes.INSUFFICIENT_SCOPE, sign(KEY, claims("scope", mark)));
        for (Map.Entry<String, String> e : tokens.entrySet()) {
            ValidationResult r = v.validate(e.getValue());
            assertEquals(e.getKey(), r.error());
            assertFalse(r.errorDescription().contains("EVIL"), r.errorDescription());
            assertFalse(r.errorDescription().contains("Injected"), r.errorDescription());
        }
    }

    // ── claim helpers ───────────────────────────────────────────────────────────────────────────────

    @Test
    void numericDateTypes() throws Exception {
        assertEquals(7L, Strict.numericDate(Map.of("x", 7), "x"));
        assertEquals(7L, Strict.numericDate(Map.of("x", 7L), "x"));
        assertEquals(7L, Strict.numericDate(Map.of("x", 7.9), "x"));
        assertEquals(-7L, Strict.numericDate(Map.of("x", -7.9), "x"));
        assertThrows(Strict.Malformed.class, () -> Strict.numericDate(Map.of("x", java.math.BigInteger.TEN.pow(30)), "x"));
        assertThrows(Strict.Malformed.class, () -> Strict.numericDate(Map.of("x", Long.MIN_VALUE), "x"));
        assertThrows(Strict.Malformed.class, () -> Strict.numericDate(Map.of("x", 1e300), "x"));
        assertThrows(Strict.Malformed.class, () -> Strict.numericDate(Map.of("x", Double.NaN), "x"));
        assertThrows(Strict.Malformed.class, () -> Strict.numericDate(Map.of("x", 7.5f), "x"));
        assertThrows(Strict.Malformed.class, () -> Strict.numericDate(Map.of("x", "7"), "x"));
        assertNull(Strict.numericDate(Map.of(), "x"));
        assertEquals(List.of(), Strict.audience(Map.of()));
        assertEquals(List.of("read", "write"), Strict.scopes(Map.of("scp", " read  write")));
        assertThrows(Strict.Malformed.class, () -> Strict.scopes(Map.of("scp", 7)));
    }
}
