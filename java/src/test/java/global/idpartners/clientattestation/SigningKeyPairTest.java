package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * {@link SigningKeyPair} unit coverage: every supported algorithm, unsupported-algorithm rejection, and the
 * {@code fromJwk} wrap path (round-trip, missing-private-part and algorithm/key mismatch rejection).
 */
class SigningKeyPairTest {

    @ParameterizedTest
    @ValueSource(strings = {"ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"})
    void generateSupportsAllAdvertisedAlgorithms(String algorithm) {
        SigningKeyPair key = SigningKeyPair.generate(algorithm);
        assertEquals(algorithm, key.algorithm());
        assertNotNull(key.keyId());
        Map<String, Object> jwk = key.publicJwk();
        assertEquals(key.keyId(), jwk.get("kid"));
        assertFalse(jwk.containsKey("d"), "publicJwk must not leak the private part");
        assertEquals(algorithm.startsWith("ES") ? "EC" : "RSA", jwk.get("kty"));
        assertNotNull(key.privateKey());
        assertNotNull(key.publicJsonWebKey());
    }

    @Test
    void unsupportedAlgorithmIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> SigningKeyPair.generate("HS256"));
        assertTrue(e.getMessage().contains("HS256"));
        assertThrows(IllegalArgumentException.class, () -> SigningKeyPair.generate("EdDSA"));
        assertThrows(IllegalArgumentException.class, () -> SigningKeyPair.generate("none"));
    }

    @Test
    void fromJwkRoundTrips() throws Exception {
        EllipticCurveJsonWebKey jose4jKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        SigningKeyPair key = SigningKeyPair.fromJwk(jose4jKey, "ES256");
        assertEquals("ES256", key.algorithm());
        assertEquals(Jwks.thumbprint(key.publicJwk()), key.keyId(), "kid must be the RFC 7638 thumbprint");
        // The wrapped key must actually sign: mint and decode a PoP.
        String pop = new PopBuilder(key).audience("https://as.example.com").build();
        Map<String, Object> header = JwtTestSupport.header(pop);
        assertEquals("ES256", header.get("alg"));
        assertEquals(key.keyId(), header.get("kid"));
    }

    @Test
    void fromJwkRejectsPublicOnlyKey() throws Exception {
        EllipticCurveJsonWebKey jose4jKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        PublicJsonWebKey publicOnly = PublicJsonWebKey.Factory.newPublicJwk(
                jose4jKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> SigningKeyPair.fromJwk(publicOnly, "ES256"));
        assertTrue(e.getMessage().contains("private key"));
    }

    @Test
    void publicJwkIsADefensiveCopy() {
        SigningKeyPair key = SigningKeyPair.generate("ES256");
        Map<String, Object> jwk = key.publicJwk();
        jwk.put("kid", "tampered");
        assertEquals(key.keyId(), key.publicJwk().get("kid"), "mutating the returned map must not leak back");
    }

    @Test
    void algorithmKeyMismatchIsRefusedAtImport() throws Exception {
        // An EC key wrapped with an RSA alg used to pass fromJwk and fail only when signing.
        EllipticCurveJsonWebKey jose4jKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> SigningKeyPair.fromJwk(jose4jKey, "RS256"));
        assertTrue(e.getMessage().contains("needs an RSA key"));
    }

    @Test
    void loadsAPrivateJwkFromAMap() throws Exception {
        EllipticCurveJsonWebKey generated = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        Map<String, Object> params = generated.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
        SigningKeyPair key = SigningKeyPair.fromJwk(params, "ES256");
        assertEquals("ES256", key.algorithm());
        assertEquals(SigningKeyPair.fromJwk((PublicJsonWebKey) generated, "ES256").keyId(), key.keyId());
        assertThrows(IllegalArgumentException.class, () -> SigningKeyPair.fromJwk(Map.of("kty", "nope"), "ES256"));
        Map<String, Object> publicOnly = generated.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        assertThrows(IllegalArgumentException.class, () -> SigningKeyPair.fromJwk(publicOnly, "ES256"));
    }
}
