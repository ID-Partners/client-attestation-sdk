package global.idpartners.clientattestation;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/** What the builders, key import and signer seam refuse to put into a signed credential. */
class CredentialConstructionTest {

    private static final String ISS = "https://attester.example.com";
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder UNB64 = Base64.getUrlDecoder();

    private static Map<String, Object> privateJwk(JsonWebKey key) {
        return new LinkedHashMap<>(key.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
    }

    private static Map<String, Object> ec(java.security.spec.ECParameterSpec curve) {
        try {
            return privateJwk(EcJwkGenerator.generateJwk(curve));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static Map<String, Object> rsa(int bits) {
        try {
            return privateJwk(RsaJwkGenerator.generateJwk(bits));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static Stream<Arguments> nonPublicConfirmationJwks() {
        Map<String, Object> ecPublic = new LinkedHashMap<>(ec(EllipticCurves.P256));
        ecPublic.remove("d");
        Map<String, Object> missingY = new LinkedHashMap<>(ecPublic);
        missingY.remove("y");
        Map<String, Object> badCurve = new LinkedHashMap<>(ecPublic);
        badCurve.put("crv", "secp256k1");
        return Stream.of(
                Arguments.of("EC private", ec(EllipticCurves.P256)),
                Arguments.of("RSA private", rsa(2048)),
                Arguments.of("oct", Map.of("kty", "oct", "k", "c2VjcmV0")),
                Arguments.of("oct without k", Map.of("kty", "oct")),
                Arguments.of("OKP", Map.of("kty", "OKP", "crv", "Ed25519", "x", "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")),
                Arguments.of("EC missing y", missingY),
                Arguments.of("EC bad curve", badCurve));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("nonPublicConfirmationJwks")
    void attestationRefusesPrivateOrSymmetricConfirmationJwk(String name, Map<String, Object> cnf) {
        SigningKeyPair attester = SigningKeyPair.generate("ES256");
        assertThrows(IllegalArgumentException.class, () -> new ClientAttestationBuilder(attester, ISS)
                .clientId("c").confirmationJwk(cnf).expiresIn(Duration.ofMinutes(5)).build());
    }

    @Test
    void attestationConfirmationJwkKeepsOnlyPublicMembers() throws Exception {
        SigningKeyPair attester = SigningKeyPair.generate("ES256");
        SigningKeyPair instance = SigningKeyPair.generate("ES256");
        Map<String, Object> cnf = instance.publicJwk();
        cnf.put("use", "sig");
        cnf.put("x5u", "https://example.com/x5u");
        String token = new ClientAttestationBuilder(attester, ISS)
                .clientId("c").confirmationJwk(cnf).expiresIn(Duration.ofMinutes(5)).build();
        @SuppressWarnings("unchecked")
        Map<String, Object> jwk = (Map<String, Object>) ((Map<String, Object>) JwtTestSupport.claims(token).get("cnf")).get("jwk");
        assertEquals(instance.publicJwk(), jwk);
    }

    @ParameterizedTest
    @ValueSource(strings = {"ES256", "ES384", "ES512", "RS256", "PS256"})
    void dpopJwkIsTheConfirmationJwkWithoutKid(String alg) throws Exception {
        Map<String, Object> source = alg.startsWith("ES")
                ? ec(alg.equals("ES256") ? EllipticCurves.P256 : alg.equals("ES384") ? EllipticCurves.P384 : EllipticCurves.P521)
                : rsa(2048);
        source.put("kid", "caller-label");
        source.put("use", "sig");
        SigningKeyPair instance = SigningKeyPair.fromJwk(source, alg);
        String attestation = new ClientAttestationBuilder(SigningKeyPair.generate("ES256"), ISS)
                .clientId("c").confirmationKey(instance).expiresIn(Duration.ofMinutes(5)).build();
        @SuppressWarnings("unchecked")
        Map<String, Object> cnfJwk = new LinkedHashMap<>((Map<String, Object>) ((Map<String, Object>) JwtTestSupport.claims(attestation).get("cnf")).get("jwk"));
        assertEquals(instance.keyId(), cnfJwk.get("kid"));

        Map<String, Object> header = JwtTestSupport.header(
                new DpopProofBuilder(instance).method("POST").uri("https://as.example.com/token").build());
        assertFalse(header.containsKey("kid"), header.toString());
        @SuppressWarnings("unchecked")
        Map<String, Object> dpopJwk = (Map<String, Object>) header.get("jwk");
        assertFalse(dpopJwk.containsKey("kid"), dpopJwk.toString());
        cnfJwk.remove("kid");
        assertEquals(cnfJwk, dpopJwk);
    }

    static Stream<Arguments> expiriesNotAfterIssuedAt() {
        Function<ClientAttestationBuilder, ClientAttestationBuilder> negative = b -> b.expiresIn(Duration.ofSeconds(-100));
        Function<ClientAttestationBuilder, ClientAttestationBuilder> zero = b -> b.expiresIn(Duration.ZERO);
        Function<ClientAttestationBuilder, ClientAttestationBuilder> before = b -> b
                .issuedAt(Instant.ofEpochSecond(1700000000)).expiresAt(Instant.ofEpochSecond(1699999999));
        return Stream.of(Arguments.of("negative ttl", negative), Arguments.of("zero ttl", zero),
                Arguments.of("exp < iat", before));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("expiriesNotAfterIssuedAt")
    void attestationRefusesExpiryNotAfterIssuedAt(String name, Function<ClientAttestationBuilder, ClientAttestationBuilder> configure) {
        SigningKeyPair attester = SigningKeyPair.generate("ES256");
        SigningKeyPair instance = SigningKeyPair.generate("ES256");
        ClientAttestationBuilder builder = new ClientAttestationBuilder(attester, ISS).clientId("c").confirmationKey(instance);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> configure.apply(builder).build());
        assertTrue(e.getMessage().contains("after iat"), e.getMessage());
    }

    @Test
    void fromJwkPublishesNeitherTheCallersKidNorItsOtherMembers() throws Exception {
        Map<String, Object> jwk = ec(EllipticCurves.P256);
        jwk.put("kid", "label");
        jwk.put("use", "enc");
        jwk.put("x5u", "https://evil.example/x5u");
        SigningKeyPair key = SigningKeyPair.fromJwk(jwk, "ES256");
        assertEquals(List.of("crv", "kid", "kty", "x", "y"), key.publicJwk().keySet().stream().sorted().toList());
        assertEquals(key.keyId(), JwtTestSupport.header(new PopBuilder(key).audience("https://as.example.com").build()).get("kid"));
    }

    private static Map<String, Object> swappedEc() {
        Map<String, Object> jwk = ec(EllipticCurves.P256);
        Map<String, Object> other = ec(EllipticCurves.P256);
        jwk.put("x", other.get("x"));
        jwk.put("y", other.get("y"));
        return jwk;
    }

    private static Map<String, Object> swappedRsa() {
        Map<String, Object> jwk = rsa(2048);
        jwk.put("n", rsa(2048).get("n"));
        return jwk;
    }

    static Stream<Arguments> keysTheAlgorithmCannotUse() {
        return Stream.of(
                Arguments.of("P-384 as ES256", (Supplier<Map<String, Object>>) () -> ec(EllipticCurves.P384), "ES256"),
                Arguments.of("P-256 as ES384", (Supplier<Map<String, Object>>) () -> ec(EllipticCurves.P256), "ES384"),
                Arguments.of("EC as RS256", (Supplier<Map<String, Object>>) () -> ec(EllipticCurves.P256), "RS256"),
                Arguments.of("RSA as ES256", (Supplier<Map<String, Object>>) () -> rsa(2048), "ES256"),
                Arguments.of("RSA-1024 as RS256", (Supplier<Map<String, Object>>) () -> rsa(1024), "RS256"),
                Arguments.of("RSA-1024 as PS256", (Supplier<Map<String, Object>>) () -> rsa(1024), "PS256"),
                Arguments.of("EC x/y of another key", (Supplier<Map<String, Object>>) CredentialConstructionTest::swappedEc, "ES256"),
                Arguments.of("RSA n of another key", (Supplier<Map<String, Object>>) CredentialConstructionTest::swappedRsa, "RS256"),
                Arguments.of("alg none", (Supplier<Map<String, Object>>) () -> ec(EllipticCurves.P256), "none"),
                Arguments.of("alg HS256", (Supplier<Map<String, Object>>) () -> ec(EllipticCurves.P256), "HS256"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("keysTheAlgorithmCannotUse")
    void fromJwkRefusesKeysTheAlgorithmCannotUse(String name, Supplier<Map<String, Object>> jwk, String alg) {
        assertThrows(IllegalArgumentException.class, () -> SigningKeyPair.fromJwk(jwk.get(), alg));
    }

    @Test
    void fromJwkPublishesCanonicalPublicJwk() throws Exception {
        EllipticCurveJsonWebKey shortX;
        do {
            shortX = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        } while (((ECPublicKey) shortX.getPublicKey()).getW().getAffineX().bitLength() > 248);
        Map<String, Object> full = privateJwk(shortX);
        Map<String, Object> shortened = new LinkedHashMap<>(full);
        BigInteger x = ((ECPublicKey) shortX.getPublicKey()).getW().getAffineX();
        byte[] xBytes = x.toByteArray();
        shortened.put("x", B64.encodeToString(xBytes[0] == 0 ? Arrays.copyOfRange(xBytes, 1, xBytes.length) : xBytes));
        SigningKeyPair fromShort = SigningKeyPair.fromJwk(shortened, "ES256");
        assertEquals(32, UNB64.decode((String) fromShort.publicJwk().get("x")).length);
        assertEquals(SigningKeyPair.fromJwk(full, "ES256").keyId(), fromShort.keyId());

        Map<String, Object> minimal = rsa(2048);
        Map<String, Object> padded = new LinkedHashMap<>(minimal);
        byte[] n = UNB64.decode((String) minimal.get("n"));
        byte[] withZero = new byte[n.length + 1];
        System.arraycopy(n, 0, withZero, 1, n.length);
        padded.put("n", B64.encodeToString(withZero));
        SigningKeyPair fromPadded = SigningKeyPair.fromJwk(padded, "RS256");
        assertEquals(minimal.get("n"), fromPadded.publicJwk().get("n"));
        assertEquals(SigningKeyPair.fromJwk(minimal, "RS256").keyId(), fromPadded.keyId());
    }

    private static JwsSigner fixedSigner(String algorithm, byte[] signature) {
        return new JwsSigner() {
            @Override
            public String algorithm() {
                return algorithm;
            }

            @Override
            public String keyId() {
                return "fixed-kid";
            }

            @Override
            public Map<String, Object> publicJwk() {
                return Map.of();
            }

            @Override
            public byte[] sign(byte[] signingInput) {
                return signature;
            }
        };
    }

    static Stream<Arguments> fakeSignatures() {
        byte[] der = new byte[70];
        der[0] = 0x30;
        der[1] = 0x44;
        return Stream.of(
                Arguments.of("alg none, empty signature", "none", new byte[0]),
                Arguments.of("alg HS256", "HS256", new byte[32]),
                Arguments.of("empty ES256 signature", "ES256", new byte[0]),
                Arguments.of("DER ES256 signature", "ES256", der),
                Arguments.of("truncated ES384 signature", "ES384", new byte[64]),
                Arguments.of("empty RS256 signature", "RS256", new byte[0]));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("fakeSignatures")
    void externalSignerMustProduceARealSignature(String name, String alg, byte[] signature) {
        SigningKeyPair instance = SigningKeyPair.generate("ES256");
        assertThrows(RuntimeException.class, () -> new ClientAttestationBuilder(fixedSigner(alg, signature), ISS)
                .clientId("c").confirmationKey(instance).expiresIn(Duration.ofMinutes(1)).build());
    }

    @Test
    void externalSignerWithRawSignatureBuilds() {
        SigningKeyPair instance = SigningKeyPair.generate("ES256");
        assertDoesNotThrow(() -> new ClientAttestationBuilder(fixedSigner("ES256", new byte[64]), ISS)
                .clientId("c").confirmationKey(instance).expiresIn(Duration.ofMinutes(1)).build());
    }

    @ParameterizedTest
    @ValueSource(strings = {"oauth-client-attestation-pop+jwt", "dpop+jwt", "oauth-client-attestation+jwt",
            "application/oauth-client-attestation-pop+jwt", "OAuth-Client-Attestation-PoP+JWT"})
    void mintRequestSignRefusesReservedTyp(String typ) {
        MintRequest request = new MintRequest(SigningKeyPair.generate("ES256"), "svid", null, null, null, null);
        Map<String, Object> claims = Map.of("aud", "https://as.example.com", "jti", "j", "iat", 1);
        assertThrows(IllegalArgumentException.class, () -> request.sign(claims, typ));
        assertThrows(IllegalArgumentException.class, () -> request.instanceProof(typ, "https://as.example.com"));
    }

    @Test
    void mintRequestSignsAProfileTyp() {
        MintRequest request = new MintRequest(SigningKeyPair.generate("ES256"), "svid", null, null, null, null);
        assertDoesNotThrow(() -> request.sign(Map.of("aud", "a"), PingFederateProfile.INSTANCE_PROOF_TYP));
    }
}
