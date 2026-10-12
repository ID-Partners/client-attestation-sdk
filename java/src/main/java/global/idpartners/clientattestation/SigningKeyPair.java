package global.idpartners.clientattestation;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;

/**
 * A signing key pair (public + private) expressed as a JWK, carrying its JWS
 * {@code alg} and RFC 7638 thumbprint {@code kid}. Used both as the client
 * instance key — which signs PoP / DPoP proofs and is bound into an
 * attestation's {@code cnf} — and as a Client Attester's issuing key.
 */
public final class SigningKeyPair {

    private final PublicJsonWebKey jwk;
    private final String algorithm;
    private final String keyId;
    private final Map<String, Object> publicParams;

    /** The JWS algorithms the SDK signs with, locally or through an external {@link JwsSigner}. */
    static final Set<String> SIGNING_ALGORITHMS =
            Set.of("ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512");

    /** The smallest RSA modulus the SDK signs with. */
    private static final int MIN_RSA_BITS = 2048;

    private SigningKeyPair(PublicJsonWebKey jwk, String algorithm) {
        this.jwk = Objects.requireNonNull(jwk, "jwk");
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        // Rebuilt from the key alone, so none of the caller's members (kid, alg, use, x5u, ...) is published.
        try {
            this.publicParams = PublicJsonWebKey.Factory.newPublicJwk(jwk.getPublicKey())
                    .toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        } catch (JoseException e) {
            throw new IllegalStateException("Unable to derive public JWK", e);
        }
        try {
            this.keyId = Jwks.thumbprint(this.publicParams);
        } catch (JoseException e) {
            throw new IllegalStateException("Unable to compute key thumbprint", e);
        }
        this.publicParams.put("kid", this.keyId);
        this.jwk.setKeyId(this.keyId);
    }

    /**
     * Generates a fresh key pair for the given JWS algorithm: {@code ES256/384/512} (EC P-256/384/521)
     * or {@code RS256/384/512} / {@code PS256/384/512} (RSA 2048).
     */
    public static SigningKeyPair generate(String algorithm) {
        try {
            PublicJsonWebKey generated = switch (algorithm) {
                case "ES256" -> EcJwkGenerator.generateJwk(EllipticCurves.P256);
                case "ES384" -> EcJwkGenerator.generateJwk(EllipticCurves.P384);
                case "ES512" -> EcJwkGenerator.generateJwk(EllipticCurves.P521);
                case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512" -> RsaJwkGenerator.generateJwk(2048);
                default -> throw new IllegalArgumentException("Unsupported signing algorithm: " + algorithm);
            };
            return new SigningKeyPair(generated, algorithm);
        } catch (JoseException e) {
            throw new IllegalStateException("Unable to generate a " + algorithm + " key", e);
        }
    }

    /**
     * Loads a private JWK, as a JSON object map (the shape {@link #publicJwk()} returns, plus the private
     * members), for the given algorithm.
     *
     * @param jwk       the JWK members, including the private key ({@code d}, and for RSA the CRT members)
     * @param algorithm the JWS algorithm the key signs with, e.g. {@code ES256}
     * @return the key pair
     * @throws IllegalArgumentException if the map is not a JWK or has no private key, or the key does not suit
     *                                  the algorithm (see {@link #fromJwk(PublicJsonWebKey, String)})
     */
    public static SigningKeyPair fromJwk(Map<String, Object> jwk, String algorithm) {
        PublicJsonWebKey parsed;
        try {
            parsed = PublicJsonWebKey.Factory.newPublicJwk(Objects.requireNonNull(jwk, "jwk"));
        } catch (JoseException e) {
            throw new IllegalArgumentException("not a usable JWK: " + e.getMessage(), e);
        }
        return fromJwk(parsed, algorithm);
    }

    /**
     * Wraps an existing jose4j JWK (which must contain the private key) for the given algorithm.
     *
     * <p>The key must suit the algorithm: an EC key on its curve for {@code ES256/384/512} (P-256/384/521),
     * an RSA key of at least 2048 bits for {@code RS256/384/512} and {@code PS256/384/512}, and its public
     * members must belong to its private key. Only the key material is kept: the published JWK is
     * re-encoded canonically and its {@code kid} is the RFC 7638 thumbprint, whatever {@code kid} or other
     * members the input had.
     *
     * <p><b>Experimental</b> (see docs/api.md): it takes a jose4j type, which ties this signature to jose4j.
     * {@link #fromJwk(Map, String)} is the Stable way to load a key.
     *
     * @param jwk       the jose4j JWK, with its private key
     * @param algorithm the JWS algorithm the key signs with
     * @return the key pair
     */
    public static SigningKeyPair fromJwk(PublicJsonWebKey jwk, String algorithm) {
        if (jwk.getPrivateKey() == null) {
            throw new IllegalArgumentException("JWK does not contain a private key");
        }
        checkKeyForAlgorithm(jwk, algorithm);
        return new SigningKeyPair(jwk, algorithm);
    }

    /**
     * Refuses a key the algorithm can't sign with (wrong type, wrong curve, RSA under 2048 bits) and a key
     * whose public half is not its private key's: signing with one key while advertising another (as
     * {@code kid}, {@code cnf.jwk} or the DPoP {@code jwk}) gives credentials no verifier accepts.
     */
    private static void checkKeyForAlgorithm(PublicJsonWebKey jwk, String algorithm) {
        if (algorithm == null || !SIGNING_ALGORITHMS.contains(algorithm)) {
            throw new IllegalArgumentException("Unsupported signing algorithm: " + algorithm);
        }
        String verifier;
        if (algorithm.startsWith("ES")) {
            String curve = switch (algorithm) {
                case "ES256" -> EllipticCurves.P_256;
                case "ES384" -> EllipticCurves.P_384;
                default -> EllipticCurves.P_521;
            };
            if (!(jwk instanceof EllipticCurveJsonWebKey ec)) {
                throw new IllegalArgumentException(algorithm + " needs an EC key, not kty " + jwk.getKeyType());
            }
            if (!curve.equals(ec.getCurveName())) {
                throw new IllegalArgumentException(algorithm + " needs an EC key on " + curve);
            }
            verifier = "SHA256withECDSA";
        } else {
            if (!(jwk instanceof RsaJsonWebKey rsa)) {
                throw new IllegalArgumentException(algorithm + " needs an RSA key, not kty " + jwk.getKeyType());
            }
            if (((RSAPublicKey) rsa.getPublicKey()).getModulus().bitLength() < MIN_RSA_BITS) {
                throw new IllegalArgumentException("RSA keys must be at least " + MIN_RSA_BITS + " bits");
            }
            verifier = "SHA256withRSA";
        }
        byte[] probe = "client-attestation-sdk key pair check".getBytes(StandardCharsets.US_ASCII);
        boolean matches;
        try {
            Signature signer = Signature.getInstance(verifier);
            signer.initSign(jwk.getPrivateKey());
            signer.update(probe);
            byte[] signature = signer.sign();
            Signature check = Signature.getInstance(verifier);
            check.initVerify(jwk.getPublicKey());
            check.update(probe);
            matches = check.verify(signature);
        } catch (GeneralSecurityException | RuntimeException e) {
            matches = false;
        }
        if (!matches) {
            throw new IllegalArgumentException("The JWK's public key does not match its private key");
        }
    }

    public String algorithm() {
        return this.algorithm;
    }

    public String keyId() {
        return this.keyId;
    }

    PrivateKey privateKey() {
        return this.jwk.getPrivateKey();
    }

    /**
     * The public-only JWK (including {@code kid}) as a JSON-ready map — suitable as an attestation
     * {@code cnf.jwk}. A DPoP proof's {@code jwk} header carries the same members without {@code kid}.
     */
    public Map<String, Object> publicJwk() {
        return new LinkedHashMap<>(this.publicParams);
    }

    /**
     * The public-only key (including {@code kid}) as a jose4j {@link JsonWebKey} — e.g. to register with a
     * verifier's attester-key resolver.
     *
     * <p><b>Experimental</b> (see docs/api.md): it returns a jose4j type. {@link #publicJwk()} is Stable.
     *
     * @return the public key as a jose4j JWK
     */
    public JsonWebKey publicJsonWebKey() {
        try {
            return Jwks.fromMap(publicJwk());
        } catch (JoseException e) {
            throw new IllegalStateException("Unable to derive public JWK", e);
        }
    }
}
