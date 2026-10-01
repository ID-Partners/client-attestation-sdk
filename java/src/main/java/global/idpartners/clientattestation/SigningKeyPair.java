package global.idpartners.clientattestation;

import java.security.PrivateKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
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

    private SigningKeyPair(PublicJsonWebKey jwk, String algorithm) {
        this.jwk = Objects.requireNonNull(jwk, "jwk");
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.publicParams = jwk.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
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

    /** Wraps an existing jose4j JWK (which must contain the private key) for the given algorithm. */
    public static SigningKeyPair fromJwk(PublicJsonWebKey jwk, String algorithm) {
        if (jwk.getPrivateKey() == null) {
            throw new IllegalArgumentException("JWK does not contain a private key");
        }
        return new SigningKeyPair(jwk, algorithm);
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
     * {@code cnf.jwk} or a DPoP {@code jwk} header value.
     */
    public Map<String, Object> publicJwk() {
        return new LinkedHashMap<>(this.publicParams);
    }

    /**
     * The public-only key as a jose4j {@link JsonWebKey} — e.g. to embed in a DPoP {@code jwk} header
     * or to register with a verifier's attester-key resolver.
     */
    public JsonWebKey publicJsonWebKey() {
        try {
            return Jwks.fromMap(publicJwk());
        } catch (JoseException e) {
            throw new IllegalStateException("Unable to derive public JWK", e);
        }
    }
}
