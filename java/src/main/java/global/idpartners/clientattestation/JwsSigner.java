package global.idpartners.clientattestation;

import java.util.Map;

/**
 * A JWS signing capability whose private key may live outside the JVM (an HSM, a vault, a KMS).
 * The signer produces the raw JWS signature bytes over the JWS signing input
 * ({@code BASE64URL(header) || '.' || BASE64URL(payload)}); for ECDSA algorithms that is the
 * fixed-width {@code r||s} concatenation RFC 7515 requires, not ASN.1/DER.
 *
 * <p>{@link SigningKeyPair} covers the local-key case; {@link OpenBaoTransitSigner} signs via an
 * OpenBao/Vault transit engine so the attester's private key never leaves the vault.
 */
public interface JwsSigner {

    /** The JWS {@code alg} this signer produces (e.g. {@code ES256}). */
    String algorithm();

    /** The {@code kid} to place in the JWS header (and under which verifiers know the public key). */
    String keyId();

    /**
     * The public-only JWK (including {@code kid}) as a JSON-ready map — what a verifier needs to
     * register this signer's key (e.g. in an attester-key resolver or a federation entity statement).
     */
    Map<String, Object> publicJwk();

    /** Signs the JWS signing input, returning the raw JWS signature bytes. */
    byte[] sign(byte[] signingInput);
}
