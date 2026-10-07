package global.idpartners.clientattestation;

/**
 * What the attester returned from a mint.
 *
 * @param attestation the Client Attestation (a compact JWT)
 * @param expiresIn   its lifetime in seconds, or {@code null} if the attester did not say
 */
public record MintResult(String attestation, Long expiresIn) {
}
