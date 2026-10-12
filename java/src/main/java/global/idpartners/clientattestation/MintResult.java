package global.idpartners.clientattestation;

import global.idpartners.clientattestation.internal.SdkLog;

/**
 * What the attester returned from a mint.
 *
 * @param attestation the Client Attestation (a compact JWT)
 * @param expiresIn   its lifetime in seconds, or {@code null} if the attester did not say
 */
public record MintResult(String attestation, Long expiresIn) {

    /** Leaves the attestation out (its length only), so a logged result logs no credential. */
    @Override
    public String toString() {
        return "MintResult[attestation=" + SdkLog.redacted(this.attestation) + ", expiresIn=" + this.expiresIn
                + "]";
    }
}
