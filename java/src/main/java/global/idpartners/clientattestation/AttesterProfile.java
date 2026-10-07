package global.idpartners.clientattestation;

/**
 * The attester-specific part of the flow.
 *
 * <p>The draft says what a Client Attestation, its PoP and the challenge endpoint look like, and how they are
 * presented at the token endpoint. It does not say how a workload gets an attestation from its attester. That
 * part (where the attester's endpoints are listed, what the mint request looks like, how the instance key is
 * proven, and what comes back) is an attester profile.
 *
 * <p>{@link ClientAttestation} and {@link AttestationIssuanceClient} use {@link PingFederateProfile} unless
 * told otherwise, which is exactly the behaviour of earlier releases. Implement this interface for another
 * attester and pass it with {@link ClientAttestation.Builder#profile(AttesterProfile)}. See
 * docs/attester-profiles.md.
 *
 * <p><b>Experimental</b> (see docs/api.md): new in 0.4.0 and fitted to one real attester so far; a method
 * added to it would break custom profiles. {@link AttesterTransport}, {@link MintRequest} and
 * {@link MintResult} are Experimental with it.
 */
public interface AttesterProfile {

    /**
     * Finds the attester's endpoints. Called once per client and cached; not called when the caller passes
     * static metadata ({@link ClientAttestation.Builder#metadata(AttesterMetadata)}).
     *
     * @param transport   the client's transport, for any calls this makes
     * @param attesterUrl the normalised attester URL, or {@code null} when none was given
     * @return the attester's metadata
     * @throws Exception if discovery fails
     */
    AttesterMetadata discover(AttesterTransport transport, String attesterUrl) throws Exception;

    /**
     * Exchanges the evidence and a proof of the instance key for an attestation.
     *
     * @param transport the client's transport, for any calls this makes
     * @param metadata  the attester's metadata
     * @param request   the instance key, evidence, challenge and optional request members
     * @return the attestation and its lifetime
     * @throws Exception if minting fails
     */
    MintResult mint(AttesterTransport transport, AttesterMetadata metadata, MintRequest request) throws Exception;
}
