package global.idpartners.clientattestation;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Where the attester lives and what it expects: what an {@link AttesterProfile} discovers, or what a caller
 * gives directly for an attester that publishes no discovery document.
 *
 * <pre>{@code
 * ClientAttestation ca = ClientAttestation.builder()
 *         .metadata(AttesterMetadata.of("https://attester.example", "https://attester.example/mint",
 *                 "https://as.example/token"))
 *         .build();
 * }</pre>
 *
 * @param evidenceAudience    the audience the workload's platform identity is requested for, and the
 *                            instance proof's {@code aud}; required
 * @param attestationEndpoint where the mint request goes
 * @param tokenEndpoint       the authorization server's token endpoint; a profile fills in its own fallback
 * @param challengeEndpoint   the draft's challenge endpoint, or {@code null} if the attester issues none
 * @param popAudience         the Client Attestation PoP {@code aud} (the AS issuer), or {@code null} for
 *                            the token endpoint URL
 * @param document            the raw discovery document, or {@code null}
 */
public record AttesterMetadata(String evidenceAudience, String attestationEndpoint, String tokenEndpoint,
        String challengeEndpoint, String popAudience, Map<String, Object> document) {

    /**
     * Static metadata with no challenge endpoint and no PoP audience.
     *
     * @param evidenceAudience    the evidence audience
     * @param attestationEndpoint the attestation (mint) endpoint
     * @param tokenEndpoint       the token endpoint
     * @return the metadata
     */
    public static AttesterMetadata of(String evidenceAudience, String attestationEndpoint, String tokenEndpoint) {
        return new AttesterMetadata(evidenceAudience, attestationEndpoint, tokenEndpoint, null, null, null);
    }

    /**
     * A copy with this challenge endpoint.
     *
     * @param challengeEndpoint the challenge endpoint
     * @return the copy
     */
    public AttesterMetadata withChallengeEndpoint(String challengeEndpoint) {
        return new AttesterMetadata(this.evidenceAudience, this.attestationEndpoint, this.tokenEndpoint,
                challengeEndpoint, this.popAudience, this.document);
    }

    /**
     * A copy with this PoP audience.
     *
     * @param popAudience the PoP audience
     * @return the copy
     */
    public AttesterMetadata withPopAudience(String popAudience) {
        return new AttesterMetadata(this.evidenceAudience, this.attestationEndpoint, this.tokenEndpoint,
                this.challengeEndpoint, popAudience, this.document);
    }

    /**
     * The raw discovery document, or, for static metadata, the fields that are set under the discovery
     * document's snake_case names.
     *
     * @return the document
     */
    public Map<String, Object> asDocument() {
        if (this.document != null) {
            return this.document;
        }
        Map<String, Object> doc = new LinkedHashMap<>();
        put(doc, "evidence_audience", this.evidenceAudience);
        put(doc, "attestation_endpoint", this.attestationEndpoint);
        put(doc, "challenge_endpoint", this.challengeEndpoint);
        put(doc, "token_endpoint", this.tokenEndpoint);
        put(doc, "pop_audience", this.popAudience);
        return doc;
    }

    private static void put(Map<String, Object> doc, String key, String value) {
        if (value != null && !value.isBlank()) {
            doc.put(key, value);
        }
    }
}
