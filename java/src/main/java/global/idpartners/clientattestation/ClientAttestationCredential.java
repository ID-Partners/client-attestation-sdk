package global.idpartners.clientattestation;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * A client's attestation credential: the Attester-issued attestation JWT plus the instance key it is bound
 * to. Produces the request headers for a token call — dedicated PoP-JWT mode or DPoP combined mode —
 * minting a fresh proof of possession each time.
 */
public final class ClientAttestationCredential {

    public static final String ATTESTATION_HEADER = "OAuth-Client-Attestation";
    public static final String POP_HEADER = "OAuth-Client-Attestation-PoP";
    public static final String DPOP_HEADER = "DPoP";

    private final String attestationJwt;
    private final SigningKeyPair instanceKey;

    public ClientAttestationCredential(String attestationJwt, SigningKeyPair instanceKey) {
        this.attestationJwt = requireText(attestationJwt, "attestationJwt");
        this.instanceKey = Objects.requireNonNull(instanceKey, "instanceKey");
    }

    /**
     * Headers for dedicated PoP-JWT mode (PoP method {@code attestation_pop_jwt}):
     * {@code OAuth-Client-Attestation} + {@code OAuth-Client-Attestation-PoP}.
     *
     * @param clientId  the client id (PoP {@code iss}); may be null to omit
     * @param audience  the AS identifier (PoP {@code aud}); required
     * @param challenge the server challenge, or null
     */
    public Map<String, String> popHeaders(String clientId, String audience, String challenge) {
        String pop = new PopBuilder(this.instanceKey)
                .clientId(clientId)
                .audience(audience)
                .challenge(challenge)
                .build();
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(ATTESTATION_HEADER, this.attestationJwt);
        headers.put(POP_HEADER, pop);
        return headers;
    }

    /**
     * Headers for DPoP combined mode (PoP method {@code dpop_combined}):
     * {@code OAuth-Client-Attestation} + {@code DPoP} (and no PoP header).
     *
     * @param method    the token request HTTP method (DPoP {@code htm})
     * @param uri       the token endpoint URL (DPoP {@code htu}); required
     * @param challenge the server challenge (DPoP {@code nonce}), or null
     */
    public Map<String, String> dpopHeaders(String method, String uri, String challenge) {
        String dpop = new DpopProofBuilder(this.instanceKey)
                .method(method)
                .uri(uri)
                .nonce(challenge)
                .build();
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(ATTESTATION_HEADER, this.attestationJwt);
        headers.put(DPOP_HEADER, dpop);
        return headers;
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value;
    }
}
