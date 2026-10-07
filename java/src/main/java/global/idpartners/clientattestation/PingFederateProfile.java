package global.idpartners.clientattestation;

import java.util.LinkedHashMap;
import java.util.Map;
import org.jose4j.json.JsonUtil;

/**
 * The attester this SDK was built against (PingFederate), and the default {@link AttesterProfile}.
 *
 * <ul>
 * <li>Discovery: {@code GET {attesterUrl}/.well-known/client-attester}, a JSON object with
 * {@code evidence_audience}, {@code attestation_endpoint}, {@code challenge_endpoint}, {@code token_endpoint}
 * and {@code pop_audience}. With no {@code token_endpoint}, {@code {attesterUrl}/as/token.oauth2}.</li>
 * <li>Mint: {@code POST attestation_endpoint} with JSON {@code {[client_id,] instance_key, svid, proof
 * [, authorization_details][, operator]}}, where {@code proof} is {@code {aud: evidence_audience, jti, iat
 * [, challenge]}} signed by the instance key with {@code typ} {@code oauth-attestation-instance-proof+jwt}. The
 * response is {@code {"attestation": ..., "expires_in": ...}}.</li>
 * </ul>
 */
public final class PingFederateProfile implements AttesterProfile {

    /** The discovery document path. */
    public static final String WELL_KNOWN_PATH = "/.well-known/client-attester";
    /** The instance-key proof {@code typ} (server InstanceKeyProofValidator.TYP). */
    public static final String INSTANCE_PROOF_TYP = "oauth-attestation-instance-proof+jwt";
    /** The token endpoint path used when discovery names none. */
    public static final String DEFAULT_TOKEN_PATH = "/as/token.oauth2";

    /** The PingFederate profile. */
    public PingFederateProfile() {
    }

    @Override
    public AttesterMetadata discover(AttesterTransport transport, String attesterUrl) throws Exception {
        if (attesterUrl == null || attesterUrl.isBlank()) {
            throw new IllegalArgumentException("attesterUrl is required for discovery");
        }
        Map<String, Object> doc = transport.requestJson("discover", "GET", attesterUrl + WELL_KNOWN_PATH, null);
        // token_endpoint is advertised by current attesters; fall back to the standard PF path so an older
        // discovery document still works from the host alone.
        String tokenEndpoint = optString(doc, "token_endpoint");
        return new AttesterMetadata(optString(doc, "evidence_audience"), optString(doc, "attestation_endpoint"),
                tokenEndpoint != null ? tokenEndpoint : attesterUrl + DEFAULT_TOKEN_PATH,
                optString(doc, "challenge_endpoint"), optString(doc, "pop_audience"), doc);
    }

    @Override
    public MintResult mint(AttesterTransport transport, AttesterMetadata metadata, MintRequest request)
            throws Exception {
        String endpoint = metadata.attestationEndpoint();
        if (endpoint == null || endpoint.isBlank()) {
            throw new ClientAttestation.ClientAttestationException(
                    "attester discovery document has no attestation_endpoint");
        }
        String proof = request.instanceProof(INSTANCE_PROOF_TYP, metadata.evidenceAudience());

        Map<String, Object> body = new LinkedHashMap<>();
        if (request.clientId() != null && !request.clientId().isEmpty()) {
            body.put("client_id", request.clientId());
        }
        body.put("instance_key", request.instanceKey().publicJwk());
        body.put("svid", request.evidence());
        body.put("proof", proof);
        if (request.authorizationDetails() != null && !request.authorizationDetails().isEmpty()) {
            body.put("authorization_details", request.authorizationDetails());
        }
        if (request.operator() != null && !request.operator().isEmpty()) {
            // The client's OPERATOR, asked for at mint time so the ATTESTER is what states it, rather than the
            // client asserting it about itself at the token endpoint. An attester that does not know this key
            // ignores it.
            body.put("operator", request.operator());
        }
        Map<String, Object> response = transport.requestJson("mint", "POST", endpoint, body);
        if (!(response.get("attestation") instanceof String attestation) || attestation.isBlank()) {
            throw new ClientAttestation.ClientAttestationException("attester response contained no attestation",
                    0, JsonUtil.toJson(response));
        }
        Object expiresIn = response.get("expires_in");
        return new MintResult(attestation, expiresIn instanceof Number n ? n.longValue() : null);
    }

    private static String optString(Map<String, Object> map, String key) {
        Object v = map.get(key);
        return v != null && !String.valueOf(v).isBlank() ? String.valueOf(v) : null;
    }
}
