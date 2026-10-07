package global.idpartners.clientattestation;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jose4j.json.JsonUtil;

/**
 * Everything an {@link AttesterProfile} needs to mint one attestation.
 *
 * @param instanceKey          the fresh key the attestation will be bound to (its {@code cnf})
 * @param evidence             the workload's platform identity token (a JWT-SVID or equivalent)
 * @param challenge            the attester-issued challenge, or {@code null}
 * @param clientId             set by {@link AttestationIssuanceClient}; {@code null} in the evidence-first
 *                             one-call flow, where the attester maps the identity to a client
 * @param authorizationDetails optional RFC 9396 access request, or {@code null}
 * @param operator             optional operator object (who answers for this workload), or {@code null}
 */
public record MintRequest(SigningKeyPair instanceKey, String evidence, String challenge, String clientId,
        List<Map<String, Object>> authorizationDetails, Map<String, Object> operator) {

    /**
     * Signs {@code claims} as a compact JWS with the instance key, under header {@code typ} (no {@code jwk}).
     *
     * @param claims the JWT claims
     * @param typ    the {@code typ} header
     * @return the compact JWS
     */
    public String sign(Map<String, Object> claims, String typ) {
        return Jws.sign(JsonUtil.toJson(claims), this.instanceKey, typ, false);
    }

    /**
     * A proof of possession of the instance key: {@code {aud, jti, iat[, challenge]}} signed with it.
     *
     * @param typ      the {@code typ} header
     * @param audience the {@code aud} claim
     * @return the compact JWS
     */
    public String instanceProof(String typ, String audience) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("aud", audience);
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("iat", System.currentTimeMillis() / 1000L);
        if (this.challenge != null && !this.challenge.isBlank()) {
            claims.put("challenge", this.challenge);
        }
        return sign(claims, typ);
    }
}
