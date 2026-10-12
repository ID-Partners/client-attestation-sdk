package global.idpartners.clientattestation;

import global.idpartners.clientattestation.internal.SdkLog;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
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
     * {@code typ} may not be one the SDK's own credentials use (the Client Attestation, its PoP, or DPoP): a
     * profile could otherwise have the instance key sign a PoP or DPoP proof with claims of its choosing.
     *
     * @param claims the JWT claims
     * @param typ    the {@code typ} header
     * @return the compact JWS
     * @throws IllegalArgumentException if {@code typ} is one of the SDK's own credential types
     */
    public String sign(Map<String, Object> claims, String typ) {
        if (reservedTyp(typ)) {
            throw new IllegalArgumentException("typ '" + typ + "' is reserved for the SDK's own credentials;"
                    + " a profile cannot sign it with the instance key");
        }
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

    /**
     * Whether {@code typ} names one of the SDK's own credential types, compared as RFC 7515 section 4.1.9 says
     * a verifier may: case-insensitively, with or without the {@code application/} prefix.
     */
    private static boolean reservedTyp(String typ) {
        String t = String.valueOf(typ).strip().toLowerCase(Locale.ROOT);
        if (t.startsWith("application/")) {
            t = t.substring("application/".length());
        }
        return t.equals(ClientAttestationBuilder.TYP) || t.equals(PopBuilder.TYP) || t.equals(DpopProofBuilder.TYP);
    }

    /** Leaves the evidence and the challenge out (their lengths only), so a logged request logs neither. */
    @Override
    public String toString() {
        return "MintRequest[instanceKey=" + this.instanceKey + ", evidence=" + SdkLog.redacted(this.evidence)
                + ", challenge=" + SdkLog.redacted(this.challenge) + ", clientId=" + this.clientId
                + ", authorizationDetails=" + this.authorizationDetails + ", operator=" + this.operator + "]";
    }
}
