package global.idpartners.clientattestation;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

/**
 * Builds a Client Attestation PoP JWT (header {@code typ=oauth-client-attestation-pop+jwt}) proving
 * possession of the instance key bound in the attestation's {@code cnf}. Carries {@code aud} (this AS's
 * identifier), {@code jti}, {@code iat}, an optional {@code iss} (= {@code client_id}) and, when the AS
 * issued one, a {@code challenge}. This is the client side of {@code attest_jwt_client_auth}: mint a fresh
 * PoP per token request and sign it with the client instance key.
 */
public final class PopBuilder {

    static final String TYP = "oauth-client-attestation-pop+jwt";

    private final SigningKeyPair instanceKey;
    private String clientId;
    private String audience;
    private String challenge;
    private String jwtId;
    private Instant issuedAt;

    public PopBuilder(SigningKeyPair instanceKey) {
        this.instanceKey = Objects.requireNonNull(instanceKey, "instanceKey");
    }

    /** Sets the optional {@code iss}; when present the verifier requires it to equal the attestation {@code sub}. */
    public PopBuilder clientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    /** The AS identifier this PoP is bound to ({@code aud}) — required. */
    public PopBuilder audience(String audience) {
        this.audience = audience;
        return this;
    }

    public PopBuilder challenge(String challenge) {
        this.challenge = challenge;
        return this;
    }

    public PopBuilder jwtId(String jwtId) {
        this.jwtId = jwtId;
        return this;
    }

    public PopBuilder issuedAt(Instant issuedAt) {
        this.issuedAt = issuedAt;
        return this;
    }

    public String build() {
        if (this.audience == null || this.audience.isBlank()) {
            throw new IllegalArgumentException("audience (aud) is required");
        }
        JwtClaims claims = new JwtClaims();
        if (this.clientId != null && !this.clientId.isBlank()) {
            claims.setIssuer(this.clientId);
        }
        claims.setAudience(this.audience);
        claims.setJwtId(this.jwtId != null ? this.jwtId : UUID.randomUUID().toString());
        Instant iat = this.issuedAt != null ? this.issuedAt : Instant.now();
        claims.setIssuedAt(NumericDate.fromSeconds(iat.getEpochSecond()));
        if (this.challenge != null && !this.challenge.isBlank()) {
            claims.setClaim("challenge", this.challenge);
        }
        return Jws.sign(claims.toJson(), this.instanceKey, TYP, false);
    }
}
