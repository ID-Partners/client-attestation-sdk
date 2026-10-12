package global.idpartners.clientattestation;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

/**
 * Builds a Client Attestation JWT (header {@code typ=oauth-client-attestation+jwt}) — the credential a
 * Client Attester issues to name a client ({@code sub} = {@code client_id}) and bind its instance key via
 * the RFC 7800 {@code cnf.jwk} claim, per draft-ietf-oauth-attestation-based-client-auth. This is the
 * <em>attester</em> side: a client never mints its own attestation. Sign with the attester's issuing key.
 */
public final class ClientAttestationBuilder {

    static final String TYP = "oauth-client-attestation+jwt";

    private final SigningKeyPair attesterKey;
    private final JwsSigner attesterSigner;
    private final String issuer;
    private String clientId;
    private Map<String, Object> confirmationJwk;
    private Instant issuedAt;
    private Instant expiresAt;
    private Duration ttl;
    private List<Map<String, Object>> authorizationDetails;
    private Map<String, Object> workload;
    private Map<String, Object> operator;

    /**
     * @param attesterKey the attester's issuing key (signs the attestation)
     * @param issuer      the attester entity identifier ({@code iss})
     */
    public ClientAttestationBuilder(SigningKeyPair attesterKey, String issuer) {
        this.attesterKey = Objects.requireNonNull(attesterKey, "attesterKey");
        this.attesterSigner = null;
        this.issuer = requireText(issuer, "issuer");
    }

    /**
     * As {@link #ClientAttestationBuilder(SigningKeyPair, String)}, but signing through an external
     * {@link JwsSigner} (e.g. {@link OpenBaoTransitSigner}) so the attester's private key never enters
     * this JVM.
     */
    public ClientAttestationBuilder(JwsSigner attesterSigner, String issuer) {
        this.attesterKey = null;
        this.attesterSigner = Objects.requireNonNull(attesterSigner, "attesterSigner");
        this.issuer = requireText(issuer, "issuer");
    }

    /** The client being attested — becomes the attestation {@code sub} (= {@code client_id}). */
    public ClientAttestationBuilder clientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    /**
     * Binds the client instance key as {@code cnf.jwk}: an EC ({@code crv} P-256, P-384 or P-521, {@code x},
     * {@code y}) or RSA ({@code n}, {@code e}) public key. Only those members and an optional {@code kid} are
     * copied into the attestation.
     *
     * @throws IllegalArgumentException if the JWK carries private or secret members ({@code d}, {@code p},
     *                                  {@code q}, {@code dp}, {@code dq}, {@code qi}, {@code oth}, {@code k}),
     *                                  is another {@code kty} or curve, or lacks a member
     */
    public ClientAttestationBuilder confirmationJwk(Map<String, Object> publicInstanceJwk) {
        this.confirmationJwk = publicConfirmationJwk(publicInstanceJwk);
        return this;
    }

    /** Convenience: binds the public half of the given instance key as {@code cnf.jwk}. */
    public ClientAttestationBuilder confirmationKey(SigningKeyPair instanceKey) {
        return confirmationJwk(instanceKey.publicJwk());
    }

    public ClientAttestationBuilder issuedAt(Instant issuedAt) {
        this.issuedAt = issuedAt;
        return this;
    }

    /** Sets an absolute {@code exp}. */
    public ClientAttestationBuilder expiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
        return this;
    }

    /** Sets {@code exp} to {@code iat + ttl}. */
    public ClientAttestationBuilder expiresIn(Duration ttl) {
        this.ttl = ttl;
        return this;
    }

    /** The optional RFC 9396 {@code authorization_details} entitlement the attester asserts for this client. */
    public ClientAttestationBuilder authorizationDetails(List<Map<String, Object>> authorizationDetails) {
        this.authorizationDetails = authorizationDetails;
        return this;
    }

    /** Optional attester-asserted {@code workload} attributes. */
    public ClientAttestationBuilder workload(Map<String, Object> workload) {
        this.workload = workload;
        return this;
    }

    /**
     * Names the client's OPERATOR — the human or organisation accountable for running this client,
     * as distinct from the client itself ({@code sub}) and from the principal it acts for.
     *
     * <p>Deliberately a top-level claim rather than a member of {@code workload}: {@code workload}
     * describes the running software, whereas the operator is an accountability statement about who
     * answers for it. It is per-client and static, so it does not affect how far an attestation can
     * be cached.
     *
     * <p>The shape mirrors RFC 8693 {@code may_act} ({@code {"sub": ..., "iss": ...}}) on purpose. An
     * AS that wants the operator to become the party authorised to act for the subject can lift this
     * straight into {@code may_act}; {@code iss} names the OP the operator's {@code sub} is
     * meaningful in, so the identifier is not ambiguous across directories.
     *
     * <p>This is an ASSERTION by the attester, not proof the operator authorised anything. A relying
     * AS should treat it as it treats the rest of the attestation: trusted exactly as far as the
     * attester is.
     *
     * @param sub    the operator's subject identifier — required, non-blank
     * @param issuer the OP the operator's {@code sub} is meaningful in; optional
     */
    public ClientAttestationBuilder operator(String sub, String issuer) {
        Map<String, Object> op = new LinkedHashMap<>();
        op.put("sub", requireText(sub, "operator sub"));
        if (issuer != null && !issuer.isBlank()) {
            op.put("iss", issuer);
        }
        this.operator = op;
        return this;
    }

    public String build() {
        String sub = requireText(this.clientId, "clientId");
        Map<String, Object> cnfJwk = Objects.requireNonNull(this.confirmationJwk, "confirmation key (cnf.jwk) is required");
        Instant iat = this.issuedAt != null ? this.issuedAt : Instant.now();
        Instant exp = resolveExpiry(iat);

        JwtClaims claims = new JwtClaims();
        claims.setIssuer(this.issuer);
        claims.setSubject(sub);
        claims.setIssuedAt(NumericDate.fromSeconds(iat.getEpochSecond()));
        claims.setExpirationTime(NumericDate.fromSeconds(exp.getEpochSecond()));
        Map<String, Object> cnf = new LinkedHashMap<>();
        cnf.put("jwk", cnfJwk);
        claims.setClaim("cnf", cnf);
        if (this.authorizationDetails != null && !this.authorizationDetails.isEmpty()) {
            claims.setClaim("authorization_details", this.authorizationDetails);
        }
        if (this.workload != null && !this.workload.isEmpty()) {
            claims.setClaim("workload", this.workload);
        }
        if (this.operator != null && !this.operator.isEmpty()) {
            claims.setClaim("operator", this.operator);
        }
        return this.attesterSigner != null
                ? Jws.sign(claims.toJson(), this.attesterSigner, TYP)
                : Jws.sign(claims.toJson(), this.attesterKey, TYP, false);
    }

    private Instant resolveExpiry(Instant iat) {
        Instant exp;
        if (this.expiresAt != null) {
            exp = this.expiresAt;
        } else if (this.ttl != null) {
            exp = iat.plus(this.ttl);
        } else {
            throw new IllegalStateException("expiry is required: call expiresAt(...) or expiresIn(...)");
        }
        // Compared as the claims carry them: whole epoch seconds.
        if (exp.getEpochSecond() <= iat.getEpochSecond()) {
            throw new IllegalArgumentException("attestation exp (" + exp.getEpochSecond()
                    + ") must be after iat (" + iat.getEpochSecond() + ")");
        }
        return exp;
    }

    /** JWK members that carry private or secret key material (RFC 7518 section 6). */
    private static final List<String> PRIVATE_JWK_MEMBERS = List.of("d", "p", "q", "dp", "dq", "qi", "oth", "k");

    /**
     * The public key to bind as {@code cnf.jwk}: {@code kty}, the key type's public members and an optional
     * {@code kid}, in the order the input has them. Refuses private or secret members, another {@code kty}
     * or curve, or a missing member, so a private key is never signed into an attestation.
     */
    static Map<String, Object> publicConfirmationJwk(Map<String, Object> jwk) {
        if (jwk == null) {
            throw new IllegalArgumentException("cnf.jwk must be a JWK object");
        }
        for (String member : PRIVATE_JWK_MEMBERS) {
            if (jwk.containsKey(member)) {
                throw new IllegalArgumentException(
                        "cnf.jwk must be a public key: it carries the private member '" + member + "'");
            }
        }
        Object kty = jwk.get("kty");
        List<String> required = "EC".equals(kty) ? List.of("crv", "x", "y")
                : "RSA".equals(kty) ? List.of("n", "e") : null;
        if (required == null) {
            throw new IllegalArgumentException("cnf.jwk must be an EC or RSA public key, not kty " + kty);
        }
        for (String member : required) {
            if (!(jwk.get(member) instanceof String value) || value.isEmpty()) {
                throw new IllegalArgumentException("cnf.jwk (kty " + kty + ") is missing '" + member + "'");
            }
        }
        if ("EC".equals(kty) && !List.of("P-256", "P-384", "P-521").contains(jwk.get("crv"))) {
            throw new IllegalArgumentException(
                    "cnf.jwk curve must be P-256, P-384 or P-521, not " + jwk.get("crv"));
        }
        if (jwk.containsKey("kid") && (!(jwk.get("kid") instanceof String kid) || kid.isEmpty())) {
            throw new IllegalArgumentException("cnf.jwk kid must be a non-empty string");
        }
        Map<String, Object> out = new LinkedHashMap<>();
        jwk.forEach((member, value) -> {
            if (member.equals("kty") || member.equals("kid") || required.contains(member)) {
                out.put(member, value);
            }
        });
        return out;
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value;
    }
}
