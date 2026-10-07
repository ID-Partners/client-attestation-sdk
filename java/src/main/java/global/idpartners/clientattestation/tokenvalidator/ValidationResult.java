package global.idpartners.clientattestation.tokenvalidator;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The outcome of validating an access token: either a valid token (with its subject, granted scopes,
 * audience and claims) or a failure carrying a stable {@link #error()} code from {@link ErrorCodes}.
 */
public final class ValidationResult {

    private final boolean valid;
    private final String error;
    private final String errorDescription;
    private final String subject;
    private final List<String> scopes;
    private final List<String> audience;
    private final Map<String, Object> claims;
    private final Long expiresAt;

    private ValidationResult(boolean valid, String error, String errorDescription, String subject,
                             List<String> scopes, List<String> audience, Map<String, Object> claims,
                             Long expiresAt) {
        this.valid = valid;
        this.error = error;
        this.errorDescription = errorDescription;
        this.subject = subject;
        this.scopes = List.copyOf(scopes);
        this.audience = List.copyOf(audience);
        this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
        this.expiresAt = expiresAt;
    }

    static ValidationResult success(Map<String, Object> claims, List<String> scopes, List<String> audience) {
        Object sub = claims.get("sub");
        Long expiresAt;
        try {
            expiresAt = Strict.numericDate(claims, "exp");
        } catch (Strict.Malformed e) {
            expiresAt = null;   // an introspection response with an odd exp: report none
        }
        return new ValidationResult(true, null, null, sub instanceof String ? (String) sub : null, scopes,
                audience, claims, expiresAt);
    }

    static ValidationResult failure(String error, String description) {
        return new ValidationResult(false, error, description, null, List.of(), List.of(), Map.of(), null);
    }

    /**
     * Whether the token was accepted.
     *
     * @return true when valid
     */
    public boolean valid() {
        return this.valid;
    }

    /**
     * The stable error code (see {@link ErrorCodes}), or null when valid.
     *
     * @return the error code, or null
     */
    public String error() {
        return this.error;
    }

    /**
     * A human-readable reason, or null when valid. It never quotes the token's unverified header or claims,
     * so it is safe to return in a {@code WWW-Authenticate} challenge.
     *
     * @return the description, or null
     */
    public String errorDescription() {
        return this.errorDescription;
    }

    /**
     * The {@code sub} claim, or null when valid without one (or when it is not a string), or when invalid.
     *
     * @return the subject, or null
     */
    public String subject() {
        return this.subject;
    }

    /**
     * The granted scopes, from {@code scope} (space-delimited) or else {@code scp} (an array).
     *
     * @return the scopes; empty when invalid
     */
    public List<String> scopes() {
        return this.scopes;
    }

    /**
     * The token's audience, as a list.
     *
     * @return the audience; empty when invalid
     */
    public List<String> audience() {
        return this.audience;
    }

    /**
     * The verified claims (or the introspection response).
     *
     * @return the claims; empty when invalid
     */
    public Map<String, Object> claims() {
        return this.claims;
    }

    /**
     * The {@code exp} claim in epoch seconds, or null when absent.
     *
     * @return the expiry, or null
     */
    public Long expiresAt() {
        return this.expiresAt;
    }

    @Override
    public String toString() {
        if (this.valid) {
            return "ValidationResult(valid, sub=" + this.subject + ", scopes=" + this.scopes + ")";
        }
        return "ValidationResult(invalid, error=" + this.error + ": " + this.errorDescription + ")";
    }
}
