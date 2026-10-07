package global.idpartners.clientattestation.tokenvalidator;

/**
 * Stable validation outcome codes, shared across the Python, TypeScript, Go and Java ports so their verdicts
 * can be compared directly. {@link ValidationResult#error()} is one of these when a token is refused.
 */
public final class ErrorCodes {

    /** The verdict logged for a valid token ({@code token.validated result=valid}). */
    public static final String VALID = "valid";

    /** {@code exp} is in the past, beyond the leeway. */
    public static final String EXPIRED = "expired";
    /** {@code nbf} is in the future, beyond the leeway. */
    public static final String NOT_YET_VALID = "not_yet_valid";
    /** The signature does not verify, or the signed payload is not JSON. */
    public static final String INVALID_SIGNATURE = "invalid_signature";
    /** {@code iss} is not the configured issuer. */
    public static final String INVALID_ISSUER = "invalid_issuer";
    /** No {@code aud} value is one this resource server accepts. */
    public static final String INVALID_AUDIENCE = "invalid_audience";
    /** A required scope was not granted. */
    public static final String INSUFFICIENT_SCOPE = "insufficient_scope";
    /** The token is malformed (or a NumericDate claim is not a number). */
    public static final String INVALID_TOKEN = "invalid_token";
    /** The header {@code alg} is not an accepted algorithm. */
    public static final String UNSUPPORTED_ALGORITHM = "unsupported_algorithm";
    /** No key in the issuer's JWKS matches the token's {@code kid} and {@code alg}. */
    public static final String KEY_NOT_FOUND = "key_not_found";
    /** Introspection says the token is not active. */
    public static final String INACTIVE = "inactive";
    /** The token has no {@code exp} claim. */
    public static final String MISSING_EXPIRY = "missing_expiry";
    /** {@code iat} is in the future, beyond the leeway. */
    public static final String ISSUED_IN_FUTURE = "issued_in_future";
    /** The header {@code typ} is present but not an accepted token type (an ID token, say). */
    public static final String INVALID_TOKEN_TYPE = "invalid_token_type";

    private ErrorCodes() {
    }
}
