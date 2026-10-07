package global.idpartners.clientattestation.tokenvalidator;

/**
 * The outcome of guarding a request with {@link ProtectedResource#authenticate(String)}. On failure it
 * carries the HTTP status (401 or 403) and the {@code WWW-Authenticate} header value to return.
 */
public final class AuthDecision {

    private final boolean authorized;
    private final ValidationResult result;
    private final int status;
    private final String wwwAuthenticate;
    private final String error;
    private final String errorDescription;

    AuthDecision(boolean authorized, ValidationResult result, int status, String wwwAuthenticate, String error,
                 String errorDescription) {
        this.authorized = authorized;
        this.result = result;
        this.status = status;
        this.wwwAuthenticate = wwwAuthenticate;
        this.error = error;
        this.errorDescription = errorDescription;
    }

    /**
     * Whether the request may proceed.
     *
     * @return true when authorized
     */
    public boolean authorized() {
        return this.authorized;
    }

    /**
     * The validator's verdict, or null when the request carried no bearer token.
     *
     * @return the verdict, or null
     */
    public ValidationResult result() {
        return this.result;
    }

    /**
     * 200 when authorized, 403 for insufficient scope, otherwise 401.
     *
     * @return the HTTP status
     */
    public int status() {
        return this.status;
    }

    /**
     * The {@code WWW-Authenticate} header value to return, or null when authorized.
     *
     * @return the challenge, or null
     */
    public String wwwAuthenticate() {
        return this.wwwAuthenticate;
    }

    /**
     * The RFC 6750 error ({@code invalid_token} or {@code insufficient_scope}), or null.
     *
     * @return the error, or null
     */
    public String error() {
        return this.error;
    }

    /**
     * Why the request was refused, or null when authorized.
     *
     * @return the description, or null
     */
    public String errorDescription() {
        return this.errorDescription;
    }
}
