package global.idpartners.clientattestation;

/**
 * An outbound HTTP call failed at the transport level: I/O error, timeout, interruption, a refused
 * redirect, an oversize or unparseable response, or (from the JSON helper) a non-2xx status. Public call
 * sites usually surface this as the cause of their own exception type
 * ({@link ClientAttestation.ClientAttestationException}, {@link AttestationIssuanceClient.IssuanceException},
 * or {@link IllegalStateException} for {@link OpenBaoTransitSigner} and {@link SvidSource}).
 */
public final class TransportException extends RuntimeException {
    private final int status;
    private final String body;

    /**
     * A transport failure.
     *
     * @param message what failed
     * @param status  the HTTP status, or 0 when none was received
     * @param body    at most 512 characters of a non-2xx response body, or null
     */
    public TransportException(String message, int status, String body) {
        super(message);
        this.status = status;
        this.body = body;
    }

    /**
     * A transport failure with its cause.
     *
     * @param message what failed
     * @param status  the HTTP status, or 0 when none was received
     * @param body    at most 512 characters of a non-2xx response body, or null
     * @param cause   the underlying exception
     */
    public TransportException(String message, int status, String body, Throwable cause) {
        super(message, cause);
        this.status = status;
        this.body = body;
    }

    /** HTTP status when one was received (including a refused 3xx), otherwise 0. */
    public int status() {
        return this.status;
    }

    /** At most 512 characters of a non-2xx response body, or null. A 2xx body is never kept. */
    public String body() {
        return this.body;
    }
}
