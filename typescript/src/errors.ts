/**
 * The SDK's error types. {@link ClientAttestationError} is the base for every failure of the
 * one-call flow; {@link TransportError} is the subclass for anything that went wrong on the wire.
 */

/**
 * A step in the flow failed. `status` and `body` are set for HTTP failures: `body` is at most the first 512
 * characters of a non-2xx response, and unset for a 2xx response that could not be used, since that body
 * may hold a token, attestation or SVID.
 */
export class ClientAttestationError extends Error {
  readonly status?: number;
  readonly body?: string;

  constructor(message: string, opts?: { status?: number; body?: string; cause?: unknown }) {
    super(message, opts?.cause === undefined ? undefined : { cause: opts.cause });
    this.name = "ClientAttestationError";
    this.status = opts?.status;
    this.body = opts?.body;
  }
}

/** Why an outbound HTTP call failed. */
export type TransportFailure =
  | "network" // could not connect, or the connection failed mid-request
  | "timeout" // the call did not complete within its timeout
  | "redirect" // the server answered 3xx; redirects are never followed
  | "too_large" // the response body exceeded the size cap
  | "status" // a non-2xx response where a 2xx was required
  | "json"; // the body was not the JSON object the caller expected

/**
 * An outbound HTTP call failed: unreachable, timed out, redirected, oversized, non-2xx, or malformed
 * JSON (see {@link kind}). `status` is set when a response was received; `body` holds at most the first
 * 512 characters of a non-2xx one.
 */
export class TransportError extends ClientAttestationError {
  readonly kind: TransportFailure;

  constructor(
    message: string,
    kind: TransportFailure,
    opts?: { status?: number; body?: string; cause?: unknown },
  ) {
    super(message, opts);
    this.name = "TransportError";
    this.kind = kind;
  }
}
