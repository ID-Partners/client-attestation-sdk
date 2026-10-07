/**
 * Optional logging. The SDK is silent unless a {@link Logger} is passed in (`logger` on
 * `ClientAttestation` and on `AccessTokenValidator`). Event names and attribute keys are shared with the
 * other ports; see docs/logging.md.
 *
 * Never logged: tokens, attestations, proofs, SVIDs, challenge values, key material, header values, or
 * URLs with their query string. As a backstop, any string attribute containing `eyJ` (how a JWT's
 * base64url-encoded header begins) is replaced with `<redacted:N bytes>` before it reaches the logger.
 */
import { TransportError } from "./errors.js";
import { utf8Encode } from "./runtime.js";

/** Attributes carried with an event. */
export type LogAttributes = Record<string, unknown>;

/** Anything with these four methods: `console` fits, as do pino, winston and bunyan wrappers. */
export interface Logger {
  debug(msg: string, attrs?: LogAttributes): void;
  info(msg: string, attrs?: LogAttributes): void;
  warn(msg: string, attrs?: LogAttributes): void;
  error(msg: string, attrs?: LogAttributes): void;
}

export type LogLevel = "debug" | "info" | "warn" | "error";

const noop = (): void => undefined;

/** The default: drops everything. */
export const NOOP_LOGGER: Logger = { debug: noop, info: noop, warn: noop, error: noop };

function guard(value: unknown): unknown {
  if (typeof value !== "string") return value;
  // A JWT's header and claims (any base64url-encoded JSON object) begin with "eyJ".
  if (value.includes("eyJ")) {
    return `<redacted:${utf8Encode(value).length} bytes>`;
  }
  return value;
}

/**
 * Emit one event: undefined attributes dropped, JWT-looking values redacted. Never throws.
 *
 * @internal
 */
export function emit(logger: Logger, level: LogLevel, event: string, attrs: LogAttributes = {}): void {
  if (logger === NOOP_LOGGER) return;
  const clean: LogAttributes = {};
  for (const [key, value] of Object.entries(attrs)) {
    if (value !== undefined && value !== null) clean[key] = guard(value);
  }
  try {
    logger[level](event, clean);
  } catch {
    // a broken logger must never break the flow
  }
}

/**
 * `host[:port]` and the path of a URL, never its query string or fragment.
 *
 * @internal
 */
export function urlParts(url: string): { host?: string; path?: string } {
  try {
    const parsed = new URL(url);
    return { host: parsed.host, path: parsed.pathname };
  } catch {
    return {};
  }
}

/**
 * `host[:port]` of a URL.
 *
 * @internal
 */
export function hostOf(url: string): string | undefined {
  return urlParts(url).host;
}

/**
 * The `reason` attribute for a failed outbound call.
 *
 * @internal
 */
export function failureReason(err: unknown): string {
  if (err instanceof TransportError) return err.kind === "json" ? "malformed" : err.kind;
  if (err instanceof SyntaxError) return "malformed";
  return "network";
}
