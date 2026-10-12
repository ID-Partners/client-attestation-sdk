/**
 * Optional logging. The SDK is silent unless a {@link Logger} is passed in (`logger` on
 * `ClientAttestation` and on `AccessTokenValidator`). Event names and attribute keys are shared with the
 * other ports; see docs/logging.md.
 *
 * Never logged: tokens, attestations, proofs, SVIDs, challenge values, key material, header values, or
 * URLs with their query string. As a backstop, an attribute under a credential key (`token`, `*_token`,
 * `auth_req_id`, `code`, ...), or a string attribute that carries a credential (contains `eyJ`, how a
 * JWT's base64url-encoded header begins; a Vault/OpenBao token; an `Authorization` header value), is
 * replaced with `<redacted:N bytes>` before it reaches the logger.
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

// The backstop (docs/logging.md, the same rule in every port): an attribute is redacted when its key names
// a credential, or its value carries one this SDK handles. Keys are matched in lower case.
const SECRET_KEYS = new Set([
  "svid", "proof", "assertion", "client_assertion", "subject_token", "actor_token", "client_secret",
  "attestation", "access_token", "refresh_token", "id_token", "authorization", "dpop",
  "oauth-client-attestation", "oauth-client-attestation-pop", "auth_req_id", "code", "handle", "token",
  "secret", "password", "private_key", "vault_token", "x-vault-token",
]);
const SECRET_KEY_SUFFIXES = ["_token", "-token", "_secret", "-secret", "_password"];
// Vault/OpenBao tokens: hvs./hvb./hvr. and the older s./b./r. forms, standing alone.
const VAULT_TOKEN =
  /(?:^|[^A-Za-z0-9._-])(?:hv[sbr]\.[A-Za-z0-9_-]{20,}|[sbr]\.[A-Za-z0-9_-]{24,}(?:$|[^A-Za-z0-9._-]))/;
// An Authorization header value anywhere in the string: a scheme this SDK sends, standing alone, then
// whitespace and the first character of a credential ("Bearer x", " Bearer x", "Authorization: Bearer x").
// A bare scheme name ("Bearer", "token_type=Bearer", "dpop_combined") is not one.
const AUTH_SCHEME = /(?:^|[^A-Za-z0-9_-])(?:bearer|dpop|basic)[ \t]+[A-Za-z0-9._~+/-]/i;

function secretKey(key: string): boolean {
  const k = key.toLowerCase();
  return SECRET_KEYS.has(k) || SECRET_KEY_SUFFIXES.some((suffix) => k.endsWith(suffix));
}

function redacted(value: string): string {
  return `<redacted:${utf8Encode(value).length} bytes>`;
}

function guard(key: string, value: unknown): unknown {
  if (secretKey(key)) {
    try {
      return redacted(typeof value === "string" ? value : String(value));
    } catch {
      // a value whose toString throws (or an object with no prototype) must not throw out of logging
      return "<redacted>";
    }
  }
  if (typeof value !== "string") return value;
  // A JWT's header and claims (any base64url-encoded JSON object) begin with "eyJ".
  if (value.includes("eyJ") || VAULT_TOKEN.test(value) || AUTH_SCHEME.test(value)) {
    return redacted(value);
  }
  return value;
}

/**
 * Emit one event: undefined attributes dropped, credential keys and credential-looking values redacted.
 * Never throws.
 *
 * @internal
 */
export function emit(logger: Logger, level: LogLevel, event: string, attrs: LogAttributes = {}): void {
  if (logger === NOOP_LOGGER) return;
  const clean: LogAttributes = {};
  for (const [key, value] of Object.entries(attrs)) {
    if (value !== undefined && value !== null) clean[key] = guard(key, value);
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
