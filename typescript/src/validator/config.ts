/**
 * Validator configuration.
 */
import type { JSONWebKeySet } from "jose";

/** Default accepted JWS algorithms: EC / RSA / RSA-PSS at 256/384/512. Frozen, so it can't be widened. */
export const DEFAULT_ALGORITHMS: readonly string[] = Object.freeze([
  "ES256",
  "ES384",
  "ES512",
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
]);

/** RFC 9068 section 2.1: a JWT access token's `typ` is `at+jwt` (the `application/` prefix is optional). */
export const DEFAULT_TOKEN_TYPES: readonly string[] = Object.freeze(["at+jwt"]);

/** How the resource server authenticates to the AS when introspecting. */
export type IntrospectionAuthMethod = "client_secret_basic" | "client_secret_post";

/**
 * RFC 7662 introspection endpoint + client credentials (the resource server authenticating to the AS).
 */
export interface IntrospectionConfig {
  endpoint: string;
  clientId: string;
  clientSecret: string;
  /** Defaults to `"client_secret_basic"`. */
  authMethod?: IntrospectionAuthMethod;
}

/**
 * What this resource server accepts: the trusted issuer, its own audience identifier(s), the signing
 * keys (static `jwks` or a `jwksUri` to fetch), required scopes, accepted algorithms, clock leeway,
 * and optional introspection.
 *
 * `issuer` and `audiences` are required: a validator that skips either accepts tokens minted for someone
 * else. `acceptedTokenTypes` is checked against the JWT `typ` header when the token carries one, so an ID
 * token can't stand in for an access token. Pass `null` to turn that check off for an issuer that stamps
 * something other than `at+jwt`.
 *
 * An explicitly empty `acceptedAlgorithms` or `acceptedTokenTypes` accepts nothing, and `leewaySeconds: 0`
 * allows no clock skew: only an omitted field takes the default. `none` and the `HS*` algorithms are
 * refused even when listed (see validation/SEMANTICS.md).
 *
 * `jwksUri` and the introspection `endpoint` must use https unless their host is loopback (`localhost`,
 * `127.0.0.1`, `::1`) or `allowInsecure` is set: over plain http anyone on the path could serve their own
 * keys, or read the resource server's client secret.
 */
export interface ValidatorConfig {
  issuer: string;
  audiences: string | string[];
  jwks?: JSONWebKeySet;
  jwksUri?: string;
  requiredScopes?: string[];
  /** Defaults to {@link DEFAULT_ALGORITHMS}. */
  acceptedAlgorithms?: string[];
  /** Clock skew allowed on `exp` / `nbf` / `iat`, in seconds. Defaults to 60. */
  leewaySeconds?: number;
  introspection?: IntrospectionConfig;
  /** Defaults to {@link DEFAULT_TOKEN_TYPES}; `null` disables the `typ` check. */
  acceptedTokenTypes?: string[] | null;
  /** Allow a plain-http `jwksUri` and introspection `endpoint` on non-loopback hosts. Defaults to `false`. */
  allowInsecure?: boolean;
}

/** A {@link ValidatorConfig} with every optional field defaulted. */
export interface ResolvedConfig {
  issuer: string;
  audiences: string[];
  jwks?: JSONWebKeySet;
  jwksUri?: string;
  requiredScopes: string[];
  acceptedAlgorithms: string[];
  leewaySeconds: number;
  introspection?: IntrospectionConfig;
  /** Normalised with {@link normaliseType}; `null` when the check is off. */
  acceptedTokenTypes: string[] | null;
}

/**
 * `none` (in any case) and the HMAC algorithms are refused whatever `acceptedAlgorithms` says: an unsigned
 * token proves nothing, and an HMAC "signature" checked against an issuer's public key is forgeable by
 * anyone who has that key.
 *
 * @internal
 */
export function isForbiddenAlgorithm(alg: string): boolean {
  const lowered = alg.toLowerCase();
  return lowered === "none" || lowered.startsWith("hs");
}

/**
 * Compare JOSE `typ` values the way RFC 7515 section 4.1.9 says to: case-insensitively, with an optional
 * `application/` prefix.
 *
 * @internal
 */
export function normaliseType(value: string): string {
  const lower = value.toLowerCase();
  return lower.startsWith("application/") ? lower.slice("application/".length) : lower;
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

/** Refuse a non-https URL unless it is loopback or `allowInsecure` is set: the rule the client applies. */
function checkSecure(url: string, what: string, allowInsecure: boolean): void {
  if (allowInsecure) return;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`${what} is not a valid URL: ${url}`);
  }
  if (parsed.protocol === "https:" || LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase())) return;
  throw new Error(`${what} must use https: ${url} (loopback hosts are exempt; pass allowInsecure: true to override)`);
}

/**
 * A list option as a copy, refusing anything but an array of strings. JavaScript callers aren't held to
 * the types, and a bare string would otherwise spread into its characters.
 */
function stringList(value: unknown, what: string): string[] {
  if (!Array.isArray(value) || !value.every((v) => typeof v === "string")) {
    throw new Error(`${what} must be an array of strings`);
  }
  return [...value];
}

/**
 * Normalize a caller-supplied config, applying defaults (mirrors Python's `ValidatorConfig`). The result
 * shares nothing mutable with `config`: a caller reusing or changing its config object afterwards (its
 * arrays, its JWKS, its introspection settings) can't change a live validator.
 *
 * @internal
 */
export function resolveConfig(config: ValidatorConfig): ResolvedConfig {
  if (!config.issuer) {
    throw new Error("issuer is required");
  }
  const audiences =
    typeof config.audiences === "string" ? [config.audiences] : stringList(config.audiences ?? [], "audiences");
  if (audiences.length === 0) {
    throw new Error("at least one audience is required");
  }
  // NaN would make every exp/nbf/iat comparison false (no time check at all), and "60" would concatenate
  const leeway: unknown = config.leewaySeconds ?? 60;
  if (typeof leeway !== "number" || !Number.isSafeInteger(leeway) || leeway < 0) {
    throw new Error("leewaySeconds must be a non-negative integer");
  }
  const allowInsecure = config.allowInsecure ?? false;
  if (typeof allowInsecure !== "boolean") {
    throw new Error("allowInsecure must be a boolean");
  }
  if (config.jwksUri) {
    checkSecure(config.jwksUri, "jwksUri", allowInsecure);
  }
  if (config.introspection?.endpoint) {
    checkSecure(config.introspection.endpoint, "introspection endpoint", allowInsecure);
  }
  const types = config.acceptedTokenTypes === undefined ? DEFAULT_TOKEN_TYPES : config.acceptedTokenTypes;
  return {
    issuer: config.issuer,
    audiences,
    // the JWKS provider keeps each JWK and imports it again for each algorithm a token names
    jwks: config.jwks == null ? undefined : structuredClone(config.jwks),
    jwksUri: config.jwksUri,
    requiredScopes: stringList(config.requiredScopes ?? [], "requiredScopes"),
    acceptedAlgorithms: stringList(config.acceptedAlgorithms ?? DEFAULT_ALGORITHMS, "acceptedAlgorithms"),
    leewaySeconds: leeway,
    introspection: config.introspection == null ? undefined : { ...config.introspection },
    acceptedTokenTypes: types === null ? null : stringList(types, "acceptedTokenTypes").map(normaliseType),
  };
}
