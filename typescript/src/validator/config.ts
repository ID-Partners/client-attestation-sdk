/**
 * Validator configuration.
 */
import type { JSONWebKeySet } from "jose";

/** Default accepted JWS algorithms: EC / RSA / RSA-PSS at 256/384/512. */
export const DEFAULT_ALGORITHMS: readonly string[] = [
  "ES256",
  "ES384",
  "ES512",
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
];

/** RFC 9068 section 2.1: a JWT access token's `typ` is `at+jwt` (the `application/` prefix is optional). */
export const DEFAULT_TOKEN_TYPES: readonly string[] = ["at+jwt"];

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
 * Compare JOSE `typ` values the way RFC 7515 section 4.1.9 says to: case-insensitively, with an optional
 * `application/` prefix.
 */
export function normaliseType(value: string): string {
  const lower = value.toLowerCase();
  return lower.startsWith("application/") ? lower.slice("application/".length) : lower;
}

/** Normalize a caller-supplied config, applying defaults (mirrors Python's `ValidatorConfig`). */
export function resolveConfig(config: ValidatorConfig): ResolvedConfig {
  if (!config.issuer) {
    throw new Error("issuer is required");
  }
  const audiences =
    typeof config.audiences === "string" ? [config.audiences] : [...(config.audiences ?? [])];
  if (audiences.length === 0) {
    throw new Error("at least one audience is required");
  }
  const types = config.acceptedTokenTypes === undefined ? DEFAULT_TOKEN_TYPES : config.acceptedTokenTypes;
  return {
    issuer: config.issuer,
    audiences,
    jwks: config.jwks,
    jwksUri: config.jwksUri,
    requiredScopes: [...(config.requiredScopes ?? [])],
    acceptedAlgorithms: [...(config.acceptedAlgorithms ?? DEFAULT_ALGORITHMS)],
    leewaySeconds: config.leewaySeconds ?? 60,
    introspection: config.introspection,
    acceptedTokenTypes: types === null ? null : types.map(normaliseType),
  };
}
