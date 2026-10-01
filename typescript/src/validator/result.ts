/**
 * The outcome of validating an access token: either a valid token (with its subject, granted scopes,
 * audience and claims) or a failure carrying a stable `error` code (see {@link ./errors}).
 */
import type { ValidationError } from "./errors.js";

export interface ValidationResult {
  valid: boolean;
  /** Stable error code when `valid` is false; `null` when valid. */
  error: ValidationError | null;
  errorDescription: string | null;
  subject: string | null;
  scopes: string[];
  audience: string[];
  claims: Record<string, unknown>;
  /** The `exp` claim (integer epoch seconds) when present. */
  expiresAt: number | null;
}

export function success(
  claims: Record<string, unknown>,
  scopes: string[],
  audience: string[],
): ValidationResult {
  const sub = claims.sub;
  const exp = claims.exp;
  return {
    valid: true,
    error: null,
    errorDescription: null,
    subject: typeof sub === "string" ? sub : null,
    scopes,
    audience,
    claims,
    expiresAt: exp == null ? null : Number(exp),
  };
}

export function failure(error: ValidationError, description?: string): ValidationResult {
  return {
    valid: false,
    error,
    errorDescription: description ?? null,
    subject: null,
    scopes: [],
    audience: [],
    claims: {},
    expiresAt: null,
  };
}
