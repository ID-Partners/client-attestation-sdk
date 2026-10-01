/**
 * Stable validation outcome codes, shared across the Python / TypeScript / Go ports so their verdicts
 * can be compared directly.
 */
export const VALID = "valid";

export const EXPIRED = "expired";
export const NOT_YET_VALID = "not_yet_valid";
export const INVALID_SIGNATURE = "invalid_signature";
export const INVALID_ISSUER = "invalid_issuer";
export const INVALID_AUDIENCE = "invalid_audience";
export const INSUFFICIENT_SCOPE = "insufficient_scope";
export const INVALID_TOKEN = "invalid_token";
export const UNSUPPORTED_ALGORITHM = "unsupported_algorithm";
export const KEY_NOT_FOUND = "key_not_found";
export const INACTIVE = "inactive";
export const MISSING_EXPIRY = "missing_expiry";
export const ISSUED_IN_FUTURE = "issued_in_future";
export const INVALID_TOKEN_TYPE = "invalid_token_type";

/** Every stable error code a validation can report. */
export type ValidationError =
  | typeof EXPIRED
  | typeof NOT_YET_VALID
  | typeof INVALID_SIGNATURE
  | typeof INVALID_ISSUER
  | typeof INVALID_AUDIENCE
  | typeof INSUFFICIENT_SCOPE
  | typeof INVALID_TOKEN
  | typeof UNSUPPORTED_ALGORITHM
  | typeof KEY_NOT_FOUND
  | typeof INACTIVE
  | typeof MISSING_EXPIRY
  | typeof ISSUED_IN_FUTURE
  | typeof INVALID_TOKEN_TYPE;
