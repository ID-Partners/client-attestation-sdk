/**
 * Resource-server access-token validation: JWT signature + scope/audience checks in a fixed,
 * cross-language error-precedence order, plus optional RFC 7662 introspection.
 *
 * This is the validator counterpart to the client-side builder SDK, and mirrors the Python
 * `client_attestation_sdk.token_validator` package so every port reports the same verdict for the shared vectors.
 */
export { AccessTokenValidator } from "./validator.js";
export type { HttpPost, Claims, ValidatorOptions } from "./validator.js";
export type { HttpGet } from "./jwks.js";
export type { Logger, LogAttributes, LogLevel } from "../logging.js";
export { resolveConfig, DEFAULT_ALGORITHMS, DEFAULT_TOKEN_TYPES } from "./config.js";
export type {
  ValidatorConfig,
  ResolvedConfig,
  IntrospectionConfig,
  IntrospectionAuthMethod,
} from "./config.js";
export type { ValidationResult } from "./result.js";
export type { ValidationError } from "./errors.js";
export * as errors from "./errors.js";
export { ProtectedResource, bearerToken } from "./resource.js";
export type { ProtectedResourceMetadata, AuthDecision } from "./resource.js";

export const VALIDATOR_VERSION = "0.3.0";
