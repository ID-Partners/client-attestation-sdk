/**
 * Access-token validation: JWT signature + claim checks, and optional RFC 7662 introspection.
 *
 * `validate` does local JWT validation in a fixed order — algorithm accepted, key resolvable,
 * signature, `typ` (when present), `iss`, `exp` present, `exp`, `nbf`, `iat` not in the future, audience,
 * then scope — returning the first failure's stable error code. That order is part of the cross-language contract so every port reports the same verdict.
 * `validateActive` instead uses RFC 7662 introspection.
 */
import { compactVerify } from "jose";

import { base64Encode, utf8Encode } from "../runtime.js";
import * as errors from "./errors.js";
import * as strict from "./strict.js";
import {
  isForbiddenAlgorithm,
  normaliseType,
  resolveConfig,
  type IntrospectionConfig,
  type ResolvedConfig,
  type ValidatorConfig,
} from "./config.js";
import { TransportError } from "../errors.js";
import { request } from "../http.js";
import { emit, failureReason, NOOP_LOGGER, urlParts, type Logger } from "../logging.js";
import { JwksProvider, type HttpGet } from "./jwks.js";
import { failure, success, type ValidationResult } from "./result.js";

/** Claims as decoded from a JWT payload (or an introspection response). */
export type Claims = Record<string, unknown>;

/**
 * Inject a POST transport (mirrors Python's `http_post`). Resolves to the parsed JSON response body.
 */
export type HttpPost = (
  url: string,
  body: string,
  headers: Record<string, string>,
) => Promise<Claims>;

/** Optional injectable transports, primarily so tests can mock network I/O. */
export interface ValidatorOptions {
  httpPost?: HttpPost;
  httpGet?: HttpGet;
  /**
   * Where to send log events (`token.validated`, `jwks.*`, `http.failed`; see docs/logging.md). Unset,
   * nothing is logged. Tokens and client secrets are never logged.
   */
  logger?: Logger;
  /** Epoch-millisecond clock that `exp` / `nbf` / `iat` are checked against. Defaults to `Date.now`. */
  clock?: () => number;
}

/**
 * An introspection response larger than this is refused.
 *
 * @internal
 */
export const MAX_INTROSPECTION_BYTES = 1024 * 1024;

const defaultPost: HttpPost = async (url, body, headers) => {
  // the shared transport never follows a redirect (it would carry the resource server's credentials) and
  // refuses a body over the cap
  const resp = await request(url, {
    method: "POST",
    body,
    headers,
    timeoutMs: 10_000,
    maxBytes: MAX_INTROSPECTION_BYTES,
  });
  if (!resp.ok) {
    throw new TransportError(`introspection failed: ${resp.status}`, "status", { status: resp.status });
  }
  try {
    return strict.parseObject(utf8Encode(resp.body), "introspection response");
  } catch (err) {
    throw new TransportError(`introspection endpoint returned ${errMessage(err)}`, "json", {
      status: resp.status,
    });
  }
};

/** Validates access tokens for a resource server. */
export class AccessTokenValidator {
  readonly config: ResolvedConfig;
  readonly #jwks: JwksProvider;
  readonly #httpPost: HttpPost;
  readonly #logger: Logger;
  readonly #clock: () => number;

  constructor(config: ValidatorConfig, opts: ValidatorOptions = {}) {
    this.config = resolveConfig(config);
    this.#jwks = new JwksProvider({
      jwks: this.config.jwks,
      jwksUri: this.config.jwksUri,
      httpGet: opts.httpGet,
      logger: opts.logger,
    });
    this.#httpPost = opts.httpPost ?? defaultPost;
    this.#logger = opts.logger ?? NOOP_LOGGER;
    this.#clock = opts.clock ?? Date.now;
  }

  /**
   * Locally validate a JWT access token. Returns the first failure in the fixed contract order, or a
   * success result exposing subject / scopes / audience / claims.
   */
  async validate(token: string, requiredScopes?: string[]): Promise<ValidationResult> {
    return this.#verdict("jwt", await this.#validate(token, requiredScopes));
  }

  /** Log a verdict (its error code only, never the token) and return it. */
  #verdict(mode: "jwt" | "introspection", result: ValidationResult): ValidationResult {
    emit(this.#logger, result.valid ? "debug" : "info", "token.validated", { result: result.valid ? "valid" : result.error, mode });
    return result;
  }

  async #validate(token: string, requiredScopes?: string[]): Promise<ValidationResult> {
    const required = requiredScopes ?? this.config.requiredScopes;

    let parts: strict.CompactParts;
    try {
      parts = strict.splitCompact(token);
    } catch {
      // never echo token data to the caller: the description lands in WWW-Authenticate
      return failure(errors.INVALID_TOKEN, "malformed token");
    }
    const { header } = parts;

    const alg = header.alg;
    if (typeof alg !== "string" || isForbiddenAlgorithm(alg) || !this.config.acceptedAlgorithms.includes(alg)) {
      // never echo the unverified header alg back to the caller (it lands in WWW-Authenticate)
      return failure(errors.UNSUPPORTED_ALGORITHM, "algorithm not accepted");
    }

    const kid = header.kid;
    const key = kid == null || typeof kid === "string" ? await this.#jwks.resolve(kid ?? undefined, alg) : undefined;
    if (key === undefined) {
      // a fetch failure's detail (internal host, dial error, IdP body) went to the logger as jwks.fetch_failed;
      // the description lands in WWW-Authenticate, in front of anyone
      return failure(
        errors.KEY_NOT_FOUND,
        this.#jwks.lastError !== null ? "signing keys unavailable" : "no signing key for this kid",
      );
    }

    try {
      if (key === null) {
        throw new Error("the key can't be used with this algorithm");
      }
      await compactVerify(token, key, { algorithms: [alg] });
    } catch {
      return failure(errors.INVALID_SIGNATURE, "signature verification failed");
    }
    let claims: Claims;
    try {
      claims = strict.parseObject(parts.payload);
    } catch (exc) {
      return failure(errors.INVALID_TOKEN, errMessage(exc));
    }

    const types = this.config.acceptedTokenTypes;
    const typ = header.typ;
    if (typ != null && types !== null && (typeof typ !== "string" || !types.includes(normaliseType(typ)))) {
      return failure(errors.INVALID_TOKEN_TYPE, "token is not a JWT access token");
    }

    if (claims.iss !== this.config.issuer) {
      return failure(errors.INVALID_ISSUER, "unexpected issuer");
    }

    const now = Math.floor(this.#clock() / 1000);
    const leeway = this.config.leewaySeconds;
    let exp: number | undefined;
    let nbf: number | undefined;
    let iat: number | undefined;
    try {
      exp = strict.numericDate(claims, "exp");
      nbf = strict.numericDate(claims, "nbf");
      iat = strict.numericDate(claims, "iat");
    } catch (exc) {
      return failure(errors.INVALID_TOKEN, errMessage(exc));
    }
    if (exp === undefined) {
      return failure(errors.MISSING_EXPIRY, "token has no exp claim");
    }
    if (now > exp + leeway) {
      return failure(errors.EXPIRED, "token has expired");
    }
    if (nbf !== undefined && now + leeway < nbf) {
      return failure(errors.NOT_YET_VALID, "token is not yet valid");
    }
    if (iat !== undefined && now + leeway < iat) {
      return failure(errors.ISSUED_IN_FUTURE, "token was issued in the future");
    }

    try {
      const audience = strict.audience(claims);
      if (!this.config.audiences.some((a) => audience.includes(a))) {
        return failure(errors.INVALID_AUDIENCE, "token audience is not accepted");
      }
      const granted = strict.scopes(claims);
      const missing = required.filter((s) => !granted.includes(s));
      if (missing.length > 0) {
        return failure(errors.INSUFFICIENT_SCOPE, `missing scopes: ${missing.join(" ")}`);
      }
      strict.subject(claims);
      return success(claims, granted, audience);
    } catch (exc) {
      return failure(errors.INVALID_TOKEN, errMessage(exc));
    }
  }

  /**
   * RFC 7662: POST the token to the AS introspection endpoint and return the parsed response.
   */
  async introspect(token: string, tokenTypeHint = "access_token"): Promise<Claims> {
    const cfg: IntrospectionConfig | undefined = this.config.introspection;
    if (cfg == null) {
      throw new Error("no introspection endpoint configured");
    }
    const form = new URLSearchParams();
    form.set("token", token);
    form.set("token_type_hint", tokenTypeHint);
    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    };
    const authMethod = cfg.authMethod ?? "client_secret_basic";
    if (authMethod === "client_secret_basic") {
      const raw = `${cfg.clientId}:${cfg.clientSecret}`;
      headers.Authorization = `Basic ${base64(raw)}`;
    } else {
      form.set("client_id", cfg.clientId);
      form.set("client_secret", cfg.clientSecret);
    }
    try {
      const data: unknown = await this.#httpPost(cfg.endpoint, form.toString(), headers);
      if (data === null || typeof data !== "object" || Array.isArray(data)) {
        throw new TransportError("introspection endpoint returned JSON that is not an object", "json");
      }
      return data as Claims;
    } catch (err) {
      emit(this.#logger, "warn", "http.failed", {
        step: "introspection",
        method: "POST",
        ...urlParts(cfg.endpoint),
        status: err instanceof TransportError ? err.status : undefined,
        reason: failureReason(err),
      });
      throw err;
    }
  }

  /**
   * Introspect the token and enforce `active` plus scope/audience from the response.
   */
  async validateActive(token: string, requiredScopes?: string[]): Promise<ValidationResult> {
    return this.#verdict("introspection", await this.#validateActive(token, requiredScopes));
  }

  async #validateActive(token: string, requiredScopes?: string[]): Promise<ValidationResult> {
    const data = await this.introspect(token);
    // RFC 7662 section 2.2: active is a boolean, so only JSON true counts
    if (data.active !== true) {
      return failure(errors.INACTIVE, "token is not active");
    }
    const required = requiredScopes ?? this.config.requiredScopes;
    try {
      const granted = strict.scopes(data);
      const missing = required.filter((s) => !granted.includes(s));
      if (missing.length > 0) {
        return failure(errors.INSUFFICIENT_SCOPE, `missing scopes: ${missing.join(" ")}`);
      }
      const audience = strict.audience(data);
      if (audience.length > 0 && !this.config.audiences.some((a) => audience.includes(a))) {
        return failure(errors.INVALID_AUDIENCE, "token audience is not accepted");
      }
      strict.subject(data);
      return success(data, granted, audience);
    } catch (exc) {
      return failure(errors.INVALID_TOKEN, errMessage(exc));
    }
  }
}

function base64(value: string): string {
  return base64Encode(utf8Encode(value));
}

function errMessage(exc: unknown): string {
  return exc instanceof Error ? exc.message : String(exc);
}
