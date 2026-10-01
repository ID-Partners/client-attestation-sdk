/**
 * Access-token validation: JWT signature + claim checks, and optional RFC 7662 introspection.
 *
 * `validate` does local JWT validation in a fixed order — algorithm accepted, key resolvable,
 * signature, `typ` (when present), `iss`, `exp` present, `exp`, `nbf`, `iat` not in the future, audience,
 * then scope — returning the first failure's stable error code. That order is part of the cross-language contract so every port reports the same verdict.
 * `validateActive` instead uses RFC 7662 introspection.
 */
import { compactVerify, decodeProtectedHeader } from "jose";

import * as errors from "./errors.js";
import {
  normaliseType,
  resolveConfig,
  type IntrospectionConfig,
  type ResolvedConfig,
  type ValidatorConfig,
} from "./config.js";
import { jsonOk, request } from "../http.js";
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
}

const defaultPost: HttpPost = async (url, body, headers) => {
  // the shared transport never follows a redirect: it would carry the resource server's credentials
  const resp = await request(url, { method: "POST", body, headers, timeoutMs: 10_000 });
  if (!resp.ok) {
    throw new Error(`introspection failed: ${resp.status}`);
  }
  return jsonOk<Claims>(resp);
};

/** Validates access tokens for a resource server. */
export class AccessTokenValidator {
  readonly config: ResolvedConfig;
  readonly #jwks: JwksProvider;
  readonly #httpPost: HttpPost;

  constructor(config: ValidatorConfig, opts: ValidatorOptions = {}) {
    this.config = resolveConfig(config);
    this.#jwks = new JwksProvider({
      jwks: this.config.jwks,
      jwksUri: this.config.jwksUri,
      httpGet: opts.httpGet,
    });
    this.#httpPost = opts.httpPost ?? defaultPost;
  }

  /**
   * Locally validate a JWT access token. Returns the first failure in the fixed contract order, or a
   * success result exposing subject / scopes / audience / claims.
   */
  async validate(token: string, requiredScopes?: string[]): Promise<ValidationResult> {
    const required = requiredScopes ?? this.config.requiredScopes;

    let header: { alg?: string; kid?: string; typ?: string };
    try {
      header = decodeProtectedHeader(token);
    } catch (exc) {
      return failure(errors.INVALID_TOKEN, `malformed token: ${errMessage(exc)}`);
    }

    const alg = header.alg;
    if (alg == null || !this.config.acceptedAlgorithms.includes(alg)) {
      // never echo the unverified header alg back to the caller (it lands in WWW-Authenticate)
      return failure(errors.UNSUPPORTED_ALGORITHM, "algorithm not accepted");
    }

    const key = await this.#jwks.resolve(header.kid, alg);
    if (key == null) {
      return failure(errors.KEY_NOT_FOUND, this.#jwks.lastError ?? "no signing key for this kid");
    }

    let claims: Claims;
    try {
      const { payload } = await compactVerify(token, key, { algorithms: [alg] });
      claims = JSON.parse(new TextDecoder().decode(payload)) as Claims;
    } catch (exc) {
      return failure(errors.INVALID_SIGNATURE, errMessage(exc));
    }
    if (claims === null || typeof claims !== "object" || Array.isArray(claims)) {
      return failure(errors.INVALID_TOKEN, "payload is not a JSON object");
    }

    const types = this.config.acceptedTokenTypes;
    if (header.typ != null && types !== null && !types.includes(normaliseType(String(header.typ)))) {
      return failure(errors.INVALID_TOKEN_TYPE, "token is not a JWT access token");
    }

    if (claims.iss !== this.config.issuer) {
      return failure(errors.INVALID_ISSUER, "unexpected issuer");
    }

    const now = Math.floor(Date.now() / 1000);
    const leeway = this.config.leewaySeconds;
    let exp: number | undefined;
    let nbf: number | undefined;
    let iat: number | undefined;
    try {
      exp = numericDate(claims, "exp");
      nbf = numericDate(claims, "nbf");
      iat = numericDate(claims, "iat");
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

    const audience = asList(claims.aud);
    if (!this.config.audiences.some((a) => audience.includes(a))) {
      return failure(errors.INVALID_AUDIENCE, "token audience is not accepted");
    }

    const granted = scopesOf(claims);
    const missing = required.filter((s) => !granted.includes(s));
    if (missing.length > 0) {
      return failure(errors.INSUFFICIENT_SCOPE, `missing scopes: ${missing.join(" ")}`);
    }

    return success(claims, granted, audience);
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
    return this.#httpPost(cfg.endpoint, form.toString(), headers);
  }

  /**
   * Introspect the token and enforce `active` plus scope/audience from the response.
   */
  async validateActive(token: string, requiredScopes?: string[]): Promise<ValidationResult> {
    const data = await this.introspect(token);
    if (!data.active) {
      return failure(errors.INACTIVE, "token is not active");
    }
    const required = requiredScopes ?? this.config.requiredScopes;
    const granted = scopesOf(data);
    const missing = required.filter((s) => !granted.includes(s));
    if (missing.length > 0) {
      return failure(errors.INSUFFICIENT_SCOPE, `missing scopes: ${missing.join(" ")}`);
    }
    const audience = asList(data.aud);
    if (
      this.config.audiences.length > 0 &&
      audience.length > 0 &&
      !this.config.audiences.some((a) => audience.includes(a))
    ) {
      return failure(errors.INVALID_AUDIENCE, "token audience is not accepted");
    }
    return success(data, granted, audience);
  }
}

/** A NumericDate claim as an integer, `undefined` when absent. Anything but a finite number is malformed. */
function numericDate(claims: Claims, name: string): number | undefined {
  const value = claims[name];
  if (value == null) {
    return undefined;
  }
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`${name} is not a NumericDate`);
  }
  return Math.trunc(value);
}

/** Normalize an `aud` claim (string | string[] | absent) to a list of strings. */
function asList(value: unknown): string[] {
  if (value == null) {
    return [];
  }
  return Array.isArray(value) ? value.map(String) : [String(value)];
}

/** Granted scopes from `scope` (space-delimited string) or `scp` (array). */
function scopesOf(claims: Claims): string[] {
  const scope = claims.scope;
  if (typeof scope === "string") {
    return scope.split(/\s+/).filter((s) => s.length > 0);
  }
  const scp = claims.scp;
  if (Array.isArray(scp)) {
    return scp.map(String);
  }
  return [];
}

function base64(value: string): string {
  return Buffer.from(value, "utf8").toString("base64");
}

function errMessage(exc: unknown): string {
  return exc instanceof Error ? exc.message : String(exc);
}
