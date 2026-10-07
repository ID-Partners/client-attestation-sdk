/**
 * Resolves issuer signing keys — from a static JWKS or a `jwksUri` (fetched and cached, refreshed on an
 * unknown `kid` and when the cached set grows old).
 *
 * A `jwksUri` provider never fetches more than once per `minRefreshSeconds`, however many unknown `kid`
 * values it is shown, and concurrent misses share one fetch. Without that, a stream of tokens with made-up
 * `kid` values turns every request into a request to the issuer.
 */
import { importJWK, type CryptoKey, type JSONWebKeySet, type JWK } from "jose";

import { TransportError } from "../errors.js";
import { request } from "../http.js";
import { emit, failureReason, hostOf, NOOP_LOGGER, type Logger } from "../logging.js";

/**
 * An imported verification key, as returned by jose's `importJWK`.
 *
 * @internal
 */
export type VerificationKey = CryptoKey | Uint8Array;

/** Fetch a URL and return its body text. Injectable so tests can avoid real network I/O. */
export type HttpGet = (url: string) => Promise<string>;

/** @internal */
export const MAX_JWKS_BYTES = 512 * 1024;
/** @internal */
export const DEFAULT_MIN_REFRESH_SECONDS = 30;
/** @internal */
export const DEFAULT_MAX_AGE_SECONDS = 3600;
const FETCH_TIMEOUT_MS = 10_000;

const defaultGet: HttpGet = async (url) => {
  // the shared transport refuses redirects and caps the body at MAX_JWKS_BYTES while reading it
  const resp = await request(url, { method: "GET", timeoutMs: FETCH_TIMEOUT_MS, maxBytes: MAX_JWKS_BYTES });
  if (!resp.ok) {
    throw new TransportError(`GET ${url} failed: ${resp.status}`, "status", { status: resp.status });
  }
  return resp.body;
};

/** Best-effort JWS `alg` for a JWK that omits `alg`, from its key type / curve. */
function algorithmFor(jwk: JWK): string {
  if (jwk.kty === "EC") {
    return { "P-256": "ES256", "P-384": "ES384", "P-521": "ES512" }[jwk.crv ?? ""] ?? "ES256";
  }
  if (jwk.kty === "RSA") {
    return "RS256";
  }
  if (jwk.kty === "OKP") {
    return "EdDSA";
  }
  return "RS256";
}

type Entry = { key: VerificationKey; alg?: string };

/** @internal */
export interface JwksProviderOptions {
  jwks?: JSONWebKeySet;
  jwksUri?: string;
  httpGet?: HttpGet;
  /** Minimum time between fetches. Defaults to {@link DEFAULT_MIN_REFRESH_SECONDS}. */
  minRefreshSeconds?: number;
  /** Refresh a fetched set once it is this old. Defaults to {@link DEFAULT_MAX_AGE_SECONDS}. */
  maxAgeSeconds?: number;
  /** Milliseconds clock, injectable for tests. Defaults to `Date.now`. */
  clock?: () => number;
  /** Where to send `jwks.*` log events. Unset, nothing is logged. */
  logger?: Logger;
}

/** @internal */
export class JwksProvider {
  readonly #static: boolean;
  readonly #jwksUri?: string;
  readonly #httpGet: HttpGet;
  readonly #minRefreshMs: number;
  readonly #maxAgeMs: number;
  readonly #clock: () => number;
  readonly #logger: Logger;
  /** kid -> key, plus the JWK's declared `alg` (a JWK that declares one is only used for that alg). */
  #keys = new Map<string | undefined, Entry>();
  #loaded: Promise<void> | null = null;
  #inFlight: Promise<void> | null = null;
  #loadedAt: number | null = null;
  #lastAttempt: number | null = null;
  /** Why the last fetch failed, or `null` after a successful one. */
  lastError: string | null = null;

  constructor(opts: JwksProviderOptions) {
    this.#static = opts.jwks != null;
    this.#jwksUri = opts.jwksUri;
    this.#httpGet = opts.httpGet ?? defaultGet;
    this.#minRefreshMs = (opts.minRefreshSeconds ?? DEFAULT_MIN_REFRESH_SECONDS) * 1000;
    this.#maxAgeMs = (opts.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS) * 1000;
    this.#clock = opts.clock ?? Date.now;
    this.#logger = opts.logger ?? NOOP_LOGGER;
    if (opts.jwks != null) {
      this.#loaded = JwksProvider.#parse(opts.jwks).then((keys) => {
        this.#keys = keys;
      });
    }
  }

  static async #parse(jwks: JSONWebKeySet): Promise<Map<string | undefined, Entry>> {
    const keys = new Map<string | undefined, Entry>();
    for (const jwk of jwks.keys ?? []) {
      const alg = jwk.alg ?? algorithmFor(jwk);
      try {
        keys.set(jwk.kid, { key: await importJWK(jwk, alg), alg: jwk.alg });
      } catch {
        continue;
      }
    }
    return keys;
  }

  /**
   * Resolve the verification key for a header `kid` (and `alg`). Falls back to the single configured key
   * when the header carries no `kid`. Returns `undefined` when no key can be found; never rejects — a
   * failed fetch leaves its reason in {@link lastError}.
   */
  async resolve(kid: string | undefined, alg?: string): Promise<VerificationKey | undefined> {
    if (this.#loaded) {
      await this.#loaded;
    }
    if (!this.#static && this.#jwksUri && (this.#lookup(kid) === undefined || this.#stale())) {
      await this.#refresh();
    }
    const entry = this.#lookup(kid);
    if (entry === undefined || (alg != null && entry.alg != null && entry.alg !== alg)) {
      return undefined;
    }
    return entry.key;
  }

  #lookup(kid: string | undefined): Entry | undefined {
    if (kid != null) {
      return this.#keys.get(kid);
    }
    return this.#keys.size === 1 ? this.#keys.values().next().value : undefined;
  }

  #stale(): boolean {
    return this.#loadedAt === null || this.#clock() - this.#loadedAt >= this.#maxAgeMs;
  }

  #refresh(): Promise<void> {
    if (this.#inFlight) {
      return this.#inFlight;
    }
    const now = this.#clock();
    if (this.#lastAttempt !== null && now - this.#lastAttempt < this.#minRefreshMs) {
      emit(this.#logger, "debug", "jwks.refetch_throttled", { host: hostOf(this.#jwksUri as string) });
      return Promise.resolve();
    }
    this.#lastAttempt = now;
    this.#inFlight = (async () => {
      try {
        const body = await this.#httpGet(this.#jwksUri as string);
        if (body.length > MAX_JWKS_BYTES) {
          throw new TransportError(`JWKS is larger than ${MAX_JWKS_BYTES} bytes`, "too_large");
        }
        this.#keys = await JwksProvider.#parse(JSON.parse(body) as JSONWebKeySet);
        this.#loadedAt = this.#clock();
        this.lastError = null;
        emit(this.#logger, "debug", "jwks.fetched", { host: hostOf(this.#jwksUri as string), keys: this.#keys.size });
      } catch (exc) {
        emit(this.#logger, "warn", "jwks.fetch_failed", {
          host: hostOf(this.#jwksUri as string),
          reason: failureReason(exc),
          status: exc instanceof TransportError ? exc.status : undefined,
        });
        // keep serving the keys already held
        this.lastError = `JWKS fetch failed: ${exc instanceof Error ? exc.message : String(exc)}`;
      } finally {
        this.#inFlight = null;
      }
    })();
    return this.#inFlight;
  }
}
