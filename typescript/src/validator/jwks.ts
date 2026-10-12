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

/** The JWK members only a private or symmetric key carries (RFC 7518 section 6). */
const PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "k"];

/**
 * Whether a JWK may verify a signature: not when its `use` is present and not `sig`, its `key_ops` is present
 * and lacks `verify`, or it carries private members. Checked on the JWK as published, before jose's
 * `importJWK` (which drops `use`) sees it.
 */
function verifiesSignatures(jwk: unknown): jwk is JWK {
  if (typeof jwk !== "object" || jwk === null || Array.isArray(jwk)) {
    return false; // not a JWK at all: skipped like any key that can't be read
  }
  if ("use" in jwk && jwk.use !== "sig") {
    return false;
  }
  if ("key_ops" in jwk && !(Array.isArray(jwk.key_ops) && (jwk.key_ops as unknown[]).includes("verify"))) {
    return false;
  }
  return !PRIVATE_MEMBERS.some((member) => member in jwk);
}

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

/**
 * One usable JWK: its `kid`, its declared `alg` (a JWK that declares one is only used for that alg) and its
 * imports so far, one per algorithm (`null`: that algorithm can't use the key). A JWK without `alg` is
 * imported for whichever algorithm a token names, so an RSA key verifies any RS* or PS* algorithm.
 */
type Entry = { kid?: string; jwk: JWK; alg?: string; imported: Map<string, VerificationKey | null> };

/** @internal */
export interface JwksProviderOptions {
  jwks?: JSONWebKeySet;
  jwksUri?: string;
  httpGet?: HttpGet;
  /** Minimum time between fetches. Defaults to {@link DEFAULT_MIN_REFRESH_SECONDS}. */
  minRefreshSeconds?: number;
  /** Refresh a fetched set once it is this old. Defaults to {@link DEFAULT_MAX_AGE_SECONDS}. */
  maxAgeSeconds?: number;
  /**
   * Monotonic milliseconds clock the set ages and the refetch cooldown runs on, injectable for tests.
   * Defaults to `performance.now`: a wall-clock step must not throttle every refetch or keep an old set.
   */
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
  /** The usable keys, in document order: kid-less JWKs are distinct keys, and the first of a duplicate kid wins. */
  #keys: Entry[] = [];
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
    this.#clock = opts.clock ?? (() => performance.now());
    this.#logger = opts.logger ?? NOOP_LOGGER;
    if (opts.jwks != null) {
      this.#loaded = JwksProvider.#parse(opts.jwks).then((keys) => {
        this.#keys = keys;
      });
    }
  }

  static async #parse(jwks: JSONWebKeySet): Promise<Entry[]> {
    const keys: Entry[] = [];
    for (const published of (jwks.keys ?? []) as unknown[]) {
      if (!verifiesSignatures(published)) {
        continue;
      }
      // Imported without its key_ops: verifiesSignatures has checked them, and jose would hand them to
      // WebCrypto as the key's usages, which refuses a public key with any usage but "verify" (a JWK exported
      // from a key pair says ["sign","verify"]). Every later import of this entry (resolve) uses this copy.
      const { key_ops: _keyOps, ...jwk } = published;
      // a JWK jose can't read at all is skipped; its key type and curve say how to read it
      const inferred = algorithmFor(jwk);
      try {
        const key = await importJWK(jwk, inferred);
        keys.push({ kid: jwk.kid, jwk, alg: jwk.alg, imported: new Map([[inferred, key]]) });
      } catch {
        continue;
      }
    }
    return keys;
  }

  /**
   * Resolve the verification key for a header `kid` (and `alg`). Falls back to the single configured key
   * when the header carries no `kid`. Returns `undefined` when no key can be found, and `null` when the key
   * found can't be used with `alg` (an EC key of another curve, an RSA key for an EC algorithm); never
   * rejects — a failed fetch leaves its reason in {@link lastError}.
   */
  async resolve(kid: string | undefined, alg?: string): Promise<VerificationKey | null | undefined> {
    if (this.#loaded) {
      await this.#loaded;
    }
    if (!this.#static && this.#jwksUri) {
      const held = this.#lookup(kid, alg) !== undefined;
      if (!held || this.#stale()) {
        await this.#refresh(held);
      }
    }
    const entry = this.#lookup(kid, alg);
    if (entry === undefined) {
      return undefined;
    }
    const as = alg ?? entry.alg ?? algorithmFor(entry.jwk);
    if (!entry.imported.has(as)) {
      entry.imported.set(as, await importJWK(entry.jwk, as).catch(() => null));
    }
    return entry.imported.get(as) ?? null;
  }

  /**
   * For a `kid`, the first key with that `kid` that may be used for `alg`; without one, the sole key when the
   * set holds exactly one. An empty `kid` names no key.
   */
  #lookup(kid: string | undefined, alg: string | undefined): Entry | undefined {
    const allowed = (entry: Entry) => alg == null || entry.alg == null || entry.alg === alg;
    if (kid != null) {
      return kid === "" ? undefined : this.#keys.find((entry) => entry.kid === kid && allowed(entry));
    }
    return this.#keys.length === 1 && allowed(this.#keys[0]) ? this.#keys[0] : undefined;
  }

  #stale(): boolean {
    return this.#loadedAt === null || this.#clock() - this.#loadedAt >= this.#maxAgeMs;
  }

  /**
   * A caller that already holds a usable (if stale) key never waits for another request's fetch: it goes on
   * with the key it has. One without a key waits for a fetch in flight, which may bring its key.
   */
  #refresh(haveKey: boolean): Promise<void> {
    if (this.#inFlight) {
      return haveKey ? Promise.resolve() : this.#inFlight;
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
        emit(this.#logger, "debug", "jwks.fetched", { host: hostOf(this.#jwksUri as string), keys: this.#keys.length });
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
