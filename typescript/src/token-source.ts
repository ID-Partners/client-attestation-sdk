/**
 * One call to get an access token with client attestation.
 *
 * Point it at a PingFederate host and call `.token()`. It runs the whole flow:
 *
 *     discover -> get platform identity (evidence) -> get a challenge -> mint the attestation ->
 *     call the token endpoint with the attestation headers -> cache the access token
 *
 * The workload sends no client secret and no client_id. Its only credential is the attestation, built
 * from the identity its runtime already gives it (auto-detected; see `evidence.ts`).
 *
 *     import { ClientAttestation } from "@idpartners/client-attestation-sdk";
 *
 *     const ca = new ClientAttestation("pf.example.com");
 *     const token = await ca.token();                       // cached until it nears expiry
 *
 *     // the fetch wrapper attaches the token (and a DPoP proof for a DPoP-bound token):
 *     await ca.fetch("https://api.example.com/things");
 *     // or build the headers for any other client:
 *     const headers = await ca.requestHeaders("GET", "https://api.example.com/things");
 */
import { base64url } from "jose";

import { DpopProofBuilder } from "./builders.js";
import { ClientAttestationCredential, DPOP_HEADER } from "./credential.js";
import { ClientAttestationError, TransportError } from "./errors.js";
import { autoDetectEvidence } from "./evidence.js";
import { INSTANCE_PROOF_TYP } from "./issuance.js";
import { jsonOk, request, type HttpRequestOptions, type HttpResponse } from "./http.js";
import { emit, failureReason, hostOf, NOOP_LOGGER, urlParts, type Logger } from "./logging.js";
import { utf8Decode } from "./runtime.js";
import { SigningKeyPair, signCompact } from "./signing-key-pair.js";
import type { SvidSource } from "./svid-source.js";

export const ATTESTATION_HEADER = "OAuth-Client-Attestation";
export const POP_HEADER = "OAuth-Client-Attestation-PoP";
export const WELL_KNOWN_PATH = "/.well-known/client-attester";
/** Refresh this many seconds before the token actually expires, so a token is never used at the edge. */
export const DEFAULT_EXPIRY_SKEW_SECONDS = 30;

export { ClientAttestationError, TransportError } from "./errors.js";

/** The attester's `/.well-known/client-attester` discovery document. */
interface AttesterDiscovery {
  evidence_audience?: string;
  attestation_endpoint?: string;
  challenge_endpoint?: string;
  token_endpoint?: string;
  pop_audience?: string;
}

/** Options for {@link ClientAttestation}. */
export interface ClientAttestationOptions {
  /**
   * How to get the workload's platform identity. Leave unset to auto-detect the runtime (env token,
   * projected token file, SPIRE socket, or GCP metadata). Pass an {@link SvidSource} to override.
   */
  evidence?: SvidSource;
  /**
   * Optional RFC 9396 access request sent at mint time; the attester grants at most what the workload
   * is entitled to.
   */
  authorizationDetails?: Array<Record<string, unknown>>;
  /**
   * The client's operator - who answers for this workload. Sent in the mint request body as
   * `operator`, so the attester (not the client) is what states it; an attester that does not know
   * this key ignores it, one that does can refuse to name an operator it cannot corroborate. When set,
   * it is also repeated at the token endpoint as the form parameter `operator` (compact JSON, sorted
   * keys) so an AS can populate RFC 8693 `may_act` from it without parsing the attestation; an AS that
   * does not know the parameter ignores it. Unset (or empty) sends nothing.
   */
  operator?: Record<string, unknown>;
  /** Instance-key signature algorithm (default `ES256`). */
  algorithm?: string;
  /** Refresh this long before the token expires (default 30s). */
  expirySkewSeconds?: number;
  /** Per-request HTTP timeout in milliseconds (default 20000). */
  timeoutMs?: number;
  /**
   * How to prove possession of the instance key at the token endpoint: the dedicated
   * `OAuth-Client-Attestation-PoP` JWT (`"attestation_pop_jwt"`, the default), or a `DPoP` proof
   * carrying the same challenge in `nonce` (`"dpop_combined"`).
   */
  popMethod?: "attestation_pop_jwt" | "dpop_combined";
  /**
   * Whether the attester-issued challenge also rides in the token-endpoint proof (the PoP's
   * `challenge` claim, or the DPoP `nonce`), on top of the mint-time instance proof it always
   * protects. The default `true` binds token issuance to the same challenge as the mint, so a captured
   * attestation cannot be redeemed for a token without it - but it requires an attester whose
   * challenge store tolerates being checked at both points. Some attesters treat a challenge as
   * consumed the moment the mint's instance proof uses it, and then reject a token request that
   * presents the same value as "unknown or expired" - set this `false` against one of those (the
   * challenge still protects the mint; only the token-endpoint copy is dropped).
   */
  challengeAtToken?: boolean;
  /**
   * When the attester advertises a `challenge_endpoint`, fail the flow if the challenge cannot be
   * fetched (default `true`). Set `false` to proceed without a challenge instead.
   */
  requireChallenge?: boolean;
  /**
   * Allow plain `http` for the PingFederate host and the endpoints the attester advertises (default
   * `false`). Loopback hosts (`localhost`, `127.0.0.1`, `::1`) are always allowed.
   */
  allowInsecure?: boolean;
  /**
   * Where to send log events (see docs/logging.md). Any object with `debug`, `info`, `warn` and
   * `error(msg, attrs)` works, `console` included. Unset, nothing is logged. Tokens, proofs,
   * attestations, SVIDs and key material are never logged.
   */
  logger?: Logger;
}

/** A minted token with everything needed to present it: its scheme and, for DPoP, the bound key. */
interface TokenState {
  accessToken: string;
  /** `"Bearer"` or `"DPoP"`. */
  tokenType: string;
  /** The instance key bound into the attestation that minted this token. */
  key: SigningKeyPair;
  expiresAt: number;
}

interface TokenResponse {
  access_token: string;
  expires_in?: number;
  token_type?: string;
}

const USE_DPOP_NONCE = "use_dpop_nonce";
const DPOP_NONCE_HEADER = "DPoP-Nonce";

/**
 * Gets and caches an access token from a PingFederate host using client attestation.
 *
 * @param pfHost the PingFederate host — `"pf.example.com"`, or a full base URL
 *   `"https://pf.example.com"`. Plain hostnames default to https.
 */
export class ClientAttestation {
  readonly baseUrl: string;
  readonly #evidence?: SvidSource;
  readonly #authorizationDetails?: Array<Record<string, unknown>>;
  readonly #operator?: Record<string, unknown>;
  readonly #challengeAtToken: boolean;
  readonly #algorithm: string;
  readonly #skew: number;
  readonly #timeoutMs: number;
  readonly #popMethod: "attestation_pop_jwt" | "dpop_combined";
  readonly #requireChallenge: boolean;
  readonly #allowInsecure: boolean;
  readonly #logger: Logger;

  /** The token, its type and its bound key: always replaced together, never one without the others. */
  #state: TokenState | null = null;
  #discovery: AttesterDiscovery | null = null;
  #refreshing: Promise<TokenState> | null = null;
  /** The last `DPoP-Nonce` each origin returned. */
  readonly #nonces = new Map<string, string>();

  constructor(pfHost: string, opts: ClientAttestationOptions = {}) {
    this.baseUrl = normalizeBaseUrl(pfHost);
    this.#evidence = opts.evidence;
    this.#authorizationDetails = opts.authorizationDetails;
    this.#operator = opts.operator && Object.keys(opts.operator).length > 0 ? opts.operator : undefined;
    this.#challengeAtToken = opts.challengeAtToken ?? true;
    this.#algorithm = opts.algorithm ?? "ES256";
    this.#skew = opts.expirySkewSeconds ?? DEFAULT_EXPIRY_SKEW_SECONDS;
    this.#timeoutMs = opts.timeoutMs ?? 20_000;
    this.#popMethod = opts.popMethod ?? "attestation_pop_jwt";
    this.#requireChallenge = opts.requireChallenge ?? true;
    this.#allowInsecure = opts.allowInsecure ?? false;
    this.#logger = opts.logger ?? NOOP_LOGGER;
    this.#checkSecure(this.baseUrl, "pfHost");
  }

  // ── public API ──────────────────────────────────────────────────────────────────────────────────
  /** Return a valid access token, minting a new one only when the cached one is near expiry. */
  async token(opts: { forceRefresh?: boolean } = {}): Promise<string> {
    return (await this.#current(opts)).accessToken;
  }

  /**
   * `{ Authorization: "<scheme> <token>" }`. For a Bearer token that is all a resource needs. For a
   * DPoP-bound token (`token_type` DPoP) the scheme is `DPoP` and every request ALSO needs a fresh
   * DPoP proof — use {@link requestHeaders} (or {@link fetch}) instead, which adds it.
   */
  async authorizationHeader(opts: { forceRefresh?: boolean } = {}): Promise<Record<string, string>> {
    const state = await this.#current(opts);
    return { Authorization: `${scheme(state)} ${state.accessToken}` };
  }

  /**
   * The headers to send to a resource for one request, obtaining or refreshing the token as needed.
   *
   * - Bearer token: `{ Authorization: "Bearer <t>" }`
   * - DPoP token: `{ Authorization: "DPoP <t>", DPoP: <proof> }` — a fresh proof signed by the key the
   *   token is bound to, for this `method` and `url`, carrying `ath` and the last `DPoP-Nonce` the
   *   url's origin returned, if any.
   */
  async requestHeaders(method: string, url: string, opts: { forceRefresh?: boolean } = {}): Promise<Record<string, string>> {
    const state = await this.#current(opts);
    const headers: Record<string, string> = { Authorization: `${scheme(state)} ${state.accessToken}` };
    if (isDpop(state)) {
      headers[DPOP_HEADER] = await new DpopProofBuilder(state.key)
        .method(method)
        .uri(url)
        .accessToken(state.accessToken)
        .nonce(this.#nonces.get(originOf(url)) ?? null)
        .build();
    }
    return headers;
  }

  /**
   * A `fetch` wrapper that attaches the token (refreshing it as needed) to the request. Same signature
   * as global `fetch`. For a DPoP-bound token it adds a fresh proof and, when the resource answers with
   * a `use_dpop_nonce` challenge and a `DPoP-Nonce`, resends ONCE with a proof carrying that nonce —
   * unless the body is a one-shot stream, which cannot be resent (the challenge response is returned).
   */
  async fetch(input: string | URL | Request, init: RequestInit = {}): Promise<Response> {
    const isRequest = typeof Request !== "undefined" && input instanceof Request;
    const url = isRequest ? (input as Request).url : String(input);
    const method = (init.method ?? (isRequest ? (input as Request).method : "GET")).toUpperCase();
    // A Request's own body is cloned so the retry can send it again.
    const nextInput = () => (isRequest ? (input as Request).clone() : input);

    let dpopBound = false;
    const send = async () => {
      const headers = new Headers(init.headers ?? (isRequest ? (input as Request).headers : undefined));
      const auth = await this.requestHeaders(method, url);
      dpopBound = DPOP_HEADER in auth;
      for (const [name, value] of Object.entries(auth)) headers.set(name, value);
      return fetch(nextInput(), { ...init, headers });
    };

    const first = await send();
    if (!dpopBound) return first;
    const nonce = first.headers.get(DPOP_NONCE_HEADER);
    if (nonce) this.#nonces.set(originOf(url), nonce);
    if (!nonce || !replayable(init.body) || !(await isNonceChallenge(first))) return first;
    emit(this.#logger, "info", "dpop.nonce_retry", { host: hostOf(url), status: first.status, at: "resource" });
    await first.body?.cancel().catch(() => undefined);
    return send();
  }

  /** The attester's `/.well-known/client-attester` document (fetched once, then cached). */
  async discovery(): Promise<AttesterDiscovery> {
    if (this.#discovery === null) {
      this.#discovery = await this.#getJson<AttesterDiscovery>("discover", "GET", this.baseUrl + WELL_KNOWN_PATH);
      emit(this.#logger, "debug", "discovery.fetched", { host: hostOf(this.baseUrl) });
    } else {
      emit(this.#logger, "debug", "discovery.cached", { host: hostOf(this.baseUrl) });
    }
    return this.#discovery;
  }

  // ── the flow ────────────────────────────────────────────────────────────────────────────────────
  /** The cached token state, or a freshly minted one. Concurrent callers share one refresh. */
  async #current(opts: { forceRefresh?: boolean }): Promise<TokenState> {
    const state = this.#state;
    if (!opts.forceRefresh && state && Date.now() < state.expiresAt) {
      emit(this.#logger, "debug", "token.cache_hit", {
        expires_in: Math.max(0, Math.round((state.expiresAt - Date.now()) / 1000)),
      });
      return state;
    }
    if (!this.#refreshing) {
      emit(this.#logger, "debug", "token.refreshing", {
        reason: opts.forceRefresh ? "forced" : state ? "expired" : "initial",
      });
      this.#refreshing = this.#refresh().finally(() => {
        this.#refreshing = null;
      });
    }
    return this.#refreshing;
  }

  async #refresh(): Promise<TokenState> {
    const { response, key } = await this.#runFlow();
    const expiresIn = response.expires_in;
    const state: TokenState = {
      accessToken: response.access_token,
      tokenType: typeof response.token_type === "string" && response.token_type ? response.token_type : "Bearer",
      key,
      expiresAt: expiresIn ? Date.now() + (Number(expiresIn) - this.#skew) * 1000 : 0,
    };
    this.#state = state;
    return state;
  }

  async #runFlow(): Promise<{ response: TokenResponse; key: SigningKeyPair }> {
    const doc = await this.discovery();
    const audience = doc.evidence_audience;
    if (!audience) {
      throw new ClientAttestationError("attester discovery document has no evidence_audience");
    }

    const evidenceSource = this.#evidence ?? (await autoDetectEvidence());
    const svid = await evidenceSource.fetch(audience);
    emit(this.#logger, "debug", "evidence.obtained", { source: evidenceSource.constructor?.name });

    const instanceKey = await SigningKeyPair.generate(this.#algorithm);
    const challenge = await this.#fetchChallenge(doc);
    const attestation = await this.#mint(doc, instanceKey, svid, challenge);

    // token_endpoint is advertised by current attesters; fall back to the standard PF path so an older
    // discovery document still works from the host alone.
    const tokenEndpoint = doc.token_endpoint || this.baseUrl + "/as/token.oauth2";
    this.#checkSecure(tokenEndpoint, "token_endpoint");
    const clientId = jwtSub(attestation);
    emit(this.#logger, "debug", "attestation.minted", {
      host: hostOf(doc.attestation_endpoint as string),
      client_id: clientId,
      alg: this.#algorithm,
    });
    // The PoP audience must be PF's configured issuer, which the attester advertises as pop_audience.
    // Falling back to the token endpoint URL only works when the dialed URL matches PF's issuer (no
    // proxy in between) — so prefer the advertised value.
    const popAudience = doc.pop_audience || tokenEndpoint;
    // See `challengeAtToken`: some attesters consume the challenge the moment the mint's instance
    // proof uses it, and reject a token request that presents the same value a second time. Against
    // one of those, only the mint gets the challenge.
    const tokenChallenge = this.#challengeAtToken ? challenge : undefined;

    const credential = new ClientAttestationCredential(attestation, instanceKey);
    const obtained = (response: TokenResponse) => {
      const expiresIn = Number(response.expires_in);
      emit(this.#logger, "info", "token.obtained", {
        host: hostOf(tokenEndpoint),
        client_id: clientId,
        token_type: typeof response.token_type === "string" && response.token_type ? response.token_type : "Bearer",
        expires_in: response.expires_in != null && Number.isFinite(expiresIn) ? expiresIn : undefined,
        pop_method: this.#popMethod,
      });
      return { response, key: instanceKey };
    };
    if (this.#popMethod !== "dpop_combined") {
      const headers = await credential.popHeaders(clientId, popAudience, tokenChallenge ?? null);
      return obtained(this.#tokenResponse(tokenEndpoint, await this.#postToken(tokenEndpoint, headers)));
    }

    // DPoP combined: the attester challenge rides as the DPoP nonce. If the AS demands its own nonce
    // (400 use_dpop_nonce + DPoP-Nonce), retry once with that — the server's demand wins.
    let res = await this.#postToken(tokenEndpoint, await credential.dpopHeaders("POST", tokenEndpoint, tokenChallenge ?? null));
    const serverNonce = res.headers.get(DPOP_NONCE_HEADER);
    if (serverNonce) this.#nonces.set(originOf(tokenEndpoint), serverNonce);
    if (res.status === 400 && serverNonce && jsonError(res.body) === USE_DPOP_NONCE) {
      emit(this.#logger, "info", "dpop.nonce_retry", { host: hostOf(tokenEndpoint), status: res.status, at: "token_endpoint" });
      res = await this.#postToken(tokenEndpoint, await credential.dpopHeaders("POST", tokenEndpoint, serverNonce));
    }
    return obtained(this.#tokenResponse(tokenEndpoint, res));
  }

  async #fetchChallenge(doc: AttesterDiscovery): Promise<string | undefined> {
    const endpoint = doc.challenge_endpoint;
    if (!endpoint) return undefined;
    this.#checkSecure(endpoint, "challenge_endpoint");
    // The attester advertised a challenge, so minting without one weakens replay protection: fail
    // closed unless the caller opted out with requireChallenge: false.
    let body: { attestation_challenge?: unknown };
    try {
      body = await this.#getJson<{ attestation_challenge?: unknown }>("challenge", "POST", endpoint);
    } catch (err) {
      if (!(err instanceof ClientAttestationError)) throw err;
      if (!this.#requireChallenge) {
        emit(this.#logger, "warn", "challenge.skipped", { host: hostOf(endpoint) });
        return undefined;
      }
      throw new ClientAttestationError(`could not fetch the attestation challenge from ${endpoint}: ${err.message}`, {
        status: err.status,
        body: err.body,
        cause: err,
      });
    }
    const challenge = body.attestation_challenge;
    if (typeof challenge === "string" && challenge) {
      emit(this.#logger, "debug", "challenge.fetched", { host: hostOf(endpoint) });
      return challenge;
    }
    if (!this.#requireChallenge) {
      emit(this.#logger, "warn", "challenge.skipped", { host: hostOf(endpoint) });
      return undefined;
    }
    throw new ClientAttestationError(`challenge endpoint ${endpoint} returned no attestation_challenge`);
  }

  async #mint(
    doc: AttesterDiscovery,
    instanceKey: SigningKeyPair,
    svid: string,
    challenge: string | undefined,
  ): Promise<string> {
    if (!doc.attestation_endpoint) {
      throw new ClientAttestationError("attester discovery document has no attestation_endpoint");
    }
    this.#checkSecure(doc.attestation_endpoint, "attestation_endpoint");
    const now = Math.floor(Date.now() / 1000);
    const proofClaims: Record<string, unknown> = {
      aud: doc.evidence_audience,
      jti: crypto.randomUUID(),
      iat: now,
    };
    if (challenge) proofClaims.challenge = challenge;
    const proof = await signCompact(proofClaims, instanceKey, INSTANCE_PROOF_TYP, false);

    // Evidence-first: no client_id. The attester maps the identity to a client.
    const body: Record<string, unknown> = {
      instance_key: instanceKey.publicJwk(),
      svid,
      proof,
    };
    if (this.#authorizationDetails) body.authorization_details = this.#authorizationDetails;
    if (this.#operator) body.operator = this.#operator;

    const response = await this.#getJson<{ attestation?: string }>(
      "mint",
      "POST",
      doc.attestation_endpoint,
      body,
    );
    if (!response.attestation) {
      throw new ClientAttestationError("attester response contained no attestation", {
        body: JSON.stringify(response),
      });
    }
    return response.attestation;
  }

  /** The parsed token response; a failure is logged as `http.failed` before it is thrown. */
  #tokenResponse(endpoint: string, res: HttpResponse): TokenResponse {
    try {
      return tokenResponse(res);
    } catch (err) {
      const reason = err instanceof TransportError ? failureReason(err) : res.ok ? "malformed" : "status";
      this.#failed("token", "POST", endpoint, reason, res.status);
      throw err;
    }
  }

  #failed(step: string, method: string, url: string, reason: string, status?: number): void {
    emit(this.#logger, "warn", "http.failed", { step, method, ...urlParts(url), status, reason });
  }

  #postToken(endpoint: string, authHeaders: Record<string, string>): Promise<HttpResponse> {
    const params = new URLSearchParams({ grant_type: "client_credentials" });
    // Extension parameter, sent only when configured: the attestation is the authoritative carrier,
    // this repeats the operator on the wire for an AS that maps it into may_act.
    if (this.#operator) params.set("operator", canonicalJson(this.#operator));
    const form = params.toString();
    return this.#send("token", endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
        ...authHeaders,
      },
      body: form,
    });
  }

  /** Refuse a non-https URL unless it is loopback or the caller passed `allowInsecure`. */
  #checkSecure(url: string, what: string): void {
    if (this.#allowInsecure) return;
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new ClientAttestationError(`${what} is not a valid URL: ${url}`);
    }
    if (parsed.protocol === "https:" || LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase())) return;
    throw new ClientAttestationError(
      `${what} must use https: ${url} (loopback hosts are exempt; pass allowInsecure: true to override)`,
    );
  }

  async #getJson<T>(step: string, method: string, url: string, jsonBody?: Record<string, unknown>): Promise<T> {
    const headers: Record<string, string> = { Accept: "application/json" };
    let body: string | undefined;
    if (jsonBody !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(jsonBody);
    }
    const res = await this.#send(step, url, { method, headers, body });
    try {
      return jsonOk<T>(res, { allowEmpty: true });
    } catch (err) {
      this.#failed(step, method, url, failureReason(err), res.status);
      throw err;
    }
  }

  /**
   * Every call the flow makes goes through the shared transport, with this client's timeout. A call that
   * gets no usable response is logged as `http.failed`.
   */
  async #send(step: string, url: string, opts: HttpRequestOptions): Promise<HttpResponse> {
    try {
      return await request(url, { ...opts, timeoutMs: this.#timeoutMs });
    } catch (err) {
      const status = err instanceof ClientAttestationError ? err.status : undefined;
      this.#failed(step, opts.method ?? "GET", url, failureReason(err), status);
      throw err;
    }
  }
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

function tokenResponse(res: HttpResponse): TokenResponse {
  if (!res.ok) {
    throw new ClientAttestationError(`token endpoint returned HTTP ${res.status}`, {
      status: res.status,
      body: res.body,
    });
  }
  const parsed = jsonOk<{ access_token?: string; expires_in?: number; token_type?: string }>(res, { allowEmpty: true });
  if (!parsed.access_token) {
    throw new ClientAttestationError("token endpoint returned no access_token", { body: res.body });
  }
  return parsed as TokenResponse;
}

function isDpop(state: TokenState): boolean {
  return state.tokenType.toLowerCase() === "dpop";
}

function scheme(state: TokenState): string {
  return isDpop(state) ? "DPoP" : "Bearer";
}

/** `scheme://host[:port]` of a URL, the key DPoP nonces are remembered under. */
function originOf(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}

/** The `error` member of a JSON object body, or undefined. */
function jsonError(body: string): unknown {
  try {
    return (JSON.parse(body) as { error?: unknown } | null)?.error;
  } catch {
    return undefined;
  }
}

/** Can this fetch body be sent a second time? One-shot streams cannot. */
function replayable(body: RequestInit["body"]): boolean {
  if (body == null) return true;
  return !(typeof ReadableStream !== "undefined" && body instanceof ReadableStream) &&
    !(typeof (body as { [Symbol.asyncIterator]?: unknown })[Symbol.asyncIterator] === "function");
}

/**
 * RFC 9449 section 9: a resource asks for a nonce with 401 + `WWW-Authenticate: DPoP error="use_dpop_nonce"`;
 * section 8 (and some resources) use a 400 JSON `{"error":"use_dpop_nonce"}`.
 */
async function isNonceChallenge(res: Response): Promise<boolean> {
  if (res.status === 401) {
    const challenge = res.headers.get("WWW-Authenticate") ?? "";
    return /(^|,)\s*DPoP\b/i.test(challenge) && /error\s*=\s*"?use_dpop_nonce"?/i.test(challenge);
  }
  if (res.status === 400) {
    return jsonError(await res.clone().text()) === USE_DPOP_NONCE;
  }
  return false;
}

/**
 * Compact JSON with object keys sorted at every depth and non-ASCII escaped as `\uXXXX` - the same
 * bytes as Python's `json.dumps(value, separators=(",", ":"), sort_keys=True)`.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value)).replace(
    /[\u0080-\uffff]/g,
    (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(obj).sort().map((k) => [k, sortKeys(obj[k])]));
  }
  return value;
}

export function normalizeBaseUrl(pfHost: string): string {
  let host = (pfHost ?? "").trim().replace(/\/+$/, "");
  if (!host) {
    throw new Error("pfHost is required");
  }
  if (!host.includes("://")) {
    host = "https://" + host;
  }
  return host;
}

export function jwtSub(compactJwt: string): string {
  const payload = compactJwt.split(".")[1] ?? "";
  let claims: { sub?: string } | null;
  try {
    claims = JSON.parse(utf8Decode(base64url.decode(payload))) as { sub?: string } | null;
  } catch {
    throw new ClientAttestationError("minted attestation is not a well-formed JWT");
  }
  if (!claims?.sub) {
    throw new ClientAttestationError("minted attestation has no sub (client id)");
  }
  return claims.sub;
}
