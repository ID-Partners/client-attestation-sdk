/**
 * One call to get an access token with client attestation.
 *
 * Point it at an attester (PingFederate by default) and call `.token()`. It runs the whole flow:
 *
 *     discover -> get platform identity (evidence) -> get a challenge -> mint the attestation ->
 *     call the token endpoint with the attestation headers -> cache the access token
 *
 * The workload sends no client secret and no client_id. Its only credential is the attestation, built
 * from the identity its runtime already gives it (auto-detected; see `evidence.ts`).
 *
 *     import { ClientAttestation } from "@idpartners/client-attestation-sdk";
 *
 *     const ca = new ClientAttestation("pf.example.com", { evidenceAudience: "https://attester.example.com/evidence" });
 *     const token = await ca.token();                       // cached until it nears expiry
 *
 *     // the fetch wrapper attaches the token (and a DPoP proof for a DPoP-bound token):
 *     await ca.fetch("https://api.example.com/things");
 *     // or build the headers for any other client:
 *     const headers = await ca.requestHeaders("GET", "https://api.example.com/things");
 */
import { base64url } from "jose";

import { checkHtu, DpopProofBuilder, htuParts, normalizeHtu } from "./builders.js";
import { ClientAttestationCredential, DPOP_HEADER } from "./credential.js";
import { ClientAttestationError, TransportError } from "./errors.js";
import { autoDetectEvidence } from "./evidence.js";
import {
  type AttesterMetadata,
  type AttesterProfile,
  type AttesterTransport,
  MintRequest,
  PingFederateProfile,
  metadataDocument,
} from "./attester.js";
import { checkSecure, jsonOk, request, snippet, type HttpRequestOptions, type HttpResponse } from "./http.js";
import { emit, failureReason, hostOf, NOOP_LOGGER, urlParts, type Logger } from "./logging.js";
import { monotonicMs, utf8Decode } from "./runtime.js";
import { SigningKeyPair } from "./signing-key-pair.js";
import type { SvidSource } from "./svid-source.js";

export const ATTESTATION_HEADER = "OAuth-Client-Attestation";
export const POP_HEADER = "OAuth-Client-Attestation-PoP";
/** Refresh this many seconds before the token actually expires, so a token is never used at the edge. */
export const DEFAULT_EXPIRY_SKEW_SECONDS = 30;
/** The PoP method names, case-sensitive, used by both the constructor's check and the flow. */
type PopMethod = Exclude<NonNullable<ClientAttestationOptions["popMethod"]>, "">;
const POP_JWT = "attestation_pop_jwt" satisfies PopMethod;
const DPOP_COMBINED = "dpop_combined" satisfies PopMethod;
const POP_METHODS: readonly PopMethod[] = [POP_JWT, DPOP_COMBINED];
const PIN_REQUIRED =
  "evidenceAudience is required: set it to the audience your attester expects the workload's " +
  "identity token for, so the attester's discovery document can't choose it";

export { ClientAttestationError, TransportError } from "./errors.js";

/** The attester's discovery document (PingFederate: `/.well-known/client-attester`). */
export interface AttesterDiscovery {
  [member: string]: unknown;
  evidence_audience?: string;
  attestation_endpoint?: string;
  challenge_endpoint?: string;
  token_endpoint?: string;
  pop_audience?: string;
}

/** Options for {@link ClientAttestation}. */
export interface ClientAttestationOptions {
  /**
   * The attester's host, when the options object is the only argument. The positional argument wins
   * when both are given.
   */
  attesterUrl?: string;
  /**
   * The attester profile that discovers the attester and mints the attestation. Default
   * {@link PingFederateProfile}, the behaviour of every earlier release. See docs/attester-profiles.md.
   */
  profile?: AttesterProfile;
  /**
   * Static attester metadata (evidence audience, attestation and token endpoints, optionally challenge
   * endpoint and PoP audience). When set, no discovery request is made; the profile still mints.
   */
  metadata?: AttesterMetadata;
  /**
   * The audience the workload's platform identity token is requested for, which the attester's
   * discovery document must name. Required unless `metadata` is given: every evidence source (GCP,
   * AWS, Azure, SPIRE) fetches a token for whatever audience it is asked for, so without a pin an
   * attester could have the workload mint a token for another service that trusts it. A missing pin or
   * a different discovered audience throws {@link ClientAttestationError} before any evidence is
   * fetched. With static `metadata`, the pin is optional and, when given, must match
   * `metadata.evidenceAudience`.
   */
  evidenceAudience?: string;
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
  /** Refresh this long before the token expires (default 30s). Must be a finite number, not negative. */
  expirySkewSeconds?: number;
  /** Per-request HTTP timeout in milliseconds (default 20000). */
  timeoutMs?: number;
  /**
   * How to prove possession of the instance key at the token endpoint: the dedicated
   * `OAuth-Client-Attestation-PoP` JWT (`"attestation_pop_jwt"`, the default), or a `DPoP` proof
   * carrying the same challenge in `nonce` (`"dpop_combined"`). `undefined`, `null` or `""` means the
   * default. The names are case-sensitive; the constructor throws a `RangeError` for any other value,
   * including one with surrounding whitespace or a non-string.
   */
  popMethod?: "attestation_pop_jwt" | "dpop_combined" | "" | null;
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
   * Allow plain `http` for the attester URL and the endpoints the attester advertises (default
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
  /** {@link monotonicMs} deadline; 0 => not cached. A wall-clock step cannot extend it. */
  expiresAt: number;
}

interface TokenResponse {
  access_token: string;
  expires_in?: unknown;
  token_type?: string;
}

const USE_DPOP_NONCE = "use_dpop_nonce";
const DPOP_NONCE_HEADER = "DPoP-Nonce";
/** At most this much of a 400 body is read to look for `use_dpop_nonce`; a longer body is not a challenge. */
const MAX_NONCE_CHALLENGE_BODY = 64 * 1024;
/** RFC 9449 nonces are short opaque strings: a longer `DPoP-Nonce` is ignored, as if there were none. */
const MAX_DPOP_NONCE_LENGTH = 1024;
/**
 * At most this many origins' nonces are remembered; a new origin over the cap replaces the one stored
 * longest ago (it costs that origin one challenge).
 */
const MAX_DPOP_NONCE_ORIGINS = 256;
/** A token is cached for at most this long (seconds), whatever `expires_in` the token endpoint gives. */
const MAX_TOKEN_LIFETIME_SECONDS = 24 * 60 * 60;

/** What the https check calls the URL a profile's call goes to, by step. */
const STEP_LABELS: Record<string, string> = {
  discover: "attesterUrl",
  mint: "attestation_endpoint",
  challenge: "challenge_endpoint",
};

/**
 * Gets and caches an access token using client attestation.
 *
 * `new ClientAttestation(attesterUrl, opts)`, or `new ClientAttestation(opts)` with `opts.metadata` (no
 * discovery) or a custom `opts.profile`. A client that discovers its attester needs `opts.evidenceAudience`.
 *
 * @param attesterUrl the attester's host — `"pf.example.com"`, or a full base URL
 *   `"https://pf.example.com"`. Plain hostnames default to https. Optional when `metadata` or `profile`
 *   is given.
 */
export class ClientAttestation {
  /** The normalised attester URL, or `""` when the client was built from static metadata alone. */
  readonly baseUrl: string;
  readonly #profile: AttesterProfile;
  readonly #evidence?: SvidSource;
  readonly #authorizationDetails?: Array<Record<string, unknown>>;
  readonly #operator?: Record<string, unknown>;
  readonly #challengeAtToken: boolean;
  readonly #algorithm: string;
  readonly #skew: number;
  readonly #timeoutMs: number;
  readonly #popMethod: PopMethod;
  readonly #requireChallenge: boolean;
  readonly #allowInsecure: boolean;
  readonly #logger: Logger;

  /** The token, its type and its bound key: always replaced together, never one without the others. */
  #state: TokenState | null = null;
  #metadata: AttesterMetadata | null;
  readonly #staticMetadata: boolean;
  readonly #evidenceAudience: string | undefined;
  #refreshing: Promise<TokenState> | null = null;
  /** The last `DPoP-Nonce` each origin returned, oldest first. */
  readonly #nonces = new Map<string, string>();

  constructor(attesterUrl?: string | ClientAttestationOptions, opts: ClientAttestationOptions = {}) {
    if (typeof attesterUrl === "object" && attesterUrl !== null) {
      opts = attesterUrl;
      attesterUrl = undefined;
    }
    const url = attesterUrl ?? opts.attesterUrl;
    this.#profile = opts.profile ?? new PingFederateProfile();
    this.#metadata = opts.metadata ?? null;
    this.#staticMetadata = this.#metadata !== null;
    this.#evidenceAudience = opts.evidenceAudience;
    this.#evidence = opts.evidence;
    this.#authorizationDetails = opts.authorizationDetails;
    this.#operator = opts.operator && Object.keys(opts.operator).length > 0 ? opts.operator : undefined;
    this.#challengeAtToken = opts.challengeAtToken ?? true;
    this.#algorithm = opts.algorithm ?? "ES256";
    this.#skew = opts.expirySkewSeconds ?? DEFAULT_EXPIRY_SKEW_SECONDS;
    if (!Number.isFinite(this.#skew) || this.#skew < 0) {
      throw new RangeError(`expirySkewSeconds must be a finite number, not negative: ${this.#skew}`);
    }
    this.#timeoutMs = opts.timeoutMs ?? 20_000;
    this.#popMethod = checkPopMethod(opts.popMethod);
    this.#requireChallenge = opts.requireChallenge ?? true;
    this.#allowInsecure = opts.allowInsecure ?? false;
    this.#logger = opts.logger ?? NOOP_LOGGER;
    if (url === undefined && (opts.metadata || opts.profile)) {
      this.baseUrl = "";
    } else {
      this.baseUrl = normalizeBaseUrl(url as string);
      this.#checkSecure(this.baseUrl, "attesterUrl");
    }
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
   *
   * `url` must be https, like every other URL the client sends a credential to (loopback hosts and
   * `allowInsecure` excepted).
   *
   * Pass the exact URL your HTTP client sends: the proof is only valid for the `htu` it names. A url with
   * a backslash, ASCII whitespace or a control character before its query or fragment is refused with a
   * {@link ClientAttestationError}, because URL parsers disagree on where it goes. For a DPoP-bound token,
   * so is a url that is not an absolute http(s) URL with a valid ASCII host, port and path; with
   * `popMethod: "dpop_combined"` that is checked before the token is fetched. The path is signed as
   * written, so pass `new URL(u).href` (what `fetch` sends) rather than a hand-written string: `fetch` may
   * escape characters (a `{`, say) that the string leaves as they are. {@link fetch} does this for you.
   */
  async requestHeaders(method: string, url: string, opts: { forceRefresh?: boolean } = {}): Promise<Record<string, string>> {
    return this.#requestHeaders(method, url, opts);
  }

  /**
   * {@link requestHeaders}, with the proof carrying `nonce` when given (the nonce of the challenge being
   * answered) instead of the origin's remembered one.
   */
  async #requestHeaders(
    method: string,
    url: string,
    opts: { forceRefresh?: boolean },
    nonce?: string,
  ): Promise<Record<string, string>> {
    this.#checkSecure(url, "resource URL");
    // A client configured for DPoP checks the whole htu before fetching the token, so a URL with no htu
    // never costs a mint and token request on a cold cache. Otherwise only what parsers disagree on is
    // refused up front: a Bearer token carries no htu.
    try {
      if (this.#popMethod === DPOP_COMBINED) normalizeHtu(url);
      else checkHtu(url);
    } catch (err) {
      throw new ClientAttestationError((err as Error).message);
    }
    const state = await this.#current(opts);
    const headers: Record<string, string> = { Authorization: `${scheme(state)} ${state.accessToken}` };
    if (isDpop(state)) {
      // Also for a DPoP token from a client not configured for DPoP (the AS chose the token type).
      try {
        normalizeHtu(url);
      } catch (err) {
        throw new ClientAttestationError((err as Error).message);
      }
      headers[DPOP_HEADER] = await new DpopProofBuilder(state.key)
        .method(method)
        .uri(url)
        .accessToken(state.accessToken)
        .nonce(nonce ?? this.#nonces.get(originOf(url)) ?? null)
        .build();
    }
    return headers;
  }

  /**
   * A `fetch` wrapper that attaches the token (refreshing it as needed) to the request. Same signature
   * as global `fetch`. For a DPoP-bound token it adds a fresh proof and, when the resource answers with
   * a `use_dpop_nonce` challenge and a `DPoP-Nonce`, resends ONCE with a proof carrying that nonce —
   * unless the body is a one-shot stream, which cannot be resent (the challenge response is returned).
   * Redirects are returned without following them, even if the input or init requests redirect following.
   */
  async fetch(input: string | URL | Request, init: RequestInit = {}): Promise<Response> {
    const isRequest = typeof Request !== "undefined" && input instanceof Request;
    // The proof names the URL as fetch parses it (WHATWG), which is where the request goes.
    const url = isRequest ? (input as Request).url : parsedHref(String(input));
    const method = (init.method ?? (isRequest ? (input as Request).method : "GET")).toUpperCase();
    // A Request's own body is cloned so the retry can send it again.
    const nextInput = () => (isRequest ? (input as Request).clone() : input);

    let dpopBound = false;
    const send = async (nonce?: string) => {
      const headers = new Headers(init.headers ?? (isRequest ? (input as Request).headers : undefined));
      const auth =
        nonce === undefined
          ? await this.requestHeaders(method, url)
          : await this.#requestHeaders(method, url, {}, nonce);
      dpopBound = DPOP_HEADER in auth;
      for (const [name, value] of Object.entries(auth)) headers.set(name, value);
      return fetch(nextInput(), { ...init, headers, redirect: "manual" });
    };

    const first = await send();
    if (!dpopBound) return first;
    const nonce = usableNonce(first.headers.get(DPOP_NONCE_HEADER));
    if (nonce) this.#rememberNonce(url, nonce);
    if (!nonce || !replayable(init.body) || !(await isNonceChallenge(first, this.#timeoutMs))) return first;
    emit(this.#logger, "info", "dpop.nonce_retry", { host: hostOf(url), status: first.status, at: "resource" });
    await first.body?.cancel().catch(() => undefined);
    // Answer this challenge with its own nonce, not one a concurrent response stored since.
    return send(nonce);
  }

  /** Store `nonce` as the origin's latest, forgetting the origin stored longest ago over the cap. */
  #rememberNonce(url: string, nonce: string): void {
    const key = originOf(url);
    this.#nonces.delete(key);
    if (this.#nonces.size >= MAX_DPOP_NONCE_ORIGINS) {
      this.#nonces.delete(this.#nonces.keys().next().value as string);
    }
    this.#nonces.set(key, nonce);
  }

  /**
   * The attester's discovery document (PingFederate: `/.well-known/client-attester`), fetched once and
   * then cached. With static `metadata`, the fields that were given, in the document's snake_case.
   */
  async discovery(): Promise<AttesterDiscovery> {
    return metadataDocument(await this.attesterMetadata()) as AttesterDiscovery;
  }

  /** The attester's endpoints: the static `metadata`, or what the profile discovered (once, then cached). */
  async attesterMetadata(): Promise<AttesterMetadata> {
    const host = this.baseUrl ? hostOf(this.baseUrl) : undefined;
    if (this.#metadata === null) {
      this.#metadata = await this.#profile.discover(this.#transport(), this.baseUrl || undefined);
      emit(this.#logger, "debug", "discovery.fetched", { host });
    } else {
      emit(this.#logger, "debug", "discovery.cached", { host });
    }
    return this.#metadata;
  }

  /** The transport handed to the profile: this client's https rule, timeout and logging. */
  #transport(): AttesterTransport {
    return {
      requestJson: (step, method, url, body) => {
        this.#checkSecure(url, STEP_LABELS[step] ?? `${step} URL`);
        return this.#getJson<Record<string, unknown>>(step, method, url, body);
      },
    };
  }

  // ── the flow ────────────────────────────────────────────────────────────────────────────────────
  /** The cached token state, or a freshly minted one. Concurrent callers share one refresh. */
  async #current(opts: { forceRefresh?: boolean }): Promise<TokenState> {
    const state = this.#state;
    const now = monotonicMs();
    if (!opts.forceRefresh && state && now < state.expiresAt) {
      emit(this.#logger, "debug", "token.cache_hit", {
        expires_in: Math.max(0, Math.round((state.expiresAt - now) / 1000)),
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
    const lifetime = tokenLifetime(response.expires_in);
    const state: TokenState = {
      accessToken: response.access_token,
      tokenType: typeof response.token_type === "string" && response.token_type ? response.token_type : "Bearer",
      key,
      expiresAt: lifetime !== undefined ? monotonicMs() + (lifetime - this.#skew) * 1000 : 0,
    };
    this.#state = state;
    return state;
  }

  async #runFlow(): Promise<{ response: TokenResponse; key: SigningKeyPair }> {
    // The constructor refused anything else. A value that still isn't one of the two fails here, before
    // any request, rather than falling back to a PoP JWT.
    if (!POP_METHODS.includes(this.#popMethod)) {
      throw new ClientAttestationError(`unsupported popMethod ${describe(this.#popMethod)}`);
    }
    if (!this.#evidenceAudience && !this.#staticMetadata) throw new ClientAttestationError(PIN_REQUIRED);
    const meta = await this.attesterMetadata();
    const audience = meta.evidenceAudience;
    if (!audience) {
      throw new ClientAttestationError("attester discovery document has no evidence_audience");
    }
    if (this.#evidenceAudience && audience !== this.#evidenceAudience) {
      throw new ClientAttestationError(
        `the attester asks for evidence for ${JSON.stringify(audience)}, but evidenceAudience is ` +
          JSON.stringify(this.#evidenceAudience),
      );
    }

    const evidenceSource = this.#evidence ?? (await autoDetectEvidence());
    const svid = await evidenceSource.fetch(audience);
    emit(this.#logger, "debug", "evidence.obtained", { source: evidenceSource.constructor?.name });

    const instanceKey = await SigningKeyPair.generate(this.#algorithm);
    const challenge = await this.#fetchChallenge(meta.challengeEndpoint);
    const { attestation } = await this.#profile.mint(
      this.#transport(),
      meta,
      new MintRequest({
        instanceKey,
        evidence: svid,
        challenge,
        authorizationDetails: this.#authorizationDetails,
        operator: this.#operator,
      }),
    );

    // The profile resolves the token endpoint (PingFederate: the advertised one, else the standard path
    // on the attester host).
    const tokenEndpoint = meta.tokenEndpoint;
    if (!tokenEndpoint) throw new ClientAttestationError("attester metadata has no token_endpoint");
    this.#checkSecure(tokenEndpoint, "token_endpoint");
    const clientId = jwtSub(attestation);
    emit(this.#logger, "debug", "attestation.minted", {
      host: meta.attestationEndpoint ? hostOf(meta.attestationEndpoint) : undefined,
      client_id: clientId,
      alg: this.#algorithm,
    });
    // The PoP audience must be PF's configured issuer, which the attester advertises as pop_audience.
    // Falling back to the token endpoint URL only works when the dialed URL matches PF's issuer (no
    // proxy in between) — so prefer the advertised value.
    const popAudience = meta.popAudience || tokenEndpoint;
    // See `challengeAtToken`: some attesters consume the challenge the moment the mint's instance
    // proof uses it, and reject a token request that presents the same value a second time. Against
    // one of those, only the mint gets the challenge.
    const tokenChallenge = this.#challengeAtToken ? challenge : undefined;

    const credential = new ClientAttestationCredential(attestation, instanceKey);
    const obtained = (response: TokenResponse) => {
      const lifetime = tokenLifetime(response.expires_in);
      emit(this.#logger, "info", "token.obtained", {
        host: hostOf(tokenEndpoint),
        client_id: clientId,
        token_type: typeof response.token_type === "string" && response.token_type ? response.token_type : "Bearer",
        expires_in: lifetime !== undefined ? Math.trunc(lifetime) : undefined,
        pop_method: this.#popMethod,
      });
      return { response, key: instanceKey };
    };
    if (this.#popMethod === POP_JWT) {
      const headers = await credential.popHeaders(clientId, popAudience, tokenChallenge ?? null);
      return obtained(this.#tokenResponse(tokenEndpoint, await this.#postToken(tokenEndpoint, headers)));
    }

    // DPoP combined, the only other value (checked at the top of the flow): the attester challenge rides
    // as the DPoP nonce. If the AS demands its own nonce (400 use_dpop_nonce + DPoP-Nonce), retry once
    // with that — the server's demand wins.
    let res = await this.#postToken(tokenEndpoint, await credential.dpopHeaders("POST", tokenEndpoint, tokenChallenge ?? null));
    const serverNonce = usableNonce(res.headers.get(DPOP_NONCE_HEADER));
    if (serverNonce) this.#rememberNonce(tokenEndpoint, serverNonce);
    if (res.status === 400 && serverNonce && jsonError(res.body) === USE_DPOP_NONCE) {
      emit(this.#logger, "info", "dpop.nonce_retry", { host: hostOf(tokenEndpoint), status: res.status, at: "token_endpoint" });
      res = await this.#postToken(tokenEndpoint, await credential.dpopHeaders("POST", tokenEndpoint, serverNonce));
    }
    return obtained(this.#tokenResponse(tokenEndpoint, res));
  }

  async #fetchChallenge(endpoint: string | undefined): Promise<string | undefined> {
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
    checkSecure(url, what, this.#allowInsecure);
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

function tokenResponse(res: HttpResponse): TokenResponse {
  if (!res.ok) {
    throw new ClientAttestationError(`token endpoint returned HTTP ${res.status}`, {
      status: res.status,
      body: snippet(res.body),
    });
  }
  const parsed = jsonOk<{ access_token?: string; expires_in?: unknown; token_type?: string }>(res, { allowEmpty: true });
  if (!parsed.access_token) {
    // No body: a 2xx token response may hold the token under another name.
    throw new ClientAttestationError("token endpoint returned no access_token");
  }
  return parsed as TokenResponse;
}

/**
 * How long to cache a token, in seconds: `expires_in` as a JSON number, or a string of decimal digits,
 * capped at {@link MAX_TOKEN_LIFETIME_SECONDS}. Anything else - missing, null, not a number, not finite,
 * zero or negative - is undefined, and the token is not cached, as with no `expires_in` at all.
 */
function tokenLifetime(expiresIn: unknown): number | undefined {
  let seconds: number;
  if (typeof expiresIn === "number") seconds = expiresIn;
  else if (typeof expiresIn === "string" && /^[0-9]+(\.[0-9]+)?$/.test(expiresIn)) seconds = Number(expiresIn);
  else return undefined;
  if (!Number.isFinite(seconds) || seconds <= 0) return undefined;
  return Math.min(seconds, MAX_TOKEN_LIFETIME_SECONDS);
}

function isDpop(state: TokenState): boolean {
  return state.tokenType.toLowerCase() === "dpop";
}

function scheme(state: TokenState): string {
  return isDpop(state) ? "DPoP" : "Bearer";
}

/** A `DPoP-Nonce` value, or null when there is none or it is longer than {@link MAX_DPOP_NONCE_LENGTH}. */
function usableNonce(nonce: string | null): string | null {
  return nonce && nonce.length <= MAX_DPOP_NONCE_LENGTH ? nonce : null;
}

/** `url` as WHATWG URL parsing (and so fetch) serialises it, or as given when it does not parse. */
function parsedHref(url: string): string {
  try {
    return new URL(url).href;
  } catch {
    return url;
  }
}

/**
 * `scheme://host[:port]` of a URL as its `htu` names it ({@link htuParts}), the key DPoP nonces are
 * remembered under. A URL that rule refuses is its own key.
 */
function originOf(url: string): string {
  try {
    return htuParts(url)[0];
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
 * section 8 (and some resources) use a 400 JSON `{"error":"use_dpop_nonce"}`. The 400 body is read from a
 * clone, at most {@link MAX_NONCE_CHALLENGE_BODY} bytes and for at most `timeoutMs`, so the caller still
 * gets the whole body.
 */
async function isNonceChallenge(res: Response, timeoutMs: number): Promise<boolean> {
  if (res.status === 401) {
    const challenge = res.headers.get("WWW-Authenticate") ?? "";
    return /(^|,)\s*DPoP\b/i.test(challenge) && /error\s*=\s*"?use_dpop_nonce"?/i.test(challenge);
  }
  if (res.status === 400) {
    const body = await peekBody(res, MAX_NONCE_CHALLENGE_BODY, timeoutMs);
    return body !== undefined && jsonError(body) === USE_DPOP_NONCE;
  }
  return false;
}

/**
 * The text of `res`'s body read from a clone, or undefined when it is longer than `maxBytes`, fails, or is
 * not complete within `timeoutMs`. The clone is cancelled once read, so no more than about `maxBytes` is
 * buffered for the caller's copy.
 */
async function peekBody(res: Response, maxBytes: number, timeoutMs: number): Promise<string | undefined> {
  const reader = res.clone().body?.getReader();
  if (!reader) return "";
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<undefined>((resolve) => {
    timer = setTimeout(() => resolve(undefined), timeoutMs);
  });
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const next = await Promise.race([reader.read(), expired]);
      if (next === undefined) return undefined;
      if (next.done) break;
      total += next.value.byteLength;
      if (total > maxBytes) return undefined;
      chunks.push(next.value);
    }
  } catch {
    return undefined;
  } finally {
    clearTimeout(timer);
    reader.cancel().catch(() => undefined);
  }
  const all = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    all.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return utf8Decode(all);
}

/**
 * Compact JSON with object keys sorted at every depth and non-ASCII escaped as `\uXXXX` - the same
 * bytes as Python's `json.dumps(value, separators=(",", ":"), sort_keys=True)`.
 *
 * @internal
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

/**
 * The PoP method to use. `undefined`, `null` or `""` (unset) is the default; any other value must be
 * exactly one of the two the draft names (case-sensitive), so a misspelt value can't quietly send a PoP
 * JWT (vectors/pop-method.json).
 */
function checkPopMethod(popMethod: unknown): PopMethod {
  if (popMethod === undefined || popMethod === null || popMethod === "") return POP_JWT;
  const known = POP_METHODS.find((name) => name === popMethod);
  if (known === undefined) {
    throw new RangeError(`popMethod must be "${POP_JWT}" or "${DPOP_COMBINED}", got ${describe(popMethod)}`);
  }
  return known;
}

/** A value for an error message: JSON where that works, never a throw (BigInt, a cycle, a symbol). */
function describe(value: unknown): string {
  try {
    const json = JSON.stringify(value);
    if (json !== undefined) return json;
  } catch {
    // fall through
  }
  try {
    return typeof value === "bigint" ? `${value}n` : String(value);
  } catch {
    return Object.prototype.toString.call(value);
  }
}

/** @internal */
export function normalizeBaseUrl(attesterUrl: string): string {
  let host = (attesterUrl ?? "").trim().replace(/\/+$/, "");
  if (!host) {
    throw new Error("attesterUrl is required");
  }
  if (!host.includes("://")) {
    host = "https://" + host;
  }
  return host;
}

/** @internal */
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
