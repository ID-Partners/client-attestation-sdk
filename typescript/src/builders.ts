/**
 * Builders for the attestation, PoP and DPoP JWTs (draft-ietf-oauth-attestation-based-client-auth).
 */
import { base64url, type JWK } from "jose";

import { SigningKeyPair, requireText, signCompact } from "./signing-key-pair.js";
import { utf8Encode } from "./runtime.js";
import { type JwsSigner, signExternal } from "./signer.js";

export const ATTESTATION_TYP = "oauth-client-attestation+jwt";
export const POP_TYP = "oauth-client-attestation-pop+jwt";
export const DPOP_TYP = "dpop+jwt";

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Builds a Client Attestation JWT — the credential a Client Attester issues to name a client
 * (`sub`) and bind its instance key via `cnf.jwk`. Attester side; sign with the attester's key.
 */
export class ClientAttestationBuilder {
  readonly #attesterKey: SigningKeyPair | JwsSigner;
  readonly #issuer: string;
  #clientId: string | null = null;
  #cnfJwk: JWK | null = null;
  #issuedAt: number | null = null;
  #expiresAt: number | null = null;
  #ttl: number | null = null;
  #authorizationDetails: unknown[] | null = null;
  #workload: Record<string, unknown> | null = null;
  #operator: Record<string, unknown> | null = null;

  constructor(attesterKey: SigningKeyPair | JwsSigner, issuer: string) {
    this.#attesterKey = attesterKey;
    this.#issuer = requireText(issuer, "issuer");
  }

  /** The client being attested — becomes the attestation `sub` (= `client_id`). */
  clientId(clientId: string): this {
    this.#clientId = clientId;
    return this;
  }

  /**
   * Binds the client instance key as `cnf.jwk`: an EC (`crv` P-256, P-384 or P-521, `x`, `y`) or RSA
   * (`n`, `e`) public key. Throws for one carrying private or secret members (`d`, `p`, `q`, `dp`, `dq`,
   * `qi`, `oth`, `k`) or another `kty`. Only those members and an optional `kid` are copied into the
   * attestation.
   */
  confirmationJwk(publicInstanceJwk: JWK): this {
    this.#cnfJwk = confirmationJwkMembers(publicInstanceJwk);
    return this;
  }

  /** Convenience: binds the public half of the given instance key as `cnf.jwk`. */
  confirmationKey(instanceKey: SigningKeyPair): this {
    return this.confirmationJwk(instanceKey.publicJwk());
  }

  issuedAt(epochSeconds: number): this {
    this.#issuedAt = epochSeconds;
    return this;
  }

  /** Sets an absolute `exp`. */
  expiresAt(epochSeconds: number): this {
    this.#expiresAt = epochSeconds;
    return this;
  }

  /** Sets `exp` to `iat + seconds`. */
  expiresIn(seconds: number): this {
    this.#ttl = seconds;
    return this;
  }

  /** The optional RFC 9396 `authorization_details` entitlement the attester asserts. */
  authorizationDetails(details: unknown[]): this {
    this.#authorizationDetails = details;
    return this;
  }

  /** Optional attester-asserted `workload` attributes. */
  workload(workload: Record<string, unknown>): this {
    this.#workload = workload;
    return this;
  }

  /**
   * Names the client's OPERATOR — the human or organisation accountable for running this client,
   * as distinct from the client itself (`sub`) and from the principal it acts for.
   *
   * Deliberately a top-level claim rather than a member of `workload`: `workload` describes the
   * running software, whereas the operator is an accountability statement about who answers for
   * it. It is per-client and static, so it does not affect how far an attestation can be cached.
   *
   * The shape mirrors RFC 8693 `may_act` (`{ sub: ..., iss: ... }`) on purpose. An AS that wants
   * the operator to become the party authorised to act for the subject can lift this straight
   * into `may_act`; `iss` names the OP the operator's `sub` is meaningful in, so the identifier is
   * not ambiguous across directories.
   *
   * This is an ASSERTION by the attester, not proof the operator authorised anything. A relying
   * AS should treat it as it treats the rest of the attestation: trusted exactly as far as the
   * attester is.
   */
  operator(sub: string, issuer?: string | null): this {
    const operator: Record<string, unknown> = { sub: requireText(sub, "operator sub") };
    if (issuer) {
      operator.iss = issuer;
    }
    this.#operator = operator;
    return this;
  }

  async build(): Promise<string> {
    const sub = requireText(this.#clientId, "client_id");
    if (this.#cnfJwk === null) {
      throw new Error("confirmation key (cnf.jwk) is required");
    }
    const iat = this.#issuedAt !== null ? this.#issuedAt : nowSeconds();
    const exp = this.#resolveExpiry(iat);
    const claims: Record<string, unknown> = {
      iss: this.#issuer,
      sub,
      iat,
      exp,
      cnf: { jwk: this.#cnfJwk },
    };
    if (this.#authorizationDetails && this.#authorizationDetails.length > 0) {
      claims.authorization_details = this.#authorizationDetails;
    }
    if (this.#workload && Object.keys(this.#workload).length > 0) {
      claims.workload = this.#workload;
    }
    if (this.#operator) {
      claims.operator = this.#operator;
    }
    if (this.#attesterKey instanceof SigningKeyPair) {
      return signCompact(claims, this.#attesterKey, ATTESTATION_TYP, false);
    }
    return signExternal(claims, this.#attesterKey, ATTESTATION_TYP);
  }

  #resolveExpiry(iat: number): number {
    let exp: number;
    if (this.#expiresAt !== null) {
      exp = this.#expiresAt;
    } else if (this.#ttl !== null) {
      exp = iat + this.#ttl;
    } else {
      throw new Error("expiry is required: call expiresAt(...) or expiresIn(...)");
    }
    if (!(exp > iat)) {
      throw new Error(`attestation exp (${exp}) must be after iat (${iat})`);
    }
    return exp;
  }
}

/** JWK members that carry private or secret key material (RFC 7518 section 6). */
const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/** The public members a `cnf.jwk` of each key type must carry. */
const CONFIRMATION_JWK_MEMBERS: Record<string, readonly string[]> = { EC: ["crv", "x", "y"], RSA: ["n", "e"] };

/**
 * The public key to bind as `cnf.jwk`: `kty`, the key type's public members and an optional `kid`, in the
 * order the input has them. Refuses private or secret members, another `kty` or curve, or a missing member,
 * so a private key is never signed into an attestation.
 */
function confirmationJwkMembers(jwk: JWK): JWK {
  if (jwk === null || typeof jwk !== "object" || Array.isArray(jwk)) {
    throw new Error("cnf.jwk must be a JWK object");
  }
  const members = jwk as Record<string, unknown>;
  for (const member of PRIVATE_JWK_MEMBERS) {
    if (member in members) {
      throw new Error(`cnf.jwk must be a public key: it carries the private member '${member}'`);
    }
  }
  const kty = members.kty;
  const required = typeof kty === "string" && Object.hasOwn(CONFIRMATION_JWK_MEMBERS, kty)
    ? CONFIRMATION_JWK_MEMBERS[kty]
    : undefined;
  if (!required) {
    throw new Error(`cnf.jwk must be an EC or RSA public key, not kty ${JSON.stringify(kty)}`);
  }
  for (const member of required) {
    if (typeof members[member] !== "string" || members[member] === "") {
      throw new Error(`cnf.jwk (kty ${kty}) is missing '${member}'`);
    }
  }
  if (kty === "EC" && !["P-256", "P-384", "P-521"].includes(members.crv as string)) {
    throw new Error(`cnf.jwk curve must be P-256, P-384 or P-521, not ${JSON.stringify(members.crv)}`);
  }
  if ("kid" in members && (typeof members.kid !== "string" || members.kid === "")) {
    throw new Error("cnf.jwk kid must be a non-empty string");
  }
  const keep = new Set(["kty", "kid", ...required]);
  return Object.fromEntries(Object.entries(members).filter(([k]) => keep.has(k))) as JWK;
}

/**
 * Builds a Client Attestation PoP JWT proving possession of the instance key. Client side of
 * `attest_jwt_client_auth`; mint a fresh one per token request.
 */
export class PopBuilder {
  readonly #instanceKey: SigningKeyPair;
  #clientId: string | null = null;
  #audience: string | null = null;
  #challenge: string | null = null;
  #jwtId: string | null = null;
  #issuedAt: number | null = null;

  constructor(instanceKey: SigningKeyPair) {
    this.#instanceKey = instanceKey;
  }

  /** Sets the optional `iss`; when present the verifier requires it to equal the attestation `sub`. */
  clientId(clientId: string | null): this {
    this.#clientId = clientId;
    return this;
  }

  /** The AS identifier this PoP is bound to (`aud`) — required. */
  audience(audience: string): this {
    this.#audience = audience;
    return this;
  }

  challenge(challenge: string | null): this {
    this.#challenge = challenge;
    return this;
  }

  jwtId(jwtId: string): this {
    this.#jwtId = jwtId;
    return this;
  }

  issuedAt(epochSeconds: number): this {
    this.#issuedAt = epochSeconds;
    return this;
  }

  async build(): Promise<string> {
    if (!this.#audience) {
      throw new Error("audience (aud) is required");
    }
    const claims: Record<string, unknown> = {
      aud: this.#audience,
      jti: this.#jwtId ?? crypto.randomUUID(),
      iat: this.#issuedAt !== null ? this.#issuedAt : nowSeconds(),
    };
    if (this.#clientId) {
      claims.iss = this.#clientId;
    }
    if (this.#challenge) {
      claims.challenge = this.#challenge;
    }
    return signCompact(claims, this.#instanceKey, POP_TYP, false);
  }
}

/**
 * Builds a DPoP proof JWT (RFC 9449) for attestation combined mode
 * (PoP method `dpop_combined`): the embedded `jwk` header MUST be the attestation's `cnf` key.
 */
export class DpopProofBuilder {
  readonly #instanceKey: SigningKeyPair;
  #htm = "POST";
  #htu: string | null = null;
  #nonce: string | null = null;
  #accessToken: string | null = null;
  #jwtId: string | null = null;
  #issuedAt: number | null = null;

  constructor(instanceKey: SigningKeyPair) {
    this.#instanceKey = instanceKey;
  }

  /** The request's HTTP method (`htm`, upper-cased when built); defaults to `POST`. */
  method(htm: string | null | undefined): this {
    if (htm) {
      this.#htm = htm;
    }
    return this;
  }

  /**
   * The target URL (`htu`) — required. Normalised when built (RFC 9449 section 4.2) by the rule in
   * vectors/README.md: userinfo, query, fragment and a default port are dropped, and scheme and host
   * lower-cased. `build` refuses a URL that is not an absolute http(s) URL with a valid ASCII host, port
   * and path, or that has a backslash, ASCII whitespace or a control character before its query or
   * fragment.
   */
  uri(htu: string): this {
    this.#htu = htu;
    return this;
  }

  /** The server challenge, carried in DPoP `nonce`. */
  nonce(nonce: string | null): this {
    this.#nonce = nonce;
    return this;
  }

  /**
   * The access token this proof accompanies at a resource: sets `ath` = base64url(SHA-256(token)).
   * Leave unset for a proof sent to the token endpoint.
   */
  accessToken(accessToken: string | null): this {
    this.#accessToken = accessToken || null;
    return this;
  }

  jwtId(jwtId: string): this {
    this.#jwtId = jwtId;
    return this;
  }

  issuedAt(epochSeconds: number): this {
    this.#issuedAt = epochSeconds;
    return this;
  }

  async build(): Promise<string> {
    if (!this.#htu) {
      throw new Error("uri (htu) is required");
    }
    const claims: Record<string, unknown> = {
      htm: this.#htm.toUpperCase(),
      htu: normalizeHtu(this.#htu),
      jti: this.#jwtId ?? crypto.randomUUID(),
      iat: this.#issuedAt !== null ? this.#issuedAt : nowSeconds(),
    };
    if (this.#nonce) {
      claims.nonce = this.#nonce;
    }
    if (this.#accessToken) {
      claims.ath = await accessTokenHash(this.#accessToken);
    }
    return signCompact(claims, this.#instanceKey, DPOP_TYP, true);
  }
}

/**
 * RFC 9449 `ath`: base64url(SHA-256(ASCII access token)).
 *
 * @internal
 */
export async function accessTokenHash(accessToken: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", utf8Encode(accessToken));
  return base64url.encode(new Uint8Array(digest));
}

/**
 * Throws unless `url` is free of backslashes, ASCII whitespace and control characters before its query or
 * fragment (the part that becomes `htu`). URL parsers disagree on where such a URL goes - WHATWG reads
 * `https://evil.example\@as.example/t` as a request to evil.example, `urllib.parse` as one to
 * as.example - so a proof's `htu` could name a different server from the one the request reaches.
 *
 * @internal
 */
export function checkHtu(url: string): void {
  const head = url.split(/[?#]/, 1)[0];
  if (/[\x00-\x20\x7f\\]/.test(head)) {
    throw new Error("uri (htu) must not contain a backslash, whitespace or control character");
  }
}

/** The schemes an `htu` may have, with their default ports. */
const HTU_DEFAULT_PORTS: Record<string, string> = { http: "80", https: "443" };
const HTU_NOT_ABSOLUTE = "uri (htu) must be an absolute http or https URL with a host";
const HTU_HOST = "uri (htu) has an invalid host";
const HTU_PORT = "uri (htu) has an invalid port";
const HTU_PATH = "uri (htu) has an invalid path";

/**
 * `[origin, path]` of a request URL's `htu`, by the rule in vectors/README.md that every port applies
 * alike: an absolute http(s) URL with a host; scheme and host lower-cased (ASCII only, an IPv6 literal as
 * written); no userinfo; the port as a plain number and dropped when it is the scheme's default; the path
 * as written with non-ASCII characters percent-encoded (UTF-8); no query or fragment. It
 * is read from the string itself, not through WHATWG `URL`, which would also resolve dot-segments,
 * compress IPv6 and convert IDN hosts. Anything else throws.
 *
 * @internal
 */
export function htuParts(url: string): [origin: string, path: string] {
  checkHtu(url);
  const bare = url.split(/[?#]/, 1)[0];
  const sep = bare.indexOf("://");
  const scheme = sep < 0 ? "" : bare.slice(0, sep).toLowerCase();
  if (!Object.hasOwn(HTU_DEFAULT_PORTS, scheme)) {
    throw new Error(HTU_NOT_ABSOLUTE);
  }
  const rest = bare.slice(sep + 3);
  const slash = rest.indexOf("/");
  const authority = slash < 0 ? rest : rest.slice(0, slash);
  const path = slash < 0 ? "" : rest.slice(slash);
  const hostport = authority.slice(authority.lastIndexOf("@") + 1);
  let host: string;
  let port = "";
  if (hostport.startsWith("[")) {
    const close = hostport.indexOf("]");
    const literal = close < 0 ? "" : hostport.slice(1, close);
    const after = close < 0 ? "" : hostport.slice(close + 1);
    if (!literal.includes(":") || !/^[0-9A-Fa-f:.]*$/.test(literal) || (after !== "" && after[0] !== ":")) {
      throw new Error(HTU_HOST);
    }
    host = `[${literal.toLowerCase()}]`;
    port = after.slice(1);
  } else {
    const colon = hostport.indexOf(":");
    host = colon < 0 ? hostport : hostport.slice(0, colon);
    port = colon < 0 ? "" : hostport.slice(colon + 1);
    if (host === "") {
      throw new Error(HTU_NOT_ABSOLUTE);
    }
    if (!/^[A-Za-z0-9\-._~]+$/.test(host)) {
      throw new Error(HTU_HOST);
    }
    host = host.toLowerCase();
  }
  if (port !== "") {
    const digits = port.replace(/^0+/, "");
    if (!/^[0-9]+$/.test(port) || digits.length > 5 || Number(digits) > 65535) {
      throw new Error(HTU_PORT);
    }
    const n = String(Number(digits));
    if (n !== HTU_DEFAULT_PORTS[scheme]) {
      host += `:${n}`;
    }
  }
  return [`${scheme}://${host}`, encodeHtuPath(path)];
}

/**
 * `path` with every non-ASCII character percent-encoded as UTF-8 (upper-case hex) and every ASCII
 * character kept as written, `%XX` escapes, a lone `%` and characters outside RFC 3986 `pchar` included:
 * those are what the HTTP client sends, and a server compares `htu` after RFC 3986 section 6.2.2
 * normalisation, which decodes only unreserved characters. (`checkHtu` has already refused controls,
 * whitespace and backslash.) A lone surrogate is refused.
 */
function encodeHtuPath(path: string): string {
  try {
    return path.replace(/[^\x00-\x7f]+/g, (run) => encodeURIComponent(run)); // throws on a lone surrogate
  } catch {
    throw new Error(HTU_PATH);
  }
}

/**
 * The DPoP `htu` for a URL (RFC 9449 section 4.2): the origin and path {@link htuParts} gives. A URL
 * with no path keeps none (no slash is invented).
 *
 * @internal
 */
export function normalizeHtu(url: string): string {
  const [origin, path] = htuParts(url);
  return origin + path;
}
