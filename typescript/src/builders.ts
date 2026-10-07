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

  /** Binds the client instance key as `cnf.jwk`. Must be a public JWK. */
  confirmationJwk(publicInstanceJwk: JWK): this {
    this.#cnfJwk = publicInstanceJwk;
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
    if (this.#expiresAt !== null) {
      return this.#expiresAt;
    }
    if (this.#ttl !== null) {
      return iat + this.#ttl;
    }
    throw new Error("expiry is required: call expiresAt(...) or expiresIn(...)");
  }
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
   * The target URL (`htu`) — required. Normalised when built: query and fragment are dropped, and
   * scheme and host lower-cased (RFC 9449 section 4.2).
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

/** RFC 9449 `ath`: base64url(SHA-256(ASCII access token)). */
export async function accessTokenHash(accessToken: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", utf8Encode(accessToken));
  return base64url.encode(new Uint8Array(digest));
}

/**
 * The DPoP `htu` for a URL: scheme, host, port and path, with no query and no fragment. Scheme and host
 * are lower-cased and a default port dropped; a URL with no path keeps none (no slash is invented).
 */
export function normalizeHtu(url: string): string {
  const bare = url.split(/[?#]/, 1)[0];
  let parsed: URL;
  try {
    parsed = new URL(bare);
  } catch {
    return bare;
  }
  const hasPath = /^[a-z][a-z0-9+.-]*:\/\/[^/]*\//i.test(bare);
  return `${parsed.protocol}//${parsed.host}${hasPath ? parsed.pathname : ""}`;
}
