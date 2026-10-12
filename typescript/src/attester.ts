/**
 * Attester profiles: the part of the flow that differs from one attester to the next.
 *
 * The draft says what a Client Attestation, its PoP and the challenge endpoint look like, and how they
 * are presented at the token endpoint. It does not say how a workload gets an attestation from its
 * attester. That part - where the attester's endpoints are listed, what the mint request looks like, how
 * the instance key is proven, and what comes back - is an {@link AttesterProfile}.
 *
 * {@link ClientAttestation} and {@link AttestationIssuanceClient} use {@link PingFederateProfile} unless
 * told otherwise, which is exactly the behaviour of earlier releases. See docs/attester-profiles.md.
 */
import { ATTESTATION_TYP, DPOP_TYP, POP_TYP } from "./builders.js";
import { ClientAttestationError } from "./errors.js";
import { type SigningKeyPair, signCompact } from "./signing-key-pair.js";

/** Where the attester lives and what it expects. */
export interface AttesterMetadata {
  /** The audience the workload's platform identity is requested for, and the instance proof's `aud`. */
  evidenceAudience?: string;
  /** Where the mint request goes. */
  attestationEndpoint?: string;
  /** The authorization server's token endpoint. A profile fills in its own fallback. */
  tokenEndpoint?: string;
  /** The draft's challenge endpoint, if the attester issues challenges. */
  challengeEndpoint?: string;
  /** The Client Attestation PoP `aud` (the AS issuer); falls back to the token endpoint URL. */
  popAudience?: string;
  /** The raw discovery document, when there was one; returned by `ClientAttestation.discovery()`. */
  document?: Record<string, unknown>;
}

/** What the attester returned: the attestation, and its lifetime in seconds if it said. */
export interface MintResult {
  attestation: string;
  expiresIn?: number;
}

/**
 * How a profile talks to the attester. The client supplies it, so every call shares the client's timeout,
 * redirect and size limits, https rule and logging (`http.failed`).
 */
export interface AttesterTransport {
  /**
   * Send `body` (as JSON, if given) and resolve to the JSON object response. `step` names the call in
   * logs (`discover`, `mint`). Rejects on a non-2xx status or a body that is not a JSON object.
   */
  requestJson(
    step: string,
    method: string,
    url: string,
    body?: Record<string, unknown>,
  ): Promise<Record<string, unknown>>;
}

/**
 * The attester-specific part of the flow. Implement it and pass it as the `profile` option.
 *
 * @experimental See docs/api.md: new in 0.4.0 and fitted to one real attester so far; a method added to it would break custom profiles.
 */
export interface AttesterProfile {
  /**
   * Find the attester's endpoints. Called once per client and cached; not called when the caller passes
   * static `metadata`.
   */
  discover(transport: AttesterTransport, attesterUrl: string | undefined): Promise<AttesterMetadata>;
  /** Exchange the evidence and a proof of the instance key for an attestation. */
  mint(transport: AttesterTransport, metadata: AttesterMetadata, request: MintRequest): Promise<MintResult>;
}

/**
 * Everything a profile needs to mint one attestation. The evidence and the challenge are getters over
 * private fields, so `JSON.stringify` and `console.log` of a request show neither.
 */
export class MintRequest {
  /** The fresh key the attestation will be bound to (its `cnf`). */
  readonly instanceKey: SigningKeyPair;
  readonly #evidence: string;
  readonly #challenge?: string;
  /** Set by {@link AttestationIssuanceClient}; unset in the evidence-first one-call flow. */
  readonly clientId?: string;
  /** Optional RFC 9396 access request. */
  readonly authorizationDetails?: Array<Record<string, unknown>>;
  /** Optional operator object (who answers for this workload). */
  readonly operator?: Record<string, unknown>;

  constructor(init: {
    instanceKey: SigningKeyPair;
    evidence: string;
    challenge?: string;
    clientId?: string;
    authorizationDetails?: Array<Record<string, unknown>>;
    operator?: Record<string, unknown>;
  }) {
    this.instanceKey = init.instanceKey;
    this.#evidence = init.evidence;
    this.#challenge = init.challenge;
    this.clientId = init.clientId;
    this.authorizationDetails = init.authorizationDetails;
    this.operator = init.operator;
  }

  /** The workload's platform identity token (a JWT-SVID or equivalent). */
  get evidence(): string {
    return this.#evidence;
  }

  /** The attester-issued challenge, if any. */
  get challenge(): string | undefined {
    return this.#challenge;
  }

  /**
   * Sign `claims` as a compact JWS with the instance key, under header `typ` (no `jwk`). `typ` may not be
   * one the SDK's own credentials use (`ATTESTATION_TYP`, `POP_TYP`, `DPOP_TYP`): a profile could otherwise
   * have the instance key sign a Client Attestation PoP or DPoP proof with claims of its choosing.
   */
  async sign(claims: Record<string, unknown>, typ: string): Promise<string> {
    if (reservedTyp(typ)) {
      throw new Error(
        `typ ${JSON.stringify(typ)} is reserved for the SDK's own credentials; a profile cannot sign it with the instance key`,
      );
    }
    return signCompact(claims, this.instanceKey, typ, false);
  }

  /** A proof of possession of the instance key: `{aud, jti, iat[, challenge]}` signed with it. */
  instanceProof(typ: string, audience: string | undefined): Promise<string> {
    const claims: Record<string, unknown> = {
      aud: audience,
      jti: crypto.randomUUID(),
      iat: Math.floor(Date.now() / 1000),
    };
    if (this.challenge) claims.challenge = this.challenge;
    return this.sign(claims, typ);
  }
}

/**
 * Whether `typ` names one of the SDK's own credential types, compared as RFC 7515 section 4.1.9 says a
 * verifier may: case-insensitively, with or without the `application/` prefix.
 */
function reservedTyp(typ: string): boolean {
  const t = String(typ).trim().toLowerCase().replace(/^application\//, "");
  return t === ATTESTATION_TYP || t === POP_TYP || t === DPOP_TYP;
}

/**
 * The PingFederate profile's discovery document path.
 *
 * @internal
 */
export const WELL_KNOWN_PATH = "/.well-known/client-attester";
/** The instance-key proof typ of the PingFederate profile (server InstanceKeyProofValidator.TYP). */
export const INSTANCE_PROOF_TYP = "oauth-attestation-instance-proof+jwt";

/**
 * The attester this SDK was built against (PingFederate), and the default.
 *
 * - Discovery: `GET {attesterUrl}/.well-known/client-attester`, a JSON object with `evidence_audience`,
 *   `attestation_endpoint`, `challenge_endpoint`, `token_endpoint` and `pop_audience`. With no
 *   `token_endpoint`, `{attesterUrl}/as/token.oauth2`.
 * - Mint: `POST attestation_endpoint` with JSON `{[client_id,] instance_key, svid, proof
 *   [, authorization_details][, operator]}`, where `proof` is `{aud: evidence_audience, jti, iat
 *   [, challenge]}` signed by the instance key with `typ` `oauth-attestation-instance-proof+jwt`. The
 *   response is `{"attestation": ..., "expires_in": ...}`.
 */
export class PingFederateProfile implements AttesterProfile {
  static readonly WELL_KNOWN_PATH = WELL_KNOWN_PATH;
  static readonly INSTANCE_PROOF_TYP = INSTANCE_PROOF_TYP;
  static readonly DEFAULT_TOKEN_PATH = "/as/token.oauth2";

  async discover(transport: AttesterTransport, attesterUrl: string | undefined): Promise<AttesterMetadata> {
    if (!attesterUrl) throw new Error("attesterUrl is required for discovery");
    const doc = await transport.requestJson("discover", "GET", attesterUrl + WELL_KNOWN_PATH);
    const str = (key: string) => (typeof doc[key] === "string" && doc[key] ? (doc[key] as string) : undefined);
    return {
      evidenceAudience: str("evidence_audience"),
      attestationEndpoint: str("attestation_endpoint"),
      // token_endpoint is advertised by current attesters; fall back to the standard PF path so an older
      // discovery document still works from the host alone.
      tokenEndpoint: str("token_endpoint") ?? attesterUrl + PingFederateProfile.DEFAULT_TOKEN_PATH,
      challengeEndpoint: str("challenge_endpoint"),
      popAudience: str("pop_audience"),
      document: doc,
    };
  }

  async mint(transport: AttesterTransport, metadata: AttesterMetadata, request: MintRequest): Promise<MintResult> {
    if (!metadata.attestationEndpoint) {
      throw new ClientAttestationError("attester discovery document has no attestation_endpoint");
    }
    const proof = await request.instanceProof(INSTANCE_PROOF_TYP, metadata.evidenceAudience);
    const body: Record<string, unknown> = {};
    if (request.clientId) body.client_id = request.clientId;
    body.instance_key = request.instanceKey.publicJwk();
    body.svid = request.evidence;
    body.proof = proof;
    if (request.authorizationDetails) body.authorization_details = request.authorizationDetails;
    // Asked for at mint time so the ATTESTER is what states the operator, rather than the client
    // asserting it about itself at the token endpoint. An attester that does not know it ignores it.
    if (request.operator) body.operator = request.operator;

    const response = await transport.requestJson("mint", "POST", metadata.attestationEndpoint, body);
    const attestation = response.attestation;
    if (typeof attestation !== "string" || !attestation) {
      // No body: a 2xx mint response may hold the attestation under another name.
      throw new ClientAttestationError("attester response contained no attestation");
    }
    const expiresIn = response.expires_in;
    return { attestation, expiresIn: typeof expiresIn === "number" ? expiresIn : undefined };
  }
}

/**
 * The discovery-document view of metadata: the raw document, or the snake_case fields that are set.
 *
 * @internal
 */
export function metadataDocument(metadata: AttesterMetadata): Record<string, unknown> {
  if (metadata.document) return metadata.document;
  const doc: Record<string, unknown> = {};
  const fields: Array<[string, string | undefined]> = [
    ["evidence_audience", metadata.evidenceAudience],
    ["attestation_endpoint", metadata.attestationEndpoint],
    ["challenge_endpoint", metadata.challengeEndpoint],
    ["token_endpoint", metadata.tokenEndpoint],
    ["pop_audience", metadata.popAudience],
  ];
  for (const [key, value] of fields) if (value) doc[key] = value;
  return doc;
}
