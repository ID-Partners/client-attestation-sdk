/**
 * Client for the Client Attestation **issuance** endpoint (`POST /federation/attestation`).
 *
 * The inverse of {@link ClientAttestationBuilder}: instead of building an attestation locally with an
 * attester key, a workload proves its SPIFFE identity (a JWT-SVID) and the Authorization Server
 * (PingFederate) validates it and **mints** a Client Attestation bound to the workload's own instance
 * key — bootstrapping a client credential from infra identity, no pre-shared secret.
 */
import { type AttesterProfile, type AttesterTransport, MintRequest, PingFederateProfile } from "./attester.js";
import { DpopProofBuilder, PopBuilder } from "./builders.js";
import { jsonOk, request } from "./http.js";
import { SigningKeyPair } from "./signing-key-pair.js";
import type { SvidSource } from "./svid-source.js";

/** The instance-key proof typ the PingFederate profile presents (server InstanceKeyProofValidator.TYP). */
export { INSTANCE_PROOF_TYP } from "./attester.js";

/** Per-call timeout for the issuance endpoint. */
const ISSUANCE_TIMEOUT_MS = 20_000;

/**
 * Thrown when the issuance endpoint rejects the request (non-2xx). Transport failures — unreachable,
 * timeout, redirect, oversized or malformed response — are a {@link TransportError} instead.
 */
export class IssuanceError extends Error {
  constructor(readonly status: number, readonly body: string) {
    super(`attestation issuance failed: HTTP ${status}: ${body}`);
    this.name = "IssuanceError";
  }
}

/** A minted Client Attestation plus the instance key it is bound to. */
export class IssuedAttestation {
  constructor(
    readonly attestation: string,
    readonly expiresIn: number | undefined,
    readonly instanceKey: SigningKeyPair,
  ) {}

  /** A fresh Client Attestation PoP for the token endpoint, signed by the bound instance key. */
  async pop(audience: string, clientId?: string, challenge?: string): Promise<string> {
    const builder = new PopBuilder(this.instanceKey).audience(audience);
    if (clientId) builder.clientId(clientId);
    if (challenge) builder.challenge(challenge);
    return builder.build();
  }

  /**
   * A fresh DPoP proof (RFC 9449) for the token endpoint (attestation combined mode, PoP method
   * `dpop_combined`), signed by the same bound instance key.
   */
  async dpop(method: string, uri: string, challenge?: string): Promise<string> {
    const builder = new DpopProofBuilder(this.instanceKey).method(method).uri(uri);
    if (challenge) builder.nonce(challenge);
    return builder.build();
  }
}

/**
 * Bootstraps a Client Attestation for a workload from its SPIFFE JWT-SVID.
 *
 * `opts.profile` sets the mint protocol (default {@link PingFederateProfile}; see
 * docs/attester-profiles.md). The endpoint is given directly, so the profile's discovery is not used.
  *
  * @experimental See docs/api.md: it calls a PingFederate demo issuance servlet (/federation/attestation)
  * whose protocol is not standardised.
 */
export class AttestationIssuanceClient {
  private constructor(
    readonly endpoint: string,
    readonly clientId: string,
    readonly attesterIssuer: string,
    private readonly source: SvidSource,
    readonly instanceKey: SigningKeyPair,
    readonly profile: AttesterProfile,
  ) {}

  /** Generate a fresh ES256 instance key and return a ready client. */
  static async create(
    endpoint: string,
    clientId: string,
    attesterIssuer: string,
    source: SvidSource,
    opts?: { instanceKey?: SigningKeyPair; profile?: AttesterProfile },
  ): Promise<AttestationIssuanceClient> {
    const key = opts?.instanceKey ?? (await SigningKeyPair.generate("ES256"));
    const profile = opts?.profile ?? new PingFederateProfile();
    return new AttestationIssuanceClient(endpoint.replace(/\/$/, ""), clientId, attesterIssuer, source, key, profile);
  }

  /** Fetch the SVID, prove possession of the instance key, and exchange them for a minted attestation. */
  async bootstrap(
    authorizationDetails?: Array<Record<string, unknown>>,
    challenge?: string,
  ): Promise<IssuedAttestation> {
    const svid = await this.source.fetch(this.attesterIssuer);
    const minted = await this.profile.mint(
      issuanceTransport,
      { evidenceAudience: this.attesterIssuer, attestationEndpoint: this.endpoint },
      new MintRequest({
        instanceKey: this.instanceKey,
        evidence: svid,
        challenge: challenge || undefined,
        clientId: this.clientId,
        authorizationDetails,
      }),
    );
    return new IssuedAttestation(minted.attestation, minted.expiresIn, this.instanceKey);
  }
}

/** The issuance endpoint's transport: a non-2xx answer is an {@link IssuanceError}. */
const issuanceTransport: AttesterTransport = {
  async requestJson(_step, method, url, body) {
    const res = await request(url, {
      method,
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      timeoutMs: ISSUANCE_TIMEOUT_MS,
    });
    if (!res.ok) throw new IssuanceError(res.status, res.body);
    return jsonOk<Record<string, unknown>>(res);
  },
};
