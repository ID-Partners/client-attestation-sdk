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
import { ClientAttestationError } from "./errors.js";
import { checkSecure, jsonOk, request, snippet } from "./http.js";
import { SigningKeyPair } from "./signing-key-pair.js";
import type { SvidSource } from "./svid-source.js";

/** The instance-key proof typ the PingFederate profile presents (server InstanceKeyProofValidator.TYP). */
export { INSTANCE_PROOF_TYP } from "./attester.js";

/** Per-call timeout for the issuance endpoint. */
const ISSUANCE_TIMEOUT_MS = 20_000;

/**
 * Thrown when the issuance endpoint rejects the request (non-2xx); `body` is at most the first 512
 * characters of the response. Transport failures — unreachable, timeout, redirect, oversized or malformed
 * response — are a {@link TransportError} instead.
 */
export class IssuanceError extends Error {
  constructor(readonly status: number, readonly body: string) {
    super(`attestation issuance failed: HTTP ${status}: ${body}`);
    this.name = "IssuanceError";
  }
}

/**
 * A minted Client Attestation plus the instance key it is bound to. The attestation is a getter over a
 * private field, so `JSON.stringify` and `console.log` of this object don't show it.
 */
export class IssuedAttestation {
  readonly #attestation: string;

  constructor(
    attestation: string,
    readonly expiresIn: number | undefined,
    readonly instanceKey: SigningKeyPair,
  ) {
    this.#attestation = attestation;
  }

  /** The Client Attestation (a compact JWT). */
  get attestation(): string {
    return this.#attestation;
  }

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
 * The SVID is a bearer credential to the attester, so the endpoint, and every URL the profile calls, must be
 * https unless its host is loopback (`localhost`, `127.0.0.1`, `::1`) or `opts.allowInsecure` is set.
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
    private readonly transport: AttesterTransport,
  ) {}

  /**
   * Generate a fresh ES256 instance key and return a ready client. `opts.allowInsecure` permits plain-http
   * URLs on hosts that are not loopback (default `false`).
   */
  static async create(
    endpoint: string,
    clientId: string,
    attesterIssuer: string,
    source: SvidSource,
    opts?: { instanceKey?: SigningKeyPair; profile?: AttesterProfile; allowInsecure?: boolean },
  ): Promise<AttestationIssuanceClient> {
    const allowInsecure = opts?.allowInsecure ?? false;
    const trimmed = endpoint.replace(/\/$/, "");
    checkSecure(trimmed, "endpoint", allowInsecure);
    const key = opts?.instanceKey ?? (await SigningKeyPair.generate("ES256"));
    const profile = opts?.profile ?? new PingFederateProfile();
    return new AttestationIssuanceClient(
      trimmed, clientId, attesterIssuer, source, key, profile, issuanceTransport(allowInsecure),
    );
  }

  /** Fetch the SVID, prove possession of the instance key, and exchange them for a minted attestation. */
  async bootstrap(
    authorizationDetails?: Array<Record<string, unknown>>,
    challenge?: string,
  ): Promise<IssuedAttestation> {
    const svid = await this.source.fetch(this.attesterIssuer);
    const minted = await this.profile.mint(
      this.transport,
      { evidenceAudience: this.attesterIssuer, attestationEndpoint: this.endpoint },
      new MintRequest({
        instanceKey: this.instanceKey,
        evidence: svid,
        challenge: challenge || undefined,
        clientId: this.clientId,
        authorizationDetails,
      }),
    );
    if (!minted?.attestation) throw new ClientAttestationError("attester response contained no attestation");
    return new IssuedAttestation(minted.attestation, minted.expiresIn, this.instanceKey);
  }
}

/** The issuance endpoint's transport: the https rule, and a non-2xx answer is an {@link IssuanceError}. */
const issuanceTransport = (allowInsecure: boolean): AttesterTransport => ({
  async requestJson(step, method, url, body) {
    checkSecure(url, `${step} URL`, allowInsecure);
    const res = await request(url, {
      method,
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      timeoutMs: ISSUANCE_TIMEOUT_MS,
    });
    if (!res.ok) throw new IssuanceError(res.status, snippet(res.body));
    return jsonOk<Record<string, unknown>>(res);
  },
});
