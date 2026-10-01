/**
 * Client for the Client Attestation **issuance** endpoint (`POST /federation/attestation`).
 *
 * The inverse of {@link ClientAttestationBuilder}: instead of building an attestation locally with an
 * attester key, a workload proves its SPIFFE identity (a JWT-SVID) and the Authorization Server
 * (PingFederate) validates it and **mints** a Client Attestation bound to the workload's own instance
 * key — bootstrapping a client credential from infra identity, no pre-shared secret.
 */
import { randomUUID } from "node:crypto";

import { DpopProofBuilder, PopBuilder } from "./builders.js";
import { jsonOk, request } from "./http.js";
import { SigningKeyPair, signCompact } from "./signing-key-pair.js";
import type { SvidSource } from "./svid-source.js";

/** The instance-key proof typ presented at the issuance endpoint (server InstanceKeyProofValidator.TYP). */
export const INSTANCE_PROOF_TYP = "oauth-attestation-instance-proof+jwt";

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

/** Bootstraps a Client Attestation for a workload from its SPIFFE JWT-SVID. */
export class AttestationIssuanceClient {
  private constructor(
    readonly endpoint: string,
    readonly clientId: string,
    readonly attesterIssuer: string,
    private readonly source: SvidSource,
    readonly instanceKey: SigningKeyPair,
  ) {}

  /** Generate a fresh ES256 instance key and return a ready client. */
  static async create(
    endpoint: string,
    clientId: string,
    attesterIssuer: string,
    source: SvidSource,
    opts?: { instanceKey?: SigningKeyPair },
  ): Promise<AttestationIssuanceClient> {
    const key = opts?.instanceKey ?? (await SigningKeyPair.generate("ES256"));
    return new AttestationIssuanceClient(endpoint.replace(/\/$/, ""), clientId, attesterIssuer, source, key);
  }

  /** Fetch the SVID, prove possession of the instance key, and exchange them for a minted attestation. */
  async bootstrap(
    authorizationDetails?: Array<Record<string, unknown>>,
    challenge?: string,
  ): Promise<IssuedAttestation> {
    const svid = await this.source.fetch(this.attesterIssuer);

    const proofClaims: Record<string, unknown> = {
      aud: this.attesterIssuer,
      jti: randomUUID(),
      iat: Math.floor(Date.now() / 1000),
    };
    if (challenge) proofClaims.challenge = challenge;
    const proof = await signCompact(proofClaims, this.instanceKey, INSTANCE_PROOF_TYP, false);

    const body: Record<string, unknown> = {
      client_id: this.clientId,
      instance_key: this.instanceKey.publicJwk(),
      svid,
      proof,
    };
    if (authorizationDetails) body.authorization_details = authorizationDetails;

    const res = await request(this.endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
      timeoutMs: ISSUANCE_TIMEOUT_MS,
    });
    if (!res.ok) throw new IssuanceError(res.status, res.body);
    const json = jsonOk<{ attestation: string; expires_in?: number }>(res);
    return new IssuedAttestation(json.attestation, json.expires_in, this.instanceKey);
  }
}
