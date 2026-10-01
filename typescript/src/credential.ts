/**
 * Assembles the request headers a client sends at the token endpoint.
 */
import { DpopProofBuilder, PopBuilder } from "./builders.js";
import { SigningKeyPair, requireText } from "./signing-key-pair.js";

export const ATTESTATION_HEADER = "OAuth-Client-Attestation";
export const POP_HEADER = "OAuth-Client-Attestation-PoP";
export const DPOP_HEADER = "DPoP";

/**
 * The Attester-issued attestation JWT plus the instance key it is bound to. Produces the
 * token-request headers — PoP-JWT mode or DPoP combined mode — minting a fresh proof each call.
 */
export class ClientAttestationCredential {
  readonly #attestationJwt: string;
  readonly #instanceKey: SigningKeyPair;

  constructor(attestationJwt: string, instanceKey: SigningKeyPair) {
    this.#attestationJwt = requireText(attestationJwt, "attestation_jwt");
    this.#instanceKey = instanceKey;
  }

  /**
   * Headers for dedicated PoP-JWT mode (PoP method `attestation_pop_jwt`):
   * `OAuth-Client-Attestation` + `OAuth-Client-Attestation-PoP`.
   */
  async popHeaders(
    clientId: string | null,
    audience: string,
    challenge?: string | null,
  ): Promise<Record<string, string>> {
    const pop = await new PopBuilder(this.#instanceKey)
      .clientId(clientId)
      .audience(audience)
      .challenge(challenge ?? null)
      .build();
    return { [ATTESTATION_HEADER]: this.#attestationJwt, [POP_HEADER]: pop };
  }

  /**
   * Headers for DPoP combined mode (PoP method `dpop_combined`):
   * `OAuth-Client-Attestation` + `DPoP` (and no PoP header).
   */
  async dpopHeaders(
    method: string,
    uri: string,
    challenge?: string | null,
  ): Promise<Record<string, string>> {
    const dpop = await new DpopProofBuilder(this.#instanceKey)
      .method(method)
      .uri(uri)
      .nonce(challenge ?? null)
      .build();
    return { [ATTESTATION_HEADER]: this.#attestationJwt, [DPOP_HEADER]: dpop };
  }
}
