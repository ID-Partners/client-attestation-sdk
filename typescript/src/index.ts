/**
 * Client-side builder SDK for OAuth Attestation-Based Client Authentication.
 *
 * Everything exported here is the package's API; docs/api.md says which parts are Stable and which are
 * Experimental. Nothing else under dist/ can be imported: package.json "exports" allows only this entry
 * point and "./validator".
 */
export { SigningKeyPair } from "./signing-key-pair.js";
export {
  ClientAttestationBuilder,
  DpopProofBuilder,
  PopBuilder,
  ATTESTATION_TYP,
  POP_TYP,
  DPOP_TYP,
} from "./builders.js";
export {
  ClientAttestationCredential,
  ATTESTATION_HEADER,
  POP_HEADER,
  DPOP_HEADER,
} from "./credential.js";
export { OpenBaoTransitSigner } from "./signer.js";
export type { JwsSigner } from "./signer.js";
export {
  AttestationIssuanceClient,
  IssuedAttestation,
  IssuanceError,
  INSTANCE_PROOF_TYP,
} from "./issuance.js";
export {
  StaticSvidSource,
  HttpSvidSource,
  SpireWorkloadApiSvidSource,
} from "./svid-source.js";
export type { SvidSource } from "./svid-source.js";
export {
  EvidenceNotFound,
  FileTokenSvidSource,
  GoogleMetadataSvidSource,
  autoDetectEvidence,
  ENV_SVID,
  ENV_TOKEN_FILE,
  ENV_SPIFFE_SOCKET,
  DEFAULT_TOKEN_FILE,
  DEFAULT_SPIFFE_SOCKET,
} from "./evidence.js";
export {
  ClientAttestation,
  ClientAttestationError,
  TransportError,
  DEFAULT_EXPIRY_SKEW_SECONDS,
} from "./token-source.js";
export type { AttesterDiscovery, ClientAttestationOptions } from "./token-source.js";
export { MintRequest, PingFederateProfile } from "./attester.js";
export type { AttesterMetadata, AttesterProfile, AttesterTransport, MintResult } from "./attester.js";
export type { TransportFailure } from "./errors.js";
export { NOOP_LOGGER } from "./logging.js";
export type { Logger, LogAttributes, LogLevel } from "./logging.js";

export const VERSION = "1.2.0";

/** draft-ietf-oauth-attestation-based-client-auth revision this SDK implements. */
export const DRAFT_REVISION = "10";
