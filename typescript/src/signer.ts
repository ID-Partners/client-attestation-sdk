/**
 * External JWS signing — keys that live outside the process (a vault, HSM, or KMS).
 *
 * {@link SigningKeyPair} covers the local-key case; {@link OpenBaoTransitSigner} signs inside an
 * OpenBao / HashiCorp Vault transit engine so the attester's private key never leaves it.
 */
import { base64url, calculateJwkThumbprint, exportJWK, importSPKI, type JWK } from "jose";

import { TransportError } from "./errors.js";
import { base64Encode } from "./runtime.js";
import { parseJsonObject, request as httpRequest, snippet, type HttpResponse } from "./http.js";

/** Per-call timeout for the vault. */
const OPENBAO_TIMEOUT_MS = 5_000;

const b64url = (bytes: Uint8Array): string => base64url.encode(bytes);

/** A JWS signing capability whose private key may live outside the process. `sign` returns the RAW JWS
 * signature over the signing input — for ECDSA the fixed-width `r||s`, not ASN.1/DER. */
export interface JwsSigner {
  readonly algorithm: string;
  readonly keyId: string;
  publicJwk(): JWK;
  sign(signingInput: Uint8Array): Promise<Uint8Array>;
}

/** Assemble a compact JWS whose signature is produced by an external signer (header carries `kid`; external
 * signers hold issuing keys, referenced by id, never an embedded jwk). */
export async function signExternal(
  claims: Record<string, unknown>,
  signer: JwsSigner,
  typ: string,
): Promise<string> {
  const enc = new TextEncoder();
  const header = { alg: signer.algorithm, typ, kid: signer.keyId };
  const signingInput = `${b64url(enc.encode(JSON.stringify(header)))}.${b64url(enc.encode(JSON.stringify(claims)))}`;
  const signature = await signer.sign(enc.encode(signingInput));
  return `${signingInput}.${b64url(signature)}`;
}

const KEY_TYPE_ALG: Record<string, string> = { "ecdsa-p256": "ES256", "ecdsa-p384": "ES384", "ecdsa-p521": "ES512" };
const ALG_HASH: Record<string, string> = { ES256: "sha2-256", ES384: "sha2-384", ES512: "sha2-512" };

/**
 * A {@link JwsSigner} backed by an OpenBao / HashiCorp Vault transit engine: the attestation is signed
 * inside the vault (`POST /v1/transit/sign/<key>` with `marshaling_algorithm=jws`, which returns the
 * fixed-width `r||s`) and the private key never leaves it. `create` reads the key metadata to pin the
 * latest version, derive the public JWK and compute its RFC 7638 `kid`. Fail-closed (vault errors throw).
 */
export class OpenBaoTransitSigner implements JwsSigner {
  readonly algorithm: string;
  readonly keyId: string;
  readonly #base: string;
  readonly #token: string;
  readonly #keyName: string;
  readonly #hash: string;
  readonly #keyVersion: number;
  readonly #publicJwk: JWK;

  private constructor(
    base: string, token: string, keyName: string, algorithm: string,
    hash: string, keyVersion: number, publicJwk: JWK, keyId: string,
  ) {
    this.#base = base;
    this.#token = token;
    this.#keyName = keyName;
    this.algorithm = algorithm;
    this.#hash = hash;
    this.#keyVersion = keyVersion;
    this.#publicJwk = publicJwk;
    this.keyId = keyId;
  }

  static async create(baoAddr: string, token: string, keyName: string): Promise<OpenBaoTransitSigner> {
    const base = baoAddr.replace(/\/+$/, "");
    const data = await request("GET", base, token, `/v1/transit/keys/${keyName}`);
    const keyType = String(data.type);
    const algorithm = KEY_TYPE_ALG[keyType];
    if (!algorithm) {
      throw new Error(`transit key '${keyName}' has unsupported type for JWS signing: ${keyType}`);
    }
    const keyVersion = Number(data.latest_version);
    const keys = data.keys as Record<string, { public_key: string }>;
    const pem = keys[String(keyVersion)].public_key;
    const jwk = await exportJWK(await importSPKI(pem, algorithm, { extractable: true }));
    const keyId = await calculateJwkThumbprint(jwk, "sha256");
    const publicJwk: JWK = { ...jwk, kid: keyId, alg: algorithm };
    return new OpenBaoTransitSigner(base, token, keyName, algorithm, ALG_HASH[algorithm], keyVersion, publicJwk, keyId);
  }

  publicJwk(): JWK {
    return { ...this.#publicJwk };
  }

  async sign(signingInput: Uint8Array): Promise<Uint8Array> {
    const body = JSON.stringify({
      input: base64Encode(signingInput),
      marshaling_algorithm: "jws",
      hash_algorithm: this.#hash,
      key_version: this.#keyVersion,
    });
    const data = await request("POST", this.#base, this.#token, `/v1/transit/sign/${this.#keyName}`, body);
    const signature = data.signature as string | undefined;
    if (!signature) {
      throw new Error("transit sign response carried no signature");
    }
    const raw = signature.slice(signature.lastIndexOf(":") + 1); // envelope: vault:v<n>:<base64url(r||s)>
    return base64url.decode(raw);
  }
}

async function request(
  method: string, base: string, token: string, path: string, body?: string,
): Promise<Record<string, unknown>> {
  let response: HttpResponse;
  try {
    response = await httpRequest(base + path, {
      method,
      headers: { "X-Vault-Token": token, ...(body ? { "Content-Type": "application/json" } : {}) },
      body,
      timeoutMs: OPENBAO_TIMEOUT_MS,
    });
  } catch (exc) {
    if (exc instanceof TransportError && (exc.kind === "network" || exc.kind === "timeout")) {
      const why =
        exc.kind === "timeout"
          ? `timed out after ${OPENBAO_TIMEOUT_MS} ms`
          : exc.cause instanceof Error
            ? exc.cause.message
            : String(exc.cause);
      throw new TransportError(`OpenBao unreachable at ${base}: ${why}`, exc.kind, { cause: exc });
    }
    throw exc;
  }
  if (response.status !== 200) {
    throw new TransportError(`OpenBao returned HTTP ${response.status} for ${path}`, "status", {
      status: response.status,
      body: snippet(response.body),
    });
  }
  const parsed = parseJsonObject<{ data?: Record<string, unknown> }>(response);
  if (!parsed.data || typeof parsed.data !== "object") {
    throw new Error("OpenBao response carried no data");
  }
  return parsed.data;
}
