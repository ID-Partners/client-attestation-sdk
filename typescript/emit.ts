/**
 * Emit attestation artifacts from the shared vectors, for the cross-language interop check.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { JWK } from "jose";

import {
  ClientAttestationBuilder,
  ClientAttestationCredential,
  SigningKeyPair,
} from "./src/index.js";

interface Inputs {
  attester: { iss: string; alg: string; jwk: JWK };
  instance: { alg: string; jwk: JWK };
  client_id: string;
  audience: string;
  token_endpoint: string;
  attestation_ttl_seconds: number;
}

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTORS = resolve(HERE, "..", "vectors");

const inp: Inputs = JSON.parse(readFileSync(join(VECTORS, "inputs.json"), "utf8"));

const attester = await SigningKeyPair.fromJwk(inp.attester.jwk, inp.attester.alg);
const instance = await SigningKeyPair.fromJwk(inp.instance.jwk, inp.instance.alg);

const attestation = await new ClientAttestationBuilder(attester, inp.attester.iss)
  .clientId(inp.client_id)
  .confirmationKey(instance)
  .expiresIn(inp.attestation_ttl_seconds)
  .build();

const cred = new ClientAttestationCredential(attestation, instance);
const pop = await cred.popHeaders(inp.client_id, inp.audience);
const dpop = await cred.dpopHeaders("POST", inp.token_endpoint);

const out = {
  language: "typescript",
  attestation,
  pop: pop["OAuth-Client-Attestation-PoP"],
  dpop: dpop["DPoP"],
  audience: inp.audience,
  tokenEndpoint: inp.token_endpoint,
  clientId: inp.client_id,
};

mkdirSync(join(VECTORS, "out"), { recursive: true });
writeFileSync(join(VECTORS, "out", "typescript.json"), JSON.stringify(out, null, 2));
console.log("wrote vectors/out/typescript.json");
