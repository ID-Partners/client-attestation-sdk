/**
 * Validate every shared token vector and emit this port's verdicts, for the cross-language agreement check.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { JSONWebKeySet } from "jose";

import { AccessTokenValidator } from "./src/validator/index.js";

interface Vectors {
  issuer: string;
  audience: string;
  required_scopes: string[];
  accepted_algorithms: string[];
  jwks: JSONWebKeySet;
  cases: { name: string; token: string; expect: string }[];
}

const HERE = dirname(fileURLToPath(import.meta.url));
const VALIDATION = resolve(HERE, "..", "validation");

const vectors: Vectors = JSON.parse(readFileSync(join(VALIDATION, "tokens.json"), "utf8"));

const validator = new AccessTokenValidator({
  issuer: vectors.issuer,
  audiences: [vectors.audience],
  jwks: vectors.jwks,
  requiredScopes: vectors.required_scopes,
  acceptedAlgorithms: vectors.accepted_algorithms,
});

const results: { name: string; valid: boolean; error: string | null }[] = [];
for (const c of vectors.cases) {
  const result = await validator.validate(c.token);
  results.push({ name: c.name, valid: result.valid, error: result.error });
}

mkdirSync(join(VALIDATION, "out"), { recursive: true });
writeFileSync(
  join(VALIDATION, "out", "typescript.json"),
  JSON.stringify({ language: "typescript", results }, null, 2),
);
console.log("wrote validation/out/typescript.json");
