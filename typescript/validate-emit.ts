/**
 * Validate every shared vector (tokens.json, introspection.json) and emit this port's verdicts, for the
 * cross-language agreement check.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { JSONWebKeySet } from "jose";

import { TransportError } from "./src/errors.js";
import { AccessTokenValidator, type ValidatorConfig } from "./src/validator/index.js";

interface Overrides {
  accepted_algorithms?: string[];
  accepted_token_types?: string[] | null;
  leeway_seconds?: number;
}

interface Vectors {
  issuer: string;
  audience: string;
  required_scopes: string[];
  accepted_algorithms: string[];
  jwks: JSONWebKeySet;
  cases: { name: string; token: string; expect: string; config?: Overrides; now?: number }[];
}

interface IntrospectionCase {
  name: string;
  response?: Record<string, unknown>;
  transport_error?: boolean;
  no_endpoint?: boolean;
}

type Row = { name: string; valid: boolean; error: string | null };

const HERE = dirname(fileURLToPath(import.meta.url));
const VALIDATION = resolve(HERE, "..", "validation");
const load = <T>(name: string): T => JSON.parse(readFileSync(join(VALIDATION, name), "utf8")) as T;

const vectors = load<Vectors>("tokens.json");

/** The shared config, with a case's overrides; an override key that is present wins even when empty. */
function configFor(overrides: Overrides = {}): ValidatorConfig {
  const config: ValidatorConfig = {
    issuer: vectors.issuer,
    audiences: [vectors.audience],
    jwks: vectors.jwks,
    requiredScopes: vectors.required_scopes,
    acceptedAlgorithms: vectors.accepted_algorithms,
  };
  if ("accepted_algorithms" in overrides) config.acceptedAlgorithms = overrides.accepted_algorithms;
  if ("accepted_token_types" in overrides) config.acceptedTokenTypes = overrides.accepted_token_types;
  if ("leeway_seconds" in overrides) config.leewaySeconds = overrides.leeway_seconds;
  return config;
}

const results: Row[] = [];
for (const c of vectors.cases) {
  const now = c.now;
  const validator = new AccessTokenValidator(configFor(c.config), {
    clock: now === undefined ? undefined : () => now * 1000,
  });
  const result = await validator.validate(c.token);
  results.push({ name: c.name, valid: result.valid, error: result.error });
}

const introspectionResults: Row[] = [];
for (const c of load<{ cases: IntrospectionCase[] }>("introspection.json").cases) {
  const config = configFor();
  if (!c.no_endpoint) {
    config.introspection = { endpoint: "https://issuer.example.com/introspect", clientId: "rs", clientSecret: "secret" };
  }
  const validator = new AccessTokenValidator(config, {
    httpPost: async () => {
      if (c.transport_error) {
        throw new TransportError("introspection failed: 503", "status", { status: 503 });
      }
      return c.response ?? {};
    },
  });
  try {
    const result = await validator.validateActive("opaque-token");
    introspectionResults.push({ name: c.name, valid: result.valid, error: result.error });
  } catch {
    introspectionResults.push({ name: c.name, valid: false, error: "raises" });
  }
}

mkdirSync(join(VALIDATION, "out"), { recursive: true });
writeFileSync(
  join(VALIDATION, "out", "typescript.json"),
  JSON.stringify({ language: "typescript", results, introspection_results: introspectionResults }, null, 2),
);
console.log("wrote validation/out/typescript.json");
