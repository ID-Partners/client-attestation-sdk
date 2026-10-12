/**
 * Validate every shared vector (tokens.json, introspection.json, config.json) and emit this port's verdicts, for the
 * cross-language agreement check.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { JSONWebKeySet } from "jose";

import { TransportError } from "./src/errors.js";
import { AccessTokenValidator, ProtectedResource, type ValidatorConfig } from "./src/validator/index.js";

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
  cases: TokenCase[];
}

interface TokenCase {
  name: string;
  token: string;
  expect: string;
  config?: Overrides;
  now?: number;
  jwks?: JSONWebKeySet;
  jwks_fetch_error?: string;
}

interface IntrospectionCase {
  name: string;
  response?: Record<string, unknown>;
  transport_error?: boolean;
  no_endpoint?: boolean;
}

interface ConfigCase {
  name: string;
  config: { jwks_uri?: string; introspection_endpoint?: string; allow_insecure?: boolean; leeway_seconds?: number };
}

type Row = { name: string; valid: boolean; error: string | null; description?: string | null };

const HERE = dirname(fileURLToPath(import.meta.url));
const VALIDATION = resolve(HERE, "..", "validation");
const load = <T>(name: string): T => JSON.parse(readFileSync(join(VALIDATION, name), "utf8")) as T;

const vectors = load<Vectors>("tokens.json");

const JWKS_URI = "https://keys.internal.example:8443/jwks";

/**
 * The shared config, with a case's overrides; an override key that is present wins even when empty. A case's
 * own key set replaces the shared one; a case with a fetch error gets a jwksUri instead.
 */
function configFor(overrides: Overrides = {}, c?: TokenCase): ValidatorConfig {
  const fetch = c?.jwks_fetch_error !== undefined;
  const config: ValidatorConfig = {
    issuer: vectors.issuer,
    audiences: [vectors.audience],
    jwks: fetch ? undefined : (c?.jwks ?? vectors.jwks),
    jwksUri: fetch ? JWKS_URI : undefined,
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
  const validator = new AccessTokenValidator(configFor(c.config, c), {
    clock: now === undefined ? undefined : () => now * 1000,
    httpGet: async () => {
      throw new TransportError(c.jwks_fetch_error ?? "unexpected fetch", "status", { status: 503 });
    },
  });
  const result = await validator.validate(c.token);
  results.push({ name: c.name, valid: result.valid, error: result.error, description: result.errorDescription });
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

const introspection = load<{ guard: { resource: string; audiences: string[] }; cases: IntrospectionCase[] }>(
  "introspection.json",
);
const guardResults: Row[] = [];
for (const c of introspection.cases) {
  const config: ValidatorConfig = {
    issuer: vectors.issuer,
    audiences: introspection.guard.audiences,
    jwks: vectors.jwks,
    requiredScopes: vectors.required_scopes,
  };
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
  const resource = new ProtectedResource(introspection.guard.resource, [vectors.issuer], validator);
  try {
    const decision = await resource.authenticateActive("Bearer opaque-token");
    guardResults.push({ name: c.name, valid: decision.authorized, error: decision.result?.error ?? null });
  } catch {
    guardResults.push({ name: c.name, valid: false, error: "raises" });
  }
}

const configResults: Row[] = [];
for (const c of load<{ cases: ConfigCase[] }>("config.json").cases) {
  const config = configFor();
  if (c.config.jwks_uri !== undefined) {
    delete config.jwks;
    config.jwksUri = c.config.jwks_uri;
  }
  if (c.config.introspection_endpoint !== undefined) {
    config.introspection = { endpoint: c.config.introspection_endpoint, clientId: "rs", clientSecret: "secret" };
  }
  if (c.config.allow_insecure !== undefined) config.allowInsecure = c.config.allow_insecure;
  if (c.config.leeway_seconds !== undefined) config.leewaySeconds = c.config.leeway_seconds;
  try {
    new AccessTokenValidator(config);
    configResults.push({ name: c.name, valid: true, error: null });
  } catch {
    configResults.push({ name: c.name, valid: false, error: "refused" });
  }
}

mkdirSync(join(VALIDATION, "out"), { recursive: true });
writeFileSync(
  join(VALIDATION, "out", "typescript.json"),
  JSON.stringify(
    {
      language: "typescript",
      results,
      introspection_results: introspectionResults,
      guard_results: guardResults,
      config_results: configResults,
    },
    null,
    2,
  ),
);
console.log("wrote validation/out/typescript.json");
