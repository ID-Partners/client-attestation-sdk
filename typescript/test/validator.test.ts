import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { TransportError } from "../src/errors.js";
import { AccessTokenValidator, errors } from "../src/validator/index.js";

const VALIDATION = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "validation");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const vectors: any = JSON.parse(readFileSync(join(VALIDATION, "tokens.json"), "utf8"));

function baseConfig() {
  return {
    issuer: vectors.issuer,
    audiences: [vectors.audience],
    jwks: vectors.jwks,
    requiredScopes: vectors.required_scopes,
    acceptedAlgorithms: vectors.accepted_algorithms,
  };
}

function newValidator(overrides: Record<string, unknown> = {}) {
  return new AccessTokenValidator({ ...baseConfig(), ...overrides });
}

function tokenNamed(name: string): string {
  return vectors.cases.find((c: { name: string }) => c.name === name).token;
}

describe("token validator", () => {
  it("validates every shared vector to its expected verdict", async () => {
    for (const c of vectors.cases) {
      const o = c.config ?? {};
      const overrides: Record<string, unknown> = {};
      if ("accepted_algorithms" in o) overrides.acceptedAlgorithms = o.accepted_algorithms;
      if ("accepted_token_types" in o) overrides.acceptedTokenTypes = o.accepted_token_types;
      if ("leeway_seconds" in o) overrides.leewaySeconds = o.leeway_seconds;
      // a case's own key set replaces the shared one; a case with a fetch error gets a jwksUri instead
      if (c.jwks !== undefined) overrides.jwks = c.jwks;
      if (c.jwks_fetch_error !== undefined) {
        overrides.jwks = undefined;
        overrides.jwksUri = "https://keys.internal.example:8443/jwks";
      }
      const validator = new AccessTokenValidator(
        { ...baseConfig(), ...overrides },
        {
          clock: c.now === undefined ? undefined : () => c.now * 1000,
          httpGet: async () => {
            throw new Error(c.jwks_fetch_error);
          },
        },
      );
      const result = await validator.validate(c.token);
      const got = result.valid ? "valid" : result.error;
      expect(got, c.name).toBe(c.expect);
      if (c.expect_description !== undefined) expect(result.errorDescription, c.name).toBe(c.expect_description);
    }
  });

  it("validates every shared introspection vector to its expected verdict", async () => {
    const cases = JSON.parse(readFileSync(join(VALIDATION, "introspection.json"), "utf8")).cases;
    for (const c of cases) {
      const validator = new AccessTokenValidator(
        {
          ...baseConfig(),
          introspection: c.no_endpoint
            ? undefined
            : { endpoint: "https://as.example.com/introspect", clientId: "rs", clientSecret: "s" },
        },
        {
          httpPost: async () => {
            if (c.transport_error) throw new TransportError("introspection failed: 503", "status", { status: 503 });
            return c.response;
          },
        },
      );
      let got: string | null;
      try {
        const result = await validator.validateActive("opaque");
        got = result.valid ? "valid" : result.error;
      } catch {
        got = "raises";
      }
      expect(got, c.name).toBe(c.expect);
    }
  });

  it("exposes subject, scopes and audience for a valid token", async () => {
    const result = await newValidator().validate(tokenNamed("valid"));
    expect(result.valid).toBe(true);
    expect(result.subject).toBe("agent-1");
    expect(result.scopes).toContain("read");
    expect(result.scopes).toContain("write");
    expect(result.audience).toContain(vectors.audience);
  });

  it("enforces a required-scope override", async () => {
    const result = await newValidator().validate(tokenNamed("valid"), ["read", "admin"]);
    expect(result.valid).toBe(false);
    expect(result.error).toBe(errors.INSUFFICIENT_SCOPE);
  });

  it("introspection sends basic auth and honours active", async () => {
    let captured: { url: string; body: string; headers: Record<string, string> } | null = null;
    const httpPost = async (url: string, body: string, headers: Record<string, string>) => {
      captured = { url, body, headers };
      return { active: true, scope: "read write", sub: "agent-1", aud: vectors.audience };
    };
    const validator = new AccessTokenValidator(
      {
        issuer: vectors.issuer,
        audiences: [vectors.audience],
        jwks: vectors.jwks,
        requiredScopes: ["read"],
        introspection: { endpoint: "https://issuer.example.com/introspect", clientId: "rs-1", clientSecret: "s3cret" },
      },
      { httpPost },
    );
    const result = await validator.validateActive("opaque-token");
    expect(result.valid).toBe(true);
    expect(result.subject).toBe("agent-1");
    expect(captured!.headers.Authorization).toMatch(/^Basic /);
    expect(captured!.body).toContain("token=opaque-token");
  });

  it("reports inactive tokens from introspection", async () => {
    const validator = new AccessTokenValidator(
      {
        issuer: vectors.issuer,
        audiences: [vectors.audience],
        jwks: vectors.jwks,
        introspection: { endpoint: "https://issuer.example.com/introspect", clientId: "rs-1", clientSecret: "s3cret" },
      },
      { httpPost: async () => ({ active: false }) },
    );
    const result = await validator.validateActive("revoked");
    expect(result.valid).toBe(false);
    expect(result.error).toBe(errors.INACTIVE);
  });
});
