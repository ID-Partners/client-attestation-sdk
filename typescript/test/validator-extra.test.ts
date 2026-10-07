import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { SignJWT, type JSONWebKeySet } from "jose";

import { SigningKeyPair } from "../src/index.js";
import {
  AccessTokenValidator,
  DEFAULT_ALGORITHMS,
  errors,
  type ValidatorConfig,
} from "../src/validator/index.js";
import { failure, success } from "../src/validator/result.js";
import { resolveConfig } from "../src/validator/config.js";

const ISSUER = "https://issuer.example.com";
const AUDIENCE = "https://api.example.com";
const INTROSPECTION = {
  endpoint: "https://issuer.example.com/introspect",
  clientId: "rs-1",
  clientSecret: "s3cret",
};

let pair: SigningKeyPair;
let jwks: JSONWebKeySet;

beforeAll(async () => {
  pair = await SigningKeyPair.generate("ES256");
  jwks = { keys: [pair.publicJwk()] };
});

function newValidator(overrides: Partial<ValidatorConfig> = {}, opts = {}) {
  return new AccessTokenValidator(
    { issuer: ISSUER, audiences: [AUDIENCE], jwks, ...overrides },
    opts,
  );
}

async function sign(claims: Record<string, unknown>, kid?: string, typ?: string): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "ES256", kid: kid ?? pair.keyId, ...(typ ? { typ } : {}) })
    .sign(pair.privateKey);
}

const inFiveMinutes = () => Math.floor(Date.now() / 1000) + 300;

function b64url(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

describe("token validator edge cases", () => {
  it("reports a malformed token", async () => {
    const result = await newValidator().validate("not-a-jwt");
    expect(result.valid).toBe(false);
    expect(result.error).toBe(errors.INVALID_TOKEN);
    expect(result.errorDescription).toContain("malformed token");
  });

  it("rejects a header without an alg", async () => {
    const token = `${b64url(JSON.stringify({ typ: "JWT" }))}.${b64url("{}")}.AAAA`;
    const result = await newValidator().validate(token);
    expect(result.error).toBe(errors.UNSUPPORTED_ALGORITHM);
  });

  it("rejects an alg outside the accepted list", async () => {
    const token = await sign({ iss: ISSUER, aud: AUDIENCE });
    const result = await newValidator({ acceptedAlgorithms: ["RS256"] }).validate(token);
    expect(result.error).toBe(errors.UNSUPPORTED_ALGORITHM);
  });

  it("reports key_not_found for an unknown kid", async () => {
    const token = await sign({ iss: ISSUER, aud: AUDIENCE }, "unknown-kid");
    const result = await newValidator().validate(token);
    expect(result.error).toBe(errors.KEY_NOT_FOUND);
  });

  it("accepts an audience list and normalizes it", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await sign({ iss: ISSUER, aud: [AUDIENCE, "https://other.example.com"], exp: now + 300 });
    const result = await newValidator().validate(token);
    expect(result.valid).toBe(true);
    expect(result.audience).toEqual([AUDIENCE, "https://other.example.com"]);
  });

  it("reads scopes from an scp array", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await sign({ iss: ISSUER, aud: AUDIENCE, exp: now + 300, scp: ["read", "write"] });
    const result = await newValidator().validate(token, ["read"]);
    expect(result.valid).toBe(true);
    expect(result.scopes).toEqual(["read", "write"]);
  });

  it("treats a token without scope/scp as having none", async () => {
    const token = await sign({ iss: ISSUER, aud: AUDIENCE, exp: inFiveMinutes() });
    const result = await newValidator().validate(token);
    expect(result.valid).toBe(true);
    expect(result.scopes).toEqual([]);
  });

  it("refuses a token without exp", async () => {
    const token = await sign({ iss: ISSUER, aud: AUDIENCE });
    expect((await newValidator().validate(token)).error).toBe(errors.MISSING_EXPIRY);
  });

  it("treats a non-numeric exp as malformed", async () => {
    for (const exp of ["4102444800", true]) {
      const token = await sign({ iss: ISSUER, aud: AUDIENCE, exp });
      expect((await newValidator().validate(token)).error).toBe(errors.INVALID_TOKEN);
    }
  });

  it("accepts an iat within the leeway", async () => {
    const iat = Math.floor(Date.now() / 1000) + 30;
    const token = await sign({ iss: ISSUER, aud: AUDIENCE, exp: inFiveMinutes(), iat });
    expect((await newValidator().validate(token)).valid).toBe(true);
  });

  it("compares typ the way RFC 7515 says to", async () => {
    const claims = { iss: ISSUER, aud: AUDIENCE, exp: inFiveMinutes() };
    const v = newValidator();
    expect((await v.validate(await sign(claims, undefined, "application/at+jwt"))).valid).toBe(true);
    expect((await v.validate(await sign(claims, undefined, "AT+JWT"))).valid).toBe(true);
    expect((await v.validate(await sign(claims, undefined, "JWT"))).error).toBe(errors.INVALID_TOKEN_TYPE);
  });

  it("can turn the typ check off", async () => {
    const token = await sign({ iss: ISSUER, aud: AUDIENCE, exp: inFiveMinutes() }, undefined, "JWT");
    expect((await newValidator({ acceptedTokenTypes: null }).validate(token)).valid).toBe(true);
  });

  it("binds a key to the alg its JWK declares", async () => {
    // the same EC key published as ES384-only: an ES256 token signed with it must not resolve
    const v = newValidator({
      jwks: { keys: [{ ...pair.publicJwk(), alg: "ES384" }] },
      acceptedAlgorithms: ["ES256", "ES384"],
    });
    const token = await sign({ iss: ISSUER, aud: AUDIENCE, exp: inFiveMinutes() });
    expect((await v.validate(token)).error).toBe(errors.KEY_NOT_FOUND);
  });
});

describe("introspection edge cases", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("introspect throws when no endpoint is configured", async () => {
    await expect(newValidator().introspect("token")).rejects.toThrow(
      "no introspection endpoint configured",
    );
  });

  it("client_secret_post puts credentials in the form body", async () => {
    let captured: { body: string; headers: Record<string, string> } | null = null;
    const httpPost = async (_url: string, body: string, headers: Record<string, string>) => {
      captured = { body, headers };
      return { active: true };
    };
    const validator = newValidator(
      { introspection: { ...INTROSPECTION, authMethod: "client_secret_post" } },
      { httpPost },
    );
    const result = await validator.validateActive("opaque-token");
    expect(result.valid).toBe(true);
    expect(captured!.headers.Authorization).toBeUndefined();
    expect(captured!.body).toContain("client_id=rs-1");
    expect(captured!.body).toContain("client_secret=s3cret");
  });

  it("validateActive enforces required scopes", async () => {
    const validator = newValidator(
      { introspection: INTROSPECTION },
      { httpPost: async () => ({ active: true, scope: "read" }) },
    );
    const result = await validator.validateActive("opaque-token", ["read", "admin"]);
    expect(result.valid).toBe(false);
    expect(result.error).toBe(errors.INSUFFICIENT_SCOPE);
  });

  it("validateActive enforces the audience when the response carries one", async () => {
    const validator = newValidator(
      { introspection: INTROSPECTION },
      { httpPost: async () => ({ active: true, aud: ["https://other.example.com"] }) },
    );
    const result = await validator.validateActive("opaque-token");
    expect(result.valid).toBe(false);
    expect(result.error).toBe(errors.INVALID_AUDIENCE);
  });

  it("validateActive refuses a non-string sub rather than drop it", async () => {
    const validator = newValidator(
      { introspection: INTROSPECTION },
      { httpPost: async () => ({ active: true, sub: 123 }) },
    );
    const result = await validator.validateActive("opaque-token");
    expect(result.valid).toBe(false);
    expect(result.error).toBe("invalid_token");
  });

  it("default POST transport posts the form and parses JSON", async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ active: true })));
    vi.stubGlobal("fetch", fetchMock);
    const validator = newValidator({ introspection: INTROSPECTION });
    const result = await validator.validateActive("opaque-token");
    expect(result.valid).toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(
      INTROSPECTION.endpoint,
      expect.objectContaining({ method: "POST", redirect: "manual" }),
    );
  });

  it("default POST transport refuses a non-2xx response", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 401 })));
    await expect(newValidator({ introspection: INTROSPECTION }).introspect("t")).rejects.toThrow(
      "introspection failed: 401",
    );
  });
});

describe("config resolution", () => {
  it("wraps a string audience into a list", () => {
    const resolved = resolveConfig({ issuer: ISSUER, audiences: AUDIENCE });
    expect(resolved.audiences).toEqual([AUDIENCE]);
  });

  it("applies defaults", () => {
    const resolved = resolveConfig({ issuer: ISSUER, audiences: AUDIENCE });
    expect(resolved.requiredScopes).toEqual([]);
    expect(resolved.acceptedAlgorithms).toEqual([...DEFAULT_ALGORITHMS]);
    expect(resolved.leewaySeconds).toBe(60);
    expect(resolved.acceptedTokenTypes).toEqual(["at+jwt"]);
  });

  it("requires an issuer and an audience", () => {
    expect(() => resolveConfig({ issuer: "", audiences: [AUDIENCE] })).toThrow("issuer is required");
    expect(() => resolveConfig({ issuer: ISSUER, audiences: [] })).toThrow("audience");
    expect(() => resolveConfig({ issuer: ISSUER, audiences: undefined as unknown as string[] })).toThrow(
      "audience",
    );
  });
});

describe("validation results", () => {
  it("failure without a description leaves errorDescription null", () => {
    const result = failure(errors.EXPIRED);
    expect(result.valid).toBe(false);
    expect(result.errorDescription).toBeNull();
  });

  it("success with a non-string sub leaves subject null", () => {
    const result = success({ sub: 42, exp: 100 }, [], []);
    expect(result.subject).toBeNull();
    expect(result.expiresAt).toBe(100);
  });
});
