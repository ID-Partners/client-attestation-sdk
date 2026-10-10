import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";
import { SignJWT } from "jose";
import { SigningKeyPair } from "../src/index.js";

import { AccessTokenValidator, ProtectedResource, bearerToken, errors } from "../src/validator/index.js";

const VALIDATION = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "validation");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const vectors: any = JSON.parse(readFileSync(join(VALIDATION, "tokens.json"), "utf8"));

function resource(): ProtectedResource {
  const validator = new AccessTokenValidator({
    issuer: vectors.issuer,
    audiences: [vectors.audience],
    jwks: vectors.jwks,
    requiredScopes: vectors.required_scopes,
    acceptedAlgorithms: vectors.accepted_algorithms,
  });
  return new ProtectedResource(vectors.audience, [vectors.issuer], validator, ["read", "write"]);
}

function tokenNamed(name: string): string {
  return vectors.cases.find((c: { name: string }) => c.name === name).token;
}

describe("protected resource", () => {
  it("checks its own audience with a shared validator", async () => {
    const other = "https://other.example.com";
    const validator = new AccessTokenValidator({ issuer: vectors.issuer, audiences: [vectors.audience, other], jwks: vectors.jwks });
    const token = tokenNamed("valid");
    expect((await validator.validate(token)).valid).toBe(true);
    const denied = await new ProtectedResource(other, [vectors.issuer], validator).authenticate("Bearer " + token);
    expect(denied.authorized).toBe(false);
    expect(denied.status).toBe(401);
    expect(denied.result?.error).toBe(errors.INVALID_AUDIENCE);
    expect(denied.error).toBe("invalid_token");
    expect((await new ProtectedResource(vectors.audience, [vectors.issuer], validator).authenticate("Bearer " + token)).authorized).toBe(true);
  });

  it.each([{ jkt: "bound-key" }, { "x5t#S256": "certificate" }, {}, "malformed"])("refuses confirmation without proof: %j", async (cnf) => {
    const key = await SigningKeyPair.generate("ES256");
    const validator = new AccessTokenValidator({ issuer: "https://issuer.test", audiences: ["https://api.test"], jwks: { keys: [key.publicJwk()] } });
    const resource = new ProtectedResource("https://api.test", ["https://issuer.test"], validator);
    const claims = { iss: "https://issuer.test", aud: "https://api.test", exp: Math.floor(Date.now() / 1000) + 300, cnf };
    const sign = (payload: Record<string, unknown>) => new SignJWT(payload).setProtectedHeader({ alg: "ES256", typ: "at+jwt", kid: key.keyId }).sign(key.privateKey);
    const token = await sign(claims);
    expect((await validator.validate(token)).valid).toBe(true);
    const denied = await resource.authenticate("Bearer " + token);
    expect(denied.authorized).toBe(false);
    expect(denied.status).toBe(401);
    expect(denied.result?.error).toBe(errors.INVALID_TOKEN);
    expect(denied.error).toBe("invalid_token");
    expect((await resource.authenticate("Bearer " + await sign({ ...claims, cnf: null }))).authorized).toBe(true);
  });

  it("extracts bearer tokens", () => {
    expect(bearerToken("Bearer abc.def")).toBe("abc.def");
    expect(bearerToken("bearer abc")).toBe("abc");
    expect(bearerToken("Basic abc")).toBeNull();
    expect(bearerToken("")).toBeNull();
    expect(bearerToken(null)).toBeNull();
    expect(bearerToken("Bearer ")).toBeNull();
  });

  it("emits RFC 9728 metadata and paths", () => {
    const pr = resource();
    const md = pr.metadata();
    expect(md.resource).toBe("https://api.example.com");
    expect(md.authorization_servers).toEqual(["https://issuer.example.com"]);
    expect(md.bearer_methods_supported).toEqual(["header"]);
    expect(md.scopes_supported).toEqual(["read", "write"]);
    expect(pr.metadataPath()).toBe("/.well-known/oauth-protected-resource");
    expect(pr.metadataUrl()).toBe("https://api.example.com/.well-known/oauth-protected-resource");

    const withPath = new ProtectedResource(
      "https://mcp.example.com/mcp",
      [vectors.issuer],
      new AccessTokenValidator({ issuer: vectors.issuer, audiences: ["https://mcp.example.com/mcp"], jwks: vectors.jwks }),
    );
    expect(withPath.metadataPath()).toBe("/.well-known/oauth-protected-resource/mcp");
  });

  it("refuses a validator that does not accept the resource as an audience", () => {
    const validator = new AccessTokenValidator({ issuer: vectors.issuer, audiences: [vectors.audience], jwks: vectors.jwks });
    expect(() => new ProtectedResource("https://other.example.com", [vectors.issuer], validator)).toThrow(
      "does not accept this resource",
    );
  });

  it("authorizes a valid token", async () => {
    const d = await resource().authenticate("Bearer " + tokenNamed("valid"));
    expect(d.authorized).toBe(true);
    expect(d.status).toBe(200);
    expect(d.result?.subject).toBe("agent-1");
  });

  it("challenges a missing token with 401", async () => {
    const d = await resource().authenticate(null);
    expect(d.authorized).toBe(false);
    expect(d.status).toBe(401);
    expect(d.wwwAuthenticate).toContain(
      'resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"',
    );
  });

  it("maps an expired token to 401 invalid_token", async () => {
    const d = await resource().authenticate("Bearer " + tokenNamed("expired"));
    expect(d.status).toBe(401);
    expect(d.error).toBe("invalid_token");
    expect(d.wwwAuthenticate).toContain('error="invalid_token"');
  });

  it("maps a wrong-audience token to 401", async () => {
    const d = await resource().authenticate("Bearer " + tokenNamed("wrong_audience"));
    expect(d.status).toBe(401);
    expect(d.result?.error).toBe(errors.INVALID_AUDIENCE);
  });

  it("maps insufficient scope to 403", async () => {
    const d = await resource().authenticate("Bearer " + tokenNamed("valid"), ["read", "admin"]);
    expect(d.status).toBe(403);
    expect(d.error).toBe("insufficient_scope");
    expect(d.wwwAuthenticate).toContain('error="insufficient_scope"');
  });
});
