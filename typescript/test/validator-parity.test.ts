/**
 * The decisions validation/SEMANTICS.md pins for every port, beyond what the shared vectors reach: the
 * default introspection transport's cap and strict parsing, injected transports that return junk, the
 * clock, and the strict JSON reader's edges.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { SignJWT, type JSONWebKeySet } from "jose";

import { TransportError } from "../src/errors.js";
import { SigningKeyPair } from "../src/index.js";
import { AccessTokenValidator, errors, type ValidatorConfig } from "../src/validator/index.js";
import * as strict from "../src/validator/strict.js";
import { MAX_INTROSPECTION_BYTES } from "../src/validator/validator.js";

const ISSUER = "https://issuer.example.com";
const AUDIENCE = "https://api.example.com";
const INTROSPECTION = { endpoint: "https://issuer.example.com/introspect", clientId: "rs", clientSecret: "s" };

let pair: SigningKeyPair;
let jwks: JSONWebKeySet;

beforeAll(async () => {
  pair = await SigningKeyPair.generate("ES256");
  jwks = { keys: [pair.publicJwk()] };
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function newValidator(overrides: Partial<ValidatorConfig> = {}, opts = {}) {
  return new AccessTokenValidator({ issuer: ISSUER, audiences: [AUDIENCE], jwks, ...overrides }, opts);
}

async function token(claims: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ iss: ISSUER, aud: AUDIENCE, sub: "agent-1", scope: "read", exp: 2_000_000_000, ...claims })
    .setProtectedHeader({ alg: "ES256", kid: pair.keyId, typ: "at+jwt" })
    .sign(pair.privateKey);
}

const encoder = new TextEncoder();

describe("default introspection transport", () => {
  it.each([
    ['{"active": true, "active": false}', "duplicate member name"],
    ["[true]", "not a JSON object"],
    ['{"active": true,}', "not JSON"],
  ])("refuses %s like every port", async (body, message) => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(body)));
    const err = await newValidator({ introspection: INTROSPECTION }).validateActive("t").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(TransportError);
    expect((err as TransportError).kind).toBe("json");
    expect((err as Error).message).toContain(message);
  });

  it("refuses a body over the 1 MiB cap", async () => {
    const big = `{"active": true, "x": "${"a".repeat(MAX_INTROSPECTION_BYTES)}"}`;
    vi.stubGlobal("fetch", vi.fn(async () => new Response(big)));
    const err = await newValidator({ introspection: INTROSPECTION }).validateActive("t").catch((e: unknown) => e);
    expect((err as TransportError).kind).toBe("too_large");
  });

  it("raises for a transport failure or a missing endpoint, never a verdict", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 503 })));
    await expect(newValidator({ introspection: INTROSPECTION }).validateActive("t")).rejects.toThrow(TransportError);
    await expect(newValidator().validateActive("t")).rejects.toThrow("no introspection endpoint");
  });
});

describe("injected introspection transport", () => {
  it.each([null, ["active"], "active", 1])("treats a non-object response (%j) as a transport error", async (junk) => {
    const validator = newValidator({ introspection: INTROSPECTION }, { httpPost: async () => junk });
    await expect(validator.validateActive("t")).rejects.toThrow("not an object");
  });
});

describe("clock and leeway", () => {
  it("checks exp against the injected clock, with leeway 0 meaning none", async () => {
    const t = await token({ exp: 1_000_000 });
    const at = (seconds: number, leewaySeconds?: number) =>
      newValidator({ leewaySeconds }, { clock: () => seconds * 1000 }).validate(t);
    expect((await at(1_000_059)).valid).toBe(true);
    expect((await at(1_000_061)).error).toBe(errors.EXPIRED);
    expect((await at(1_000_000, 0)).valid).toBe(true);
    expect((await at(1_000_001, 0)).error).toBe(errors.EXPIRED);
  });
});

describe("strict parsing", () => {
  it("never throws on hostile input", async () => {
    const validator = newValidator();
    for (const t of [undefined, 7, "", "..", "a.b.c.d", "e30.e30.", "!!.e30.e30"]) {
      const result = await validator.validate(t as unknown as string);
      expect(result.valid).toBe(false);
      expect([errors.INVALID_TOKEN, errors.UNSUPPORTED_ALGORITHM]).toContain(result.error);
    }
  });

  it("reads names and strings with escapes and nested containers", () => {
    expect(strict.parseObject(encoder.encode('{"a": "x\\"y{[", "b": [1, {"c": null}], "d": {}}'))).toEqual({
      a: 'x"y{[',
      b: [1, { c: null }],
      d: {},
    });
    expect(() => strict.parseObject(encoder.encode('{"a": [{"x": 1, "x": 2}]}'))).toThrow("duplicate");
    expect(() => strict.parseObject(encoder.encode(`${"[".repeat(70)}${"]".repeat(70)}`))).toThrow(
      "not a JSON object",
    );
  });

  it("bounds NumericDates to the exact-integer range", () => {
    expect(() => strict.numericDate({ exp: -(2 ** 53) }, "exp")).toThrow("out of range");
    expect(strict.numericDate({ exp: -4.9 }, "exp")).toBe(-4);
  });

  it("refuses non-string subjects and leaves a missing one undefined", async () => {
    expect(strict.subject({})).toBeUndefined();
    const result = await newValidator().validate(await token({ sub: 7 }));
    expect(result.error).toBe(errors.INVALID_TOKEN);
  });
});
