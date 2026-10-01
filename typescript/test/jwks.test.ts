import { afterEach, describe, expect, it, vi } from "vitest";
import type { JSONWebKeySet, JWK } from "jose";

import { SigningKeyPair } from "../src/index.js";
import { JwksProvider } from "../src/validator/jwks.js";

async function realKey(): Promise<JWK> {
  return (await SigningKeyPair.generate("ES256")).publicJwk();
}

describe("JwksProvider", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("falls back to the single configured key when the header has no kid", async () => {
    const jwk = await realKey();
    delete jwk.kid;
    const provider = new JwksProvider({ jwks: { keys: [jwk] } });
    expect(await provider.resolve(undefined)).toBeDefined();
  });

  it("returns undefined without a kid when multiple keys are configured", async () => {
    const provider = new JwksProvider({ jwks: { keys: [await realKey(), await realKey()] } });
    expect(await provider.resolve(undefined)).toBeUndefined();
  });

  it("returns undefined for an unknown kid on a static JWKS", async () => {
    const provider = new JwksProvider({ jwks: { keys: [await realKey()] } });
    expect(await provider.resolve("no-such-kid")).toBeUndefined();
  });

  it("tolerates a JWKS document without a keys array", async () => {
    const provider = new JwksProvider({ jwks: {} as JSONWebKeySet });
    expect(await provider.resolve(undefined)).toBeUndefined();
  });

  it("skips unimportable JWKs but keeps the good ones", async () => {
    const good = await realKey();
    const bad: JWK = { kty: "EC", crv: "P-256", x: "!!not-base64url!!", y: "!!", kid: "bad" };
    const provider = new JwksProvider({ jwks: { keys: [bad, good] } });
    expect(await provider.resolve(good.kid)).toBeDefined();
    expect(await provider.resolve("bad")).toBeUndefined();
  });

  it("infers an alg for JWKs that omit it, across key types", async () => {
    const p256 = await realKey();
    delete p256.alg;
    const keys: JWK[] = [
      p256,
      { kty: "EC", crv: "P-384", x: "AA", y: "AA", kid: "p384" },
      { kty: "EC", crv: "P-521", x: "AA", y: "AA", kid: "p521" },
      { kty: "EC", crv: "P-999", x: "AA", y: "AA", kid: "weird-crv" },
      { kty: "EC", kid: "no-crv" },
      { kty: "RSA", n: "AA", e: "AQAB", kid: "rsa" },
      { kty: "OKP", crv: "Ed25519", x: "AA", kid: "okp" },
      { kty: "oct", k: "AA", kid: "oct" },
    ];
    const provider = new JwksProvider({ jwks: { keys } });
    // The real P-256 key imports; the placeholder JWKs exercise alg inference and are skipped.
    expect(await provider.resolve(p256.kid)).toBeDefined();
  });

  it("fetches from jwksUri and refreshes on an unknown kid, at most once per cooldown", async () => {
    const a = await realKey();
    const b = await realKey();
    const responses = [{ keys: [a] }, { keys: [a, b] }, { keys: [a, b] }];
    const httpGet = vi.fn(async () => JSON.stringify(responses.shift()));
    let now = 1_000_000;
    const provider = new JwksProvider({ jwksUri: "https://as.example.com/jwks", httpGet, clock: () => now });

    expect(await provider.resolve(a.kid)).toBeDefined();
    expect(httpGet).toHaveBeenCalledTimes(1);
    // inside the cooldown an unknown kid does not fetch
    expect(await provider.resolve(b.kid)).toBeUndefined();
    expect(httpGet).toHaveBeenCalledTimes(1);
    now += 30_000;
    expect(await provider.resolve(b.kid)).toBeDefined();
    expect(httpGet).toHaveBeenCalledTimes(2);
  });

  it("cannot be made to fetch per request by made-up kids", async () => {
    const httpGet = vi.fn(async () => JSON.stringify({ keys: [await realKey()] }));
    const provider = new JwksProvider({ jwksUri: "https://as.example.com/jwks", httpGet });
    for (let i = 0; i < 100; i++) {
      expect(await provider.resolve(`made-up-${i}`)).toBeUndefined();
    }
    expect(httpGet).toHaveBeenCalledTimes(1);
  });

  it("shares one fetch between concurrent misses", async () => {
    const jwk = await realKey();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const httpGet = vi.fn(async () => {
      await gate;
      return JSON.stringify({ keys: [jwk] });
    });
    const provider = new JwksProvider({ jwksUri: "https://as.example.com/jwks", httpGet });
    const pending = Array.from({ length: 10 }, () => provider.resolve(jwk.kid));
    release();
    const keys = await Promise.all(pending);
    expect(httpGet).toHaveBeenCalledTimes(1);
    expect(keys.every((k) => k !== undefined)).toBe(true);
  });

  it("refreshes old keys and keeps them when the refresh fails", async () => {
    const old = await realKey();
    const rotated = await realKey();
    let fail = false;
    let served = old;
    const httpGet = vi.fn(async () => {
      if (fail) throw new Error("issuer down");
      return JSON.stringify({ keys: [served] });
    });
    let now = 1_000_000;
    const provider = new JwksProvider({
      jwksUri: "https://as.example.com/jwks",
      httpGet,
      maxAgeSeconds: 600,
      clock: () => now,
    });
    expect(await provider.resolve(old.kid)).toBeDefined();
    served = rotated;
    now += 600_000;
    expect(await provider.resolve(rotated.kid)).toBeDefined();
    expect(await provider.resolve(old.kid)).toBeUndefined();
    fail = true;
    now += 600_000;
    expect(await provider.resolve(rotated.kid)).toBeDefined();
    expect(provider.lastError).toContain("issuer down");
  });

  it("refuses an oversized JWKS", async () => {
    const httpGet = async () => JSON.stringify({ keys: [], padding: "x".repeat(512 * 1024) });
    const provider = new JwksProvider({ jwksUri: "https://as.example.com/jwks", httpGet });
    expect(await provider.resolve("any")).toBeUndefined();
    expect(provider.lastError).toContain("larger than");
  });

  it("default HTTP GET fetches the JWKS body", async () => {
    const jwk = await realKey();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ keys: [jwk] }))),
    );
    const provider = new JwksProvider({ jwksUri: "https://as.example.com/jwks" });
    expect(await provider.resolve(jwk.kid)).toBeDefined();
  });

  it("default HTTP GET fails on a non-2xx status", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 500 })));
    const provider = new JwksProvider({ jwksUri: "https://as.example.com/jwks" });
    expect(await provider.resolve("any")).toBeUndefined();
    expect(provider.lastError).toContain("GET https://as.example.com/jwks failed: 500");
  });

  it("default HTTP GET refuses a declared oversized body", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: true, headers: new Headers({ "content-length": String(10 * 1024 * 1024) }) })),
    );
    const provider = new JwksProvider({ jwksUri: "https://as.example.com/jwks" });
    expect(await provider.resolve("any")).toBeUndefined();
    expect(provider.lastError).toContain("larger than");
  });
});
