import { afterEach, describe, expect, it, vi } from "vitest";
import type { JSONWebKeySet, JWK } from "jose";

import { SigningKeyPair } from "../src/index.js";
import { JwksProvider } from "../src/validator/jwks.js";

async function realKey(): Promise<JWK> {
  return (await SigningKeyPair.generate("ES256")).publicJwk();
}

describe("JwksProvider", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

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

  it("skips entries that aren't JSON objects and keeps the rest", async () => {
    const good = await realKey();
    const keys = ["not a jwk", 42, null, ["kty"], good] as unknown as JWK[];
    const provider = new JwksProvider({ jwks: { keys } });
    expect(await provider.resolve(good.kid)).toBeDefined();
    // the readable key is the only one, so it answers a token without a kid
    expect(await provider.resolve(undefined)).toBeDefined();
  });

  it("uses a key whose key_ops holds verify among other operations", async () => {
    // WebCrypto refuses a public key with usages besides "verify"; the key is imported without its key_ops
    for (const ops of [["sign", "verify"], ["verify", "encrypt"]]) {
      const ec = { ...(await realKey()), key_ops: ops };
      delete ec.alg;
      const pair = await crypto.subtle.generateKey(
        { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
        true,
        ["sign", "verify"],
      );
      const rsa = { ...((await crypto.subtle.exportKey("jwk", pair.publicKey)) as JWK), kid: "rsa", key_ops: ops };
      delete rsa.alg;
      const provider = new JwksProvider({ jwks: { keys: [ec, rsa] } });
      expect(await provider.resolve(ec.kid, "ES256")).toBeTruthy();
      expect(await provider.resolve("rsa", "RS256")).toBeTruthy(); // imported while parsing the set
      expect(await provider.resolve("rsa", "PS256")).toBeTruthy(); // imported later, for another alg
    }
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

  it("lets a caller holding a stale key go on without waiting for another caller's fetch", async () => {
    const jwk = await realKey();
    let slow = false;
    let started!: () => void;
    const fetching = new Promise<void>((r) => (started = r));
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const httpGet = vi.fn(async () => {
      if (slow) {
        started();
        await gate;
      }
      return JSON.stringify({ keys: [jwk] });
    });
    let now = 1_000_000;
    const provider = new JwksProvider({ jwksUri: "https://as.example.com/jwks", httpGet, clock: () => now });
    expect(await provider.resolve(jwk.kid)).toBeDefined();
    slow = true;
    now += 3_600_000; // stale: the next caller refetches, and the fetch hangs
    const fetcher = provider.resolve(jwk.kid);
    await fetching;
    const settled = <T>(p: Promise<T>, ms: number) =>
      Promise.race([p.then(() => true), new Promise<boolean>((r) => setTimeout(() => r(false), ms))]);
    const holder = provider.resolve(jwk.kid);
    expect(await settled(holder, 1000), "a caller with a usable stale key waited for another caller's fetch").toBe(
      true,
    );
    expect(await holder).toBeDefined();
    // a caller without the key waits for the fetch in flight, which may bring it
    const misser = provider.resolve("other");
    expect(await settled(misser, 100)).toBe(false);
    release();
    expect(await fetcher).toBeDefined();
    expect(await misser).toBeUndefined();
    expect(httpGet).toHaveBeenCalledTimes(2);
  });

  it("ages the set and throttles refetches on a monotonic clock, not the wall clock", async () => {
    const a = await realKey();
    const b = await realKey();
    let served = a;
    const httpGet = vi.fn(async () => JSON.stringify({ keys: [served] }));
    let wall = Date.now();
    let mono = 5_000;
    vi.spyOn(Date, "now").mockImplementation(() => wall);
    vi.spyOn(performance, "now").mockImplementation(() => mono);
    const provider = new JwksProvider({ jwksUri: "https://as.example.com/jwks", httpGet });
    expect(await provider.resolve(a.kid)).toBeDefined();
    // the wall clock steps back an hour (an NTP correction); the cooldown still passes in real time
    served = b;
    wall -= 3_600_000;
    mono += 30_000;
    expect(await provider.resolve(b.kid), "an unknown kid after the cooldown was throttled").toBeDefined();
    expect(httpGet).toHaveBeenCalledTimes(2);
    // and the set still grows old: a removed key is dropped after max age
    served = a;
    mono += 3_600_000;
    expect(await provider.resolve(b.kid), "a key removed from the set was trusted past max age").toBeUndefined();
    expect(httpGet).toHaveBeenCalledTimes(3);
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

  it("keeps only the keys of a fetched set that may verify signatures", async () => {
    // the shared vectors pin this for a static set; a fetched set goes through the same filter
    const sig = { ...(await realKey()), kid: "sig", use: "sig", key_ops: ["verify"] };
    const enc = { ...(await realKey()), kid: "enc", use: "enc" };
    const wrap = { ...(await realKey()), kid: "wrap", key_ops: ["wrapKey"] };
    const leaked = { ...(await realKey()), kid: "private", d: "AAAA" };
    const httpGet = async () => JSON.stringify({ keys: [enc, wrap, leaked, sig] });
    const provider = new JwksProvider({ jwksUri: "https://as.example.com/jwks", httpGet });
    expect(await provider.resolve("sig", "ES256")).toBeTruthy();
    for (const kid of ["enc", "wrap", "private"]) {
      expect(await provider.resolve(kid, "ES256"), kid).toBeUndefined();
    }
    // the sole usable key answers a token without a kid
    expect(await provider.resolve(undefined, "ES256")).toBeTruthy();
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
