/**
 * Unit tests for IssuedAttestation's token-endpoint proof helpers: the dedicated PoP JWT (`.pop`)
 * and the DPoP-combined proof (`.dpop`) — both signed by the instance key the issuance endpoint
 * bound into the minted attestation.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { decodeJwt, decodeProtectedHeader } from "jose";

import {
  AttestationIssuanceClient,
  type AttesterProfile,
  ClientAttestationError,
  IssuedAttestation,
  type MintResult,
  SigningKeyPair,
  StaticSvidSource,
} from "../src/index.js";

const AUDIENCE = "https://as.example.com";
const TOKEN_ENDPOINT = "https://as.example.com/as/token.oauth2";
const CLIENT_ID = "https://rp.example.com";

describe("IssuedAttestation.pop", () => {
  it("builds a Client Attestation PoP JWT carrying clientId and challenge", async () => {
    const instanceKey = await SigningKeyPair.generate("ES256");
    const issued = new IssuedAttestation("h.p.s", 300, instanceKey);
    const pop = await issued.pop(AUDIENCE, CLIENT_ID, "chal-1");
    const claims = decodeJwt(pop);
    expect(claims.aud).toBe(AUDIENCE);
    expect(claims.iss).toBe(CLIENT_ID);
    expect(claims.challenge).toBe("chal-1");
  });

  it("omits iss and challenge when unset", async () => {
    const instanceKey = await SigningKeyPair.generate("ES256");
    const issued = new IssuedAttestation("h.p.s", 300, instanceKey);
    const pop = await issued.pop(AUDIENCE);
    const claims = decodeJwt(pop);
    expect(claims.iss).toBeUndefined();
    expect(claims.challenge).toBeUndefined();
  });
});

describe("IssuedAttestation.dpop", () => {
  it("builds a DPoP proof JWT bound to the token endpoint, carrying the challenge as nonce", async () => {
    const instanceKey = await SigningKeyPair.generate("ES256");
    const issued = new IssuedAttestation("h.p.s", 300, instanceKey);
    const dpop = await issued.dpop("POST", TOKEN_ENDPOINT, "chal-2");
    const claims = decodeJwt(dpop);
    expect(claims.htm).toBe("POST");
    expect(claims.htu).toBe(TOKEN_ENDPOINT);
    expect(claims.nonce).toBe("chal-2");
    expect(decodeProtectedHeader(dpop).typ).toBe("dpop+jwt");
  });

  it("omits nonce when no challenge is given", async () => {
    const instanceKey = await SigningKeyPair.generate("ES256");
    const issued = new IssuedAttestation("h.p.s", 300, instanceKey);
    const dpop = await issued.dpop("POST", TOKEN_ENDPOINT);
    const claims = decodeJwt(dpop);
    expect(claims.nonce).toBeUndefined();
  });
});

describe("AttestationIssuanceClient https rule", () => {
  afterEach(() => vi.unstubAllGlobals());

  /** Answers every request with a minted attestation and records where it went, with no network. */
  function recordFetch(): string[] {
    const urls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL) => {
        urls.push(String(url));
        return new Response(JSON.stringify({ attestation: "h.p.s", client_attestation: "h.p.s" }), { status: 200 });
      }),
    );
    return urls;
  }

  /** Mints through the transport at a URL of its own choosing, as a custom profile may. */
  const offsite = (target: string): AttesterProfile => ({
    discover: async () => {
      throw new Error("not used");
    },
    mint: async (transport, _metadata, request) => {
      const res = await transport.requestJson("mint", "POST", target, { evidence: request.evidence });
      return { attestation: res.client_attestation as string };
    },
  });

  const client = (endpoint: string, opts?: Parameters<typeof AttestationIssuanceClient.create>[4]) =>
    AttestationIssuanceClient.create(endpoint, "client-1", "https://attester.example", new StaticSvidSource("svid"), opts);

  it("refuses a plain-http endpoint at construction", async () => {
    const urls = recordFetch();
    const err = await client("http://pf.example/federation/attestation").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ClientAttestationError);
    expect((err as Error).message).toContain("endpoint must use https");
    expect(urls).toEqual([]);
  });

  it("allows https and loopback endpoints", async () => {
    const urls = recordFetch();
    expect((await (await client("https://pf.example/federation/attestation")).bootstrap()).attestation).toBe("h.p.s");
    expect((await (await client("http://127.0.0.1:9031/federation/attestation")).bootstrap()).attestation).toBe("h.p.s");
    expect(urls).toEqual(["https://pf.example/federation/attestation", "http://127.0.0.1:9031/federation/attestation"]);
  });

  it("keeps the https rule for a custom profile's calls", async () => {
    const urls = recordFetch();
    const c = await client("https://pf.example/federation/attestation", { profile: offsite("http://attester.example/mint") });
    await expect(c.bootstrap()).rejects.toThrow("must use https");
    expect(urls).toEqual([]);
  });

  it("lifts the https rule with allowInsecure", async () => {
    const urls = recordFetch();
    await (await client("http://pf.example/federation/attestation", { allowInsecure: true })).bootstrap();
    const c = await client("http://pf.example/federation/attestation", {
      allowInsecure: true,
      profile: offsite("http://attester.example/mint"),
    });
    expect((await c.bootstrap()).attestation).toBe("h.p.s");
    expect(urls).toEqual(["http://pf.example/federation/attestation", "http://attester.example/mint"]);
  });

  it.each([undefined, null, { attestation: "" }])("rejects a profile that mints %j", async (result) => {
    const empty: AttesterProfile = {
      discover: async () => {
        throw new Error("not used");
      },
      mint: async () => result as unknown as MintResult,
    };
    const c = await client("https://pf.example/federation/attestation", { profile: empty });
    const err = await c.bootstrap().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ClientAttestationError);
    expect((err as Error).message).toBe("attester response contained no attestation");
  });
});
