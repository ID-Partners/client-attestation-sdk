/**
 * Unit tests for IssuedAttestation's token-endpoint proof helpers: the dedicated PoP JWT (`.pop`)
 * and the DPoP-combined proof (`.dpop`) — both signed by the instance key the issuance endpoint
 * bound into the minted attestation.
 */
import { describe, expect, it } from "vitest";
import { decodeJwt, decodeProtectedHeader } from "jose";

import { IssuedAttestation, SigningKeyPair } from "../src/index.js";

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
