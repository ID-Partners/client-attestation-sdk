import { describe, expect, it } from "vitest";
import { decodeProtectedHeader, importJWK, jwtVerify, type JWK } from "jose";

import {
  ATTESTATION_TYP,
  ClientAttestationBuilder,
  ClientAttestationCredential,
  DPOP_TYP,
  DpopProofBuilder,
  POP_TYP,
  PopBuilder,
  SigningKeyPair,
} from "../src/index.js";

const ATTESTER_ISS = "https://attester.example.com";
const CLIENT_ID = "https://rp.example.com";
const AUDIENCE = "https://as.example.com";
const TOKEN_ENDPOINT = "https://as.example.com/as/token.oauth2";

/** Import the public half of a SigningKeyPair as a verification key. */
async function publicKey(key: SigningKeyPair) {
  return importJWK(key.publicJwk(), key.algorithm);
}

describe("client attestation SDK roundtrip", () => {
  it("attestation binds the instance key (typ + iss + sub + cnf.jwk.x)", async () => {
    const attester = await SigningKeyPair.generate("ES256");
    const instance = await SigningKeyPair.generate("ES256");
    const attestation = await new ClientAttestationBuilder(attester, ATTESTER_ISS)
      .clientId(CLIENT_ID)
      .confirmationKey(instance)
      .expiresIn(300)
      .build();

    expect(decodeProtectedHeader(attestation).typ).toBe(ATTESTATION_TYP);
    const { payload } = await jwtVerify(attestation, await publicKey(attester));
    expect(payload.iss).toBe(ATTESTER_ISS);
    expect(payload.sub).toBe(CLIENT_ID);
    const cnf = payload.cnf as { jwk: JWK };
    expect(cnf.jwk.x).toBe(instance.publicJwk().x);
    // cnf.jwk must include the instance kid (its RFC 7638 thumbprint).
    expect(cnf.jwk.kid).toBe(instance.keyId);
  });

  it("PoP carries aud/jti/iat and verifies with the instance key", async () => {
    const instance = await SigningKeyPair.generate("ES256");
    const pop = await new PopBuilder(instance).clientId(CLIENT_ID).audience(AUDIENCE).build();

    expect(decodeProtectedHeader(pop).typ).toBe(POP_TYP);
    const { payload } = await jwtVerify(pop, await publicKey(instance), { audience: AUDIENCE });
    expect(payload.aud).toBe(AUDIENCE);
    expect(payload.iss).toBe(CLIENT_ID);
    expect(payload.jti).toBeTypeOf("string");
    expect(payload.iat).toBeTypeOf("number");
    // PoP must NOT carry exp.
    expect(payload.exp).toBeUndefined();
  });

  it("DPoP embeds the public jwk header (no d) and carries htm/htu/jti/iat", async () => {
    const instance = await SigningKeyPair.generate("ES256");
    const dpop = await new DpopProofBuilder(instance).method("POST").uri(TOKEN_ENDPOINT).build();

    const header = decodeProtectedHeader(dpop);
    expect(header.typ).toBe(DPOP_TYP);
    expect(header.jwk).toBeDefined();
    const jwk = header.jwk as JWK;
    expect(jwk.d).toBeUndefined();
    expect(jwk.kid).toBeUndefined();
    expect(jwk.x).toBe(instance.publicJwk().x);

    const { payload } = await jwtVerify(dpop, await publicKey(instance));
    expect(payload.htm).toBe("POST");
    expect(payload.htu).toBe(TOKEN_ENDPOINT);
    expect(payload.jti).toBeTypeOf("string");
    expect(payload.iat).toBeTypeOf("number");
  });

  it("credential produces both header sets", async () => {
    const attester = await SigningKeyPair.generate("ES256");
    const instance = await SigningKeyPair.generate("ES256");
    const attestation = await new ClientAttestationBuilder(attester, ATTESTER_ISS)
      .clientId(CLIENT_ID)
      .confirmationKey(instance)
      .expiresIn(300)
      .build();

    const cred = new ClientAttestationCredential(attestation, instance);
    const popHeaders = await cred.popHeaders(CLIENT_ID, AUDIENCE);
    const dpopHeaders = await cred.dpopHeaders("POST", TOKEN_ENDPOINT);

    expect(popHeaders["OAuth-Client-Attestation"]).toBe(attestation);
    expect(popHeaders["OAuth-Client-Attestation-PoP"]).toBeTypeOf("string");
    expect(dpopHeaders["OAuth-Client-Attestation"]).toBe(attestation);
    expect(dpopHeaders["DPoP"]).toBeTypeOf("string");
  });

  it("kid equals the RFC 7638 thumbprint and matches the header kid", async () => {
    const attester = await SigningKeyPair.generate("ES256");
    const instance = await SigningKeyPair.generate("ES256");
    const attestation = await new ClientAttestationBuilder(attester, ATTESTER_ISS)
      .clientId(CLIENT_ID)
      .confirmationKey(instance)
      .expiresIn(300)
      .build();

    // Attestation header kid is the attester thumbprint; PoP header kid is the instance thumbprint.
    expect(decodeProtectedHeader(attestation).kid).toBe(attester.keyId);
    const pop = await new PopBuilder(instance).audience(AUDIENCE).build();
    expect(decodeProtectedHeader(pop).kid).toBe(instance.keyId);
  });
});
