import { describe, expect, it } from "vitest";
import { decodeJwt, decodeProtectedHeader } from "jose";

import {
  ClientAttestationBuilder,
  DpopProofBuilder,
  PopBuilder,
  SigningKeyPair,
} from "../src/index.js";

const ATTESTER_ISS = "https://attester.example.com";
const CLIENT_ID = "https://rp.example.com";
const AUDIENCE = "https://as.example.com";
const TOKEN_ENDPOINT = "https://as.example.com/as/token.oauth2";

describe("ClientAttestationBuilder", () => {
  it("rejects a blank issuer", async () => {
    const attester = await SigningKeyPair.generate("ES256");
    expect(() => new ClientAttestationBuilder(attester, "   ")).toThrow("issuer is required");
  });

  it("requires a client_id", async () => {
    const attester = await SigningKeyPair.generate("ES256");
    const instance = await SigningKeyPair.generate("ES256");
    await expect(
      new ClientAttestationBuilder(attester, ATTESTER_ISS)
        .confirmationKey(instance)
        .expiresIn(300)
        .build(),
    ).rejects.toThrow("client_id is required");
  });

  it("requires a confirmation key", async () => {
    const attester = await SigningKeyPair.generate("ES256");
    await expect(
      new ClientAttestationBuilder(attester, ATTESTER_ISS)
        .clientId(CLIENT_ID)
        .expiresIn(300)
        .build(),
    ).rejects.toThrow("confirmation key (cnf.jwk) is required");
  });

  it("requires an expiry", async () => {
    const attester = await SigningKeyPair.generate("ES256");
    const instance = await SigningKeyPair.generate("ES256");
    await expect(
      new ClientAttestationBuilder(attester, ATTESTER_ISS)
        .clientId(CLIENT_ID)
        .confirmationKey(instance)
        .build(),
    ).rejects.toThrow("expiry is required");
  });

  it("honours explicit issuedAt and expiresAt", async () => {
    const attester = await SigningKeyPair.generate("ES256");
    const instance = await SigningKeyPair.generate("ES256");
    const attestation = await new ClientAttestationBuilder(attester, ATTESTER_ISS)
      .clientId(CLIENT_ID)
      .confirmationKey(instance)
      .issuedAt(1_700_000_000)
      .expiresAt(1_700_000_300)
      .build();
    const payload = decodeJwt(attestation);
    expect(payload.iat).toBe(1_700_000_000);
    expect(payload.exp).toBe(1_700_000_300);
  });

  it("computes exp from issuedAt + expiresIn", async () => {
    const attester = await SigningKeyPair.generate("ES256");
    const instance = await SigningKeyPair.generate("ES256");
    const attestation = await new ClientAttestationBuilder(attester, ATTESTER_ISS)
      .clientId(CLIENT_ID)
      .confirmationKey(instance)
      .issuedAt(1_700_000_000)
      .expiresIn(600)
      .build();
    const payload = decodeJwt(attestation);
    expect(payload.exp).toBe(1_700_000_600);
  });

  it("carries authorization_details and workload when non-empty", async () => {
    const attester = await SigningKeyPair.generate("ES256");
    const instance = await SigningKeyPair.generate("ES256");
    const details = [{ type: "payment_initiation", actions: ["initiate"] }];
    const attestation = await new ClientAttestationBuilder(attester, ATTESTER_ISS)
      .clientId(CLIENT_ID)
      .confirmationKey(instance)
      .expiresIn(300)
      .authorizationDetails(details)
      .workload({ runtime: "container", region: "ap-southeast-2" })
      .build();
    const payload = decodeJwt(attestation);
    expect(payload.authorization_details).toEqual(details);
    expect(payload.workload).toEqual({ runtime: "container", region: "ap-southeast-2" });
  });

  it("omits empty authorization_details and workload", async () => {
    const attester = await SigningKeyPair.generate("ES256");
    const instance = await SigningKeyPair.generate("ES256");
    const attestation = await new ClientAttestationBuilder(attester, ATTESTER_ISS)
      .clientId(CLIENT_ID)
      .confirmationKey(instance)
      .expiresIn(300)
      .authorizationDetails([])
      .workload({})
      .build();
    const payload = decodeJwt(attestation);
    expect(payload.authorization_details).toBeUndefined();
    expect(payload.workload).toBeUndefined();
  });

  it("operator claim mirrors the may_act shape (sub + iss)", async () => {
    // The operator names who ANSWERS for the client, distinct from the client (`sub`) and from
    // any principal it acts for. Shaped like RFC 8693 `may_act` so an AS can lift it straight in.
    const attester = await SigningKeyPair.generate("ES256");
    const instance = await SigningKeyPair.generate("ES256");
    const attestation = await new ClientAttestationBuilder(attester, ATTESTER_ISS)
      .clientId(CLIENT_ID)
      .confirmationKey(instance)
      .expiresIn(300)
      .operator("ops-team@example.com", "https://op.example.com")
      .build();
    const payload = decodeJwt(attestation);
    expect(payload.operator).toEqual({ sub: "ops-team@example.com", iss: "https://op.example.com" });
    // Top-level, NOT tucked inside workload: workload describes the running software, the
    // operator is an accountability statement about who answers for it.
    expect((payload.workload as Record<string, unknown> | undefined)?.operator).toBeUndefined();
  });

  it("operator issuer is optional", async () => {
    const attester = await SigningKeyPair.generate("ES256");
    const instance = await SigningKeyPair.generate("ES256");
    const attestation = await new ClientAttestationBuilder(attester, ATTESTER_ISS)
      .clientId(CLIENT_ID)
      .confirmationKey(instance)
      .expiresIn(300)
      .operator("ops-team@example.com")
      .build();
    expect(decodeJwt(attestation).operator).toEqual({ sub: "ops-team@example.com" });
  });

  it("omits operator when never called", async () => {
    const attester = await SigningKeyPair.generate("ES256");
    const instance = await SigningKeyPair.generate("ES256");
    const attestation = await new ClientAttestationBuilder(attester, ATTESTER_ISS)
      .clientId(CLIENT_ID)
      .confirmationKey(instance)
      .expiresIn(300)
      .build();
    expect(decodeJwt(attestation).operator).toBeUndefined();
  });

  it("requires a non-blank operator subject", async () => {
    const attester = await SigningKeyPair.generate("ES256");
    expect(() =>
      new ClientAttestationBuilder(attester, ATTESTER_ISS).operator("", "https://op.example.com"),
    ).toThrow("operator sub is required");
  });
});

describe("PopBuilder", () => {
  it("requires an audience", async () => {
    const instance = await SigningKeyPair.generate("ES256");
    await expect(new PopBuilder(instance).clientId(CLIENT_ID).build()).rejects.toThrow(
      "audience (aud) is required",
    );
  });

  it("carries challenge and honours jti / iat overrides", async () => {
    const instance = await SigningKeyPair.generate("ES256");
    const pop = await new PopBuilder(instance)
      .audience(AUDIENCE)
      .challenge("as-challenge")
      .jwtId("jti-1")
      .issuedAt(1_700_000_000)
      .build();
    const payload = decodeJwt(pop);
    expect(payload.challenge).toBe("as-challenge");
    expect(payload.jti).toBe("jti-1");
    expect(payload.iat).toBe(1_700_000_000);
  });

  it("omits iss and challenge when unset", async () => {
    const instance = await SigningKeyPair.generate("ES256");
    const pop = await new PopBuilder(instance).audience(AUDIENCE).challenge(null).build();
    const payload = decodeJwt(pop);
    expect(payload.iss).toBeUndefined();
    expect(payload.challenge).toBeUndefined();
  });
});

describe("DpopProofBuilder", () => {
  it("requires the uri (htu)", async () => {
    const instance = await SigningKeyPair.generate("ES256");
    await expect(new DpopProofBuilder(instance).build()).rejects.toThrow("uri (htu) is required");
  });

  it("carries nonce and honours jti / iat overrides", async () => {
    const instance = await SigningKeyPair.generate("ES256");
    const dpop = await new DpopProofBuilder(instance)
      .method("GET")
      .uri(TOKEN_ENDPOINT)
      .nonce("server-nonce")
      .jwtId("jti-2")
      .issuedAt(1_700_000_000)
      .build();
    const payload = decodeJwt(dpop);
    expect(payload.htm).toBe("GET");
    expect(payload.nonce).toBe("server-nonce");
    expect(payload.jti).toBe("jti-2");
    expect(payload.iat).toBe(1_700_000_000);
    expect(decodeProtectedHeader(dpop).typ).toBe("dpop+jwt");
  });

  it("keeps the POST default when method is null/undefined and omits an unset nonce", async () => {
    const instance = await SigningKeyPair.generate("ES256");
    const dpop = await new DpopProofBuilder(instance)
      .method(null)
      .method(undefined)
      .uri(TOKEN_ENDPOINT)
      .nonce(null)
      .build();
    const payload = decodeJwt(dpop);
    expect(payload.htm).toBe("POST");
    expect(payload.nonce).toBeUndefined();
  });
});
