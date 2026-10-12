// What the builders, key import and signer seam refuse to put into a signed credential.
import { generateKeyPairSync } from "node:crypto";

import { afterEach, describe, expect, it, vi } from "vitest";
import { base64url, decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair, type JWK } from "jose";

import {
  ATTESTATION_TYP,
  ClientAttestationBuilder,
  DPOP_TYP,
  DpopProofBuilder,
  type JwsSigner,
  MintRequest,
  OpenBaoTransitSigner,
  POP_TYP,
  PopBuilder,
  SigningKeyPair,
} from "../src/index.js";

const ISS = "https://attester.example.com";

async function privateJwk(alg: string): Promise<JWK> {
  const { privateKey } = await generateKeyPair(alg, { extractable: true });
  return exportJWK(privateKey);
}

/** jose won't generate an RSA key under 2048 bits, so node:crypto makes this one. */
function rsa1024Jwk(): JWK {
  return generateKeyPairSync("rsa", { modulusLength: 1024 }).privateKey.export({ format: "jwk" }) as JWK;
}

describe("ClientAttestationBuilder cnf.jwk", () => {
  const cases: Array<[string, () => Promise<JWK>]> = [
    ["EC private", () => privateJwk("ES256")],
    ["RSA private", () => privateJwk("RS256")],
    ["oct", async () => ({ kty: "oct", k: "c2VjcmV0" })],
    ["oct without k", async () => ({ kty: "oct" })],
    ["OKP", async () => ({ kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" })],
    ["EC missing y", async () => ({ kty: "EC", crv: "P-256", x: "AAAA" })],
    ["EC bad curve", async () => ({ kty: "EC", crv: "secp256k1", x: "AAAA", y: "AAAA" })],
  ];
  for (const [name, make] of cases) {
    it(`refuses ${name}`, async () => {
      const attester = await SigningKeyPair.generate("ES256");
      const cnf = await make();
      await expect(
        (async () =>
          new ClientAttestationBuilder(attester, ISS).clientId("c").confirmationJwk(cnf).expiresIn(300).build())(),
      ).rejects.toThrow("cnf.jwk");
    });
  }

  it("keeps only the public members", async () => {
    const attester = await SigningKeyPair.generate("ES256");
    const instance = await SigningKeyPair.generate("ES256");
    const cnf = { ...instance.publicJwk(), use: "sig", x5u: "https://example.com/x5u" };
    const token = await new ClientAttestationBuilder(attester, ISS)
      .clientId("c").confirmationJwk(cnf).expiresIn(300).build();
    expect((decodeJwt(token).cnf as { jwk: JWK }).jwk).toEqual(instance.publicJwk());
  });
});

describe("ClientAttestationBuilder lifetime", () => {
  const cases: Array<[string, (b: ClientAttestationBuilder) => ClientAttestationBuilder]> = [
    ["negative ttl", (b) => b.expiresIn(-100)],
    ["zero ttl", (b) => b.expiresIn(0)],
    ["exp < iat", (b) => b.issuedAt(1700000000).expiresAt(1699999999)],
  ];
  for (const [name, configure] of cases) {
    it(`refuses ${name}`, async () => {
      const attester = await SigningKeyPair.generate("ES256");
      const instance = await SigningKeyPair.generate("ES256");
      const builder = new ClientAttestationBuilder(attester, ISS).clientId("c").confirmationKey(instance);
      await expect(configure(builder).build()).rejects.toThrow("after iat");
    });
  }
});

describe("SigningKeyPair.fromJwk", () => {
  it("signs with the thumbprint kid, not the JWK's own", async () => {
    const key = await SigningKeyPair.fromJwk({ ...(await privateJwk("ES256")), kid: "label" }, "ES256");
    const pop = await new PopBuilder(key).audience("https://as.example.com").build();
    expect(decodeProtectedHeader(pop).kid).toBe(key.keyId);
  });

  const swappedEc = async (): Promise<JWK> => {
    const other = await privateJwk("ES256");
    return { ...(await privateJwk("ES256")), x: other.x, y: other.y };
  };
  const swappedRsa = async (): Promise<JWK> => {
    const { kty, e, d } = await privateJwk("RS256");
    return { kty, e, d, n: (await privateJwk("RS256")).n };
  };
  const cases: Array<[string, () => Promise<JWK>, string]> = [
    ["P-384 as ES256", () => privateJwk("ES384"), "ES256"],
    ["P-256 as ES384", () => privateJwk("ES256"), "ES384"],
    ["EC as RS256", () => privateJwk("ES256"), "RS256"],
    ["RSA as ES256", () => privateJwk("RS256"), "ES256"],
    ["RSA-1024 as RS256", async () => rsa1024Jwk(), "RS256"],
    ["RSA-1024 as PS256", async () => rsa1024Jwk(), "PS256"],
    ["EC x/y of another key", swappedEc, "ES256"],
    ["RSA n of another key", swappedRsa, "RS256"],
    ["alg none", () => privateJwk("ES256"), "none"],
    ["alg HS256", () => privateJwk("ES256"), "HS256"],
  ];
  for (const [name, make, alg] of cases) {
    it(`refuses ${name}`, async () => {
      const jwk = await make();
      await expect(SigningKeyPair.fromJwk(jwk, alg)).rejects.toThrow();
    });
  }

  it("publishes a canonical public JWK", async () => {
    let full: JWK;
    do {
      full = await privateJwk("ES256");
    } while (base64url.decode(full.x!)[0] !== 0);
    const short = { ...full, x: base64url.encode(base64url.decode(full.x!).subarray(1)) };
    const fromShort = await SigningKeyPair.fromJwk(short, "ES256");
    expect(fromShort.publicJwk().x).toBe(full.x);
    expect(fromShort.keyId).toBe((await SigningKeyPair.fromJwk(full, "ES256")).keyId);

    const rsa = await privateJwk("RS256");
    const padded = { ...rsa, n: base64url.encode(new Uint8Array([0, ...base64url.decode(rsa.n!)])) };
    const fromPadded = await SigningKeyPair.fromJwk(padded, "RS256");
    expect(fromPadded.publicJwk().n).toBe(rsa.n);
    expect(fromPadded.keyId).toBe((await SigningKeyPair.fromJwk(rsa, "RS256")).keyId);
  });
});

function fixedSigner(algorithm: string, signature: Uint8Array): JwsSigner {
  return { algorithm, keyId: "fixed-kid", publicJwk: () => ({}), sign: async () => signature };
}

describe("external JwsSigner", () => {
  const cases: Array<[string, string, Uint8Array]> = [
    ["alg none, empty signature", "none", new Uint8Array()],
    ["alg HS256", "HS256", new Uint8Array(32)],
    ["empty ES256 signature", "ES256", new Uint8Array()],
    ["DER ES256 signature", "ES256", new Uint8Array([0x30, 0x44, 0x02, 0x20, ...new Uint8Array(66)])],
    ["truncated ES384 signature", "ES384", new Uint8Array(64)],
    ["empty RS256 signature", "RS256", new Uint8Array()],
  ];
  for (const [name, alg, signature] of cases) {
    it(`refuses ${name}`, async () => {
      const instance = await SigningKeyPair.generate("ES256");
      await expect(
        new ClientAttestationBuilder(fixedSigner(alg, signature), ISS)
          .clientId("c").confirmationKey(instance).expiresIn(60).build(),
      ).rejects.toThrow();
    });
  }

  it("accepts a raw r||s ES256 signature", async () => {
    const instance = await SigningKeyPair.generate("ES256");
    await expect(
      new ClientAttestationBuilder(fixedSigner("ES256", new Uint8Array(64)), ISS)
        .clientId("c").confirmationKey(instance).expiresIn(60).build(),
    ).resolves.toBeTypeOf("string");
  });

  afterEach(() => vi.unstubAllGlobals());

  it("OpenBao refuses a public key on another curve than the key type", async () => {
    const pem = generateKeyPairSync("ec", { namedCurve: "P-384" }).publicKey.export({ type: "spki", format: "pem" });
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
      data: { type: "ecdsa-p256", latest_version: 1, keys: { "1": { public_key: pem } } },
    }))));
    await expect(OpenBaoTransitSigner.create("https://bao.example.com", "t", "k")).rejects.toThrow();
  });
});

describe("DpopProofBuilder htu", () => {
  // The shared htu rule (vectors/htu.json) needs "scheme://": WHATWG parsing (what fetch uses) would read
  // these as https://as.example.com/t, so the builder refuses them rather than sign a path the URL doesn't
  // show. ca.fetch is unaffected: it signs the URL as fetch parsed it.
  for (const uri of ["https:as.example.com/t", "https:/as.example.com/t"]) {
    it(`refuses ${JSON.stringify(uri)}`, async () => {
      await expect(new DpopProofBuilder(await SigningKeyPair.generate("ES256")).uri(uri).build()).rejects.toThrow();
    });
  }
  const cases: Array<[string, string]> = [
    ["https://as.example.com", "https://as.example.com"],
    ["https://as.example.com/", "https://as.example.com/"],
  ];
  for (const [uri, htu] of cases) {
    it(`takes the path fetch requests from ${JSON.stringify(uri)}`, async () => {
      const proof = await new DpopProofBuilder(await SigningKeyPair.generate("ES256")).uri(uri).build();
      expect(decodeJwt(proof).htu).toBe(htu);
    });
  }
});

describe("DpopProofBuilder jwk", () => {
  for (const alg of ["ES256", "ES384", "ES512", "RS256", "PS256"]) {
    it(`is the ${alg} cnf.jwk without kid`, async () => {
      const instance = await SigningKeyPair.fromJwk({ ...(await privateJwk(alg)), kid: "caller-label", use: "sig" }, alg);
      const attestation = await new ClientAttestationBuilder(await SigningKeyPair.generate("ES256"), ISS)
        .clientId("c").confirmationKey(instance).expiresIn(300).build();
      const { kid, ...cnfWithoutKid } = (decodeJwt(attestation).cnf as { jwk: JWK }).jwk;
      expect(kid).toBe(instance.keyId);
      const header = decodeProtectedHeader(
        await new DpopProofBuilder(instance).method("POST").uri("https://as.example.com/token").build(),
      );
      expect(header).not.toHaveProperty("kid");
      expect(header.jwk).not.toHaveProperty("kid");
      expect(header.jwk).toStrictEqual(cnfWithoutKid);
    });
  }
});

describe("MintRequest.sign", () => {
  for (const typ of [POP_TYP, DPOP_TYP, ATTESTATION_TYP, `application/${POP_TYP}`, "OAuth-Client-Attestation-PoP+JWT"]) {
    it(`refuses the reserved typ ${typ}`, async () => {
      const request = new MintRequest({ instanceKey: await SigningKeyPair.generate("ES256"), evidence: "svid" });
      await expect(request.sign({ aud: "https://as.example.com", jti: "j", iat: 1 }, typ)).rejects.toThrow("reserved");
      await expect(request.instanceProof(typ, "https://as.example.com")).rejects.toThrow("reserved");
    });
  }

  it("signs a profile typ", async () => {
    const request = new MintRequest({ instanceKey: await SigningKeyPair.generate("ES256"), evidence: "svid" });
    await expect(request.sign({ aud: "a" }, "oauth-attestation-instance-proof+jwt")).resolves.toBeTypeOf("string");
  });
});
