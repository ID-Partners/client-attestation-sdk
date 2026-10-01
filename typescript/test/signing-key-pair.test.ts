import { describe, expect, it } from "vitest";
import { exportJWK, importJWK, jwtVerify, type JWK } from "jose";

import { SigningKeyPair } from "../src/index.js";
import { requireText, signCompact, thumbprint } from "../src/signing-key-pair.js";

describe("SigningKeyPair", () => {
  it("rejects unsupported algorithms in generate", async () => {
    await expect(SigningKeyPair.generate("HS256")).rejects.toThrow(
      "unsupported signing algorithm: HS256",
    );
  });

  it.each(["ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"])(
    "generates %s keys that sign verifiably and round-trip through fromJwk",
    async (alg) => {
      const key = await SigningKeyPair.generate(alg);
      expect(key.algorithm).toBe(alg);
      const pub = key.publicJwk();
      expect(pub.kty).toBe(alg.startsWith("ES") ? "EC" : "RSA");
      expect(pub.d).toBeUndefined();
      if (pub.kty === "RSA") {
        expect(Buffer.from(pub.n as string, "base64url").length * 8).toBe(2048);
      } else {
        expect(pub.crv).toBe({ ES256: "P-256", ES384: "P-384", ES512: "P-521" }[alg]);
      }
      expect(await thumbprint(pub)).toBe(key.keyId);

      const jws = await signCompact({ ping: "pong" }, key, "test+jwt", false);
      const { payload, protectedHeader } = await jwtVerify(jws, await importJWK(pub, alg));
      expect(payload.ping).toBe("pong");
      expect(protectedHeader.alg).toBe(alg);

      const restored = await SigningKeyPair.fromJwk((await exportJWK(key.privateKey)) as JWK, alg);
      expect(restored.keyId).toBe(key.keyId);
      expect(restored.publicJwk()).toEqual(pub);
    },
  );

  it("fromJwk restores the same key (matching kid) and signs verifiably", async () => {
    const original = await SigningKeyPair.generate("ES256");
    const privateJwk = (await exportJWK(original.privateKey)) as JWK;
    const restored = await SigningKeyPair.fromJwk(privateJwk, "ES256");

    expect(restored.algorithm).toBe("ES256");
    expect(restored.keyId).toBe(original.keyId);
    const publicJwk = restored.publicJwk();
    expect(publicJwk.d).toBeUndefined();
    expect(publicJwk.kid).toBe(original.keyId);

    const jws = await signCompact({ ping: "pong" }, restored, "test+jwt", false);
    const { payload } = await jwtVerify(jws, await importJWK(original.publicJwk(), "ES256"));
    expect(payload.ping).toBe("pong");
  });

  it("fromJwk rejects a JWK without the private component", async () => {
    const original = await SigningKeyPair.generate("ES256");
    await expect(SigningKeyPair.fromJwk(original.publicJwk(), "ES256")).rejects.toThrow(
      "JWK does not contain a private key",
    );
  });

  it("fromJwk rejects unsupported algorithms", async () => {
    const original = await SigningKeyPair.generate("ES256");
    const privateJwk = (await exportJWK(original.privateKey)) as JWK;
    await expect(SigningKeyPair.fromJwk(privateJwk, "EdDSA")).rejects.toThrow(
      "unsupported signing algorithm: EdDSA",
    );
  });

  it("thumbprint matches the key's RFC 7638 kid", async () => {
    const key = await SigningKeyPair.generate("ES256");
    expect(await thumbprint(key.publicJwk())).toBe(key.keyId);
  });
});

describe("requireText", () => {
  it("returns non-blank values unchanged", () => {
    expect(requireText("value", "field")).toBe("value");
  });

  it.each([null, undefined, "", "   "])("rejects %j", (value) => {
    expect(() => requireText(value as string | null | undefined, "field")).toThrow(
      "field is required",
    );
  });
});
