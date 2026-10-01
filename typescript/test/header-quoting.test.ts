/**
 * WWW-Authenticate quoting and no token data in error_description.
 */
import { SignJWT, type JSONWebKeySet } from "jose";
import { beforeAll, describe, expect, it } from "vitest";

import { SigningKeyPair } from "../src/index.js";
import { AccessTokenValidator, ProtectedResource, errors } from "../src/validator/index.js";
import { quote } from "../src/validator/resource.js";

const ISSUER = "https://issuer.example.com";
const AUDIENCE = "https://api.example.com";

let pair: SigningKeyPair;
let jwks: JSONWebKeySet;

beforeAll(async () => {
  pair = await SigningKeyPair.generate("ES256");
  jwks = { keys: [pair.publicJwk()] };
});

function resource(acceptedAlgorithms?: string[]): ProtectedResource {
  const validator = new AccessTokenValidator({ issuer: ISSUER, audiences: [AUDIENCE], jwks, acceptedAlgorithms });
  return new ProtectedResource(AUDIENCE, [ISSUER], validator);
}

const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
const HOSTILE = 'x"\r\nSet-Cookie: a=b\u0000\u007f\\';

describe("WWW-Authenticate quoting", () => {
  it("strips control characters and escapes backslash and quote", () => {
    expect(quote(HOSTILE)).toBe('x\\"Set-Cookie: a=b\\\\');
    expect(quote("tab\there")).toBe("tabhere");
  });

  it("never lets a value break out of the header", () => {
    const header = resource().challenge("invalid_token\r\nX: y", HOSTILE);
    expect(header).not.toMatch(/[\x00-\x1f\x7f]/);
    expect(header).toContain('error="invalid_tokenX: y"');
    expect(header).toContain('error_description="x\\"Set-Cookie: a=b\\\\"');
  });
});

describe("no token data in error_description", () => {
  it("does not echo an unaccepted alg", async () => {
    const token = `${b64({ alg: HOSTILE, kid: "evil-kid" })}.${b64({})}.AAAA`;
    const decision = await resource().authenticate(`Bearer ${token}`);
    expect(decision.result?.error).toBe(errors.UNSUPPORTED_ALGORITHM);
    expect(decision.errorDescription).toBe("algorithm not accepted");
    expect(decision.wwwAuthenticate).not.toContain("Set-Cookie");
  });

  it("does not echo kid, alg, iss or aud on any other failure", async () => {
    const markers = ["evil-kid-marker", "evil-iss-marker", "evil-aud-marker"];
    const sign = (claims: Record<string, unknown>, kid: string) =>
      new SignJWT(claims).setProtectedHeader({ alg: "ES256", kid }).sign(pair.privateKey);
    const exp = Math.floor(Date.now() / 1000) + 300;
    const cases = [
      await sign({ iss: ISSUER, aud: AUDIENCE, exp }, markers[0]), // unknown kid
      await sign({ iss: markers[1], aud: AUDIENCE, exp }, pair.keyId), // wrong issuer
      await sign({ iss: ISSUER, aud: markers[2], exp }, pair.keyId), // wrong audience
    ];
    const rejectedAlg = resource(["RS256"]);
    for (const token of cases) {
      for (const pr of [resource(), rejectedAlg]) {
        const decision = await pr.authenticate(`Bearer ${token}`);
        expect(decision.authorized).toBe(false);
        for (const m of [...markers, "ES256"]) {
          expect(decision.errorDescription ?? "").not.toContain(m);
          expect(decision.wwwAuthenticate ?? "").not.toContain(m);
        }
      }
    }
  });
});
