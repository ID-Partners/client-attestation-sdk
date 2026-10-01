/**
 * The `operator` and `challengeAtToken` options of the one-call flow, asserted on the wire against a
 * fake attester + token endpoint; plus the DRAFT_REVISION constant and canonical operator JSON.
 */
import { createServer, type Server } from "node:http";
import { type AddressInfo } from "node:net";

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { decodeJwt } from "jose";

import { ClientAttestation, DRAFT_REVISION, StaticSvidSource } from "../src/index.js";
import { canonicalJson } from "../src/token-source.js";

interface Seen {
  mintBody?: Record<string, unknown>;
  tokenForm?: URLSearchParams;
  tokenHeaders?: Record<string, string | string[] | undefined>;
}

let server: Server;
let baseUrl: string;
let seen: Seen;

beforeEach(async () => {
  seen = {};
  server = createServer((req, res) => {
    const base = `http://${req.headers.host}`;
    const json = (code: number, obj: unknown) => {
      res.writeHead(code, { "Content-Type": "application/json" });
      res.end(JSON.stringify(obj));
    };
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      switch (req.url) {
        case "/.well-known/client-attester":
          return json(200, {
            attestation_endpoint: base + "/attestation",
            challenge_endpoint: base + "/challenge",
            token_endpoint: base + "/token",
            evidence_audience: "https://attester.example.com",
          });
        case "/challenge":
          return json(200, { attestation_challenge: "chal-abc" });
        case "/attestation": {
          seen.mintBody = JSON.parse(raw) as Record<string, unknown>;
          const payload = Buffer.from(JSON.stringify({ sub: "demo-client" })).toString("base64url");
          return json(200, { attestation: `h.${payload}.sig` });
        }
        case "/token":
          seen.tokenForm = new URLSearchParams(raw);
          seen.tokenHeaders = { ...req.headers };
          return json(200, { access_token: "AT", expires_in: 3600, token_type: "Bearer" });
        default:
          return json(404, { error: "not_found" });
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

const evidence = new StaticSvidSource("fake-svid");

function mintProofChallenge(): unknown {
  return decodeJwt(seen.mintBody!.proof as string).challenge;
}

describe("DRAFT_REVISION", () => {
  it("names draft revision 10", () => {
    expect(DRAFT_REVISION).toBe("10");
  });
});

describe("operator", () => {
  it("is sent in the mint body and as a sorted compact-JSON token form parameter", async () => {
    const operator = { sub: "ops@example.com", iss: "https://idp.example.com", ext: { z: 1, a: [{ y: 2, b: 3 }] } };
    const ca = new ClientAttestation(baseUrl, { evidence, operator });
    expect(await ca.token()).toBe("AT");

    expect(seen.mintBody!.operator).toEqual(operator);
    expect(seen.tokenForm!.get("grant_type")).toBe("client_credentials");
    expect(seen.tokenForm!.get("operator")).toBe(
      '{"ext":{"a":[{"b":3,"y":2}],"z":1},"iss":"https://idp.example.com","sub":"ops@example.com"}',
    );
  });

  it.each([undefined, {}])("sends nothing when unset or empty (%j)", async (operator) => {
    const ca = new ClientAttestation(baseUrl, { evidence, operator });
    await ca.token();
    expect(seen.mintBody).not.toHaveProperty("operator");
    expect(seen.tokenForm!.has("operator")).toBe(false);
    expect([...seen.tokenForm!.keys()]).toEqual(["grant_type"]);
  });

  it("canonicalJson matches Python json.dumps(sort_keys=True, separators=(',', ':'))", () => {
    expect(canonicalJson({ b: "é", a: null, c: [true, 1.5, "x"] })).toBe('{"a":null,"b":"\\u00e9","c":[true,1.5,"x"]}');
  });
});

describe("challengeAtToken", () => {
  it("defaults to true: the challenge protects the mint proof and the token-endpoint PoP", async () => {
    await new ClientAttestation(baseUrl, { evidence }).token();
    expect(mintProofChallenge()).toBe("chal-abc");
    const pop = decodeJwt(seen.tokenHeaders!["oauth-client-attestation-pop"] as string);
    expect(pop.challenge).toBe("chal-abc");
  });

  it("false: the PoP JWT carries no challenge, the mint proof still does", async () => {
    await new ClientAttestation(baseUrl, { evidence, challengeAtToken: false }).token();
    expect(mintProofChallenge()).toBe("chal-abc");
    const pop = decodeJwt(seen.tokenHeaders!["oauth-client-attestation-pop"] as string);
    expect(pop).not.toHaveProperty("challenge");
  });

  it("false in dpop_combined mode: the DPoP proof carries no nonce, the mint proof still has the challenge", async () => {
    await new ClientAttestation(baseUrl, { evidence, popMethod: "dpop_combined", challengeAtToken: false }).token();
    expect(mintProofChallenge()).toBe("chal-abc");
    const dpop = decodeJwt(seen.tokenHeaders!["dpop"] as string);
    expect(dpop).not.toHaveProperty("nonce");
    expect(dpop.htm).toBe("POST");
  });

  it("true in dpop_combined mode: the challenge rides as the DPoP nonce", async () => {
    await new ClientAttestation(baseUrl, { evidence, popMethod: "dpop_combined" }).token();
    expect(decodeJwt(seen.tokenHeaders!["dpop"] as string).nonce).toBe("chal-abc");
  });
});
