/**
 * Attester profiles: the default PingFederate profile, static metadata (no discovery), and a custom
 * profile for a made-up attester whose discovery path, proof typ and mint request/response all differ.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { type AddressInfo } from "node:net";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  AttestationIssuanceClient,
  ClientAttestation,
  ClientAttestationError,
  MintRequest,
  PingFederateProfile,
  StaticSvidSource,
  type AttesterMetadata,
  type AttesterProfile,
  type AttesterTransport,
  type MintResult,
} from "../src/index.js";

const b64 = (obj: unknown) => Buffer.from(JSON.stringify(obj)).toString("base64url");
const decode = (jwt: string) => jwt.split(".").slice(0, 2).map((p) => JSON.parse(Buffer.from(p, "base64url").toString()));
const ATTESTATION = `e30.${b64({ sub: "client-1" })}.sig`;

interface Seen {
  method: string;
  path: string;
  body: Record<string, unknown> | null;
}

let server: Server;
let base: string;
let seen: Seen[];

beforeEach(async () => {
  seen = [];
  server = createServer((req: IncomingMessage, res: ServerResponse) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      seen.push({ method: req.method!, path: req.url!, body: raw.startsWith("{") ? JSON.parse(raw) : null });
      const send = (status: number, obj: unknown) => {
        res.writeHead(status, { "Content-Type": "application/json" });
        res.end(JSON.stringify(obj));
      };
      switch (req.url) {
        case "/.well-known/client-attester":
          return send(200, { evidence_audience: base, attestation_endpoint: base + "/pf/mint", token_endpoint: base + "/token" });
        case "/acme/config":
          return send(200, { audience: "acme-aud", mint_url: base + "/acme/mint", token_url: base + "/token" });
        case "/pf/mint":
          return send(200, { attestation: ATTESTATION, expires_in: 600 });
        case "/acme/mint":
          return send(200, { client_attestation: ATTESTATION, ttl: 300 });
        case "/token": {
          const ok = req.headers["oauth-client-attestation"] === ATTESTATION && req.headers["oauth-client-attestation-pop"];
          return ok ? send(200, { access_token: "at-1", expires_in: 60 }) : send(401, { error: "invalid_client" });
        }
        default:
          return send(404, { error: "not_found" });
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

const paths = () => seen.map((s) => s.path);
const bodyOf = (path: string) => seen.find((s) => s.path === path)!.body!;

/** A non-PingFederate attester: its own discovery path and fields, proof typ, and mint shapes. */
class AcmeProfile implements AttesterProfile {
  async discover(transport: AttesterTransport, attesterUrl: string | undefined): Promise<AttesterMetadata> {
    const doc = await transport.requestJson("discover", "GET", attesterUrl + "/acme/config");
    return {
      evidenceAudience: doc.audience as string,
      attestationEndpoint: doc.mint_url as string,
      tokenEndpoint: doc.token_url as string,
      document: doc,
    };
  }

  async mint(transport: AttesterTransport, metadata: AttesterMetadata, request: MintRequest): Promise<MintResult> {
    const pop = await request.instanceProof("acme-key-proof+jwt", "acme");
    const res = await transport.requestJson("mint", "POST", metadata.attestationEndpoint!, {
      evidence: request.evidence,
      key: request.instanceKey.publicJwk(),
      pop,
    });
    return { attestation: res.client_attestation as string, expiresIn: res.ttl as number };
  }
}

const svid = new StaticSvidSource("svid");

describe("attester profiles", () => {
  it("uses the PingFederate profile by default", async () => {
    const ca = new ClientAttestation(base, { evidence: svid });
    expect(await ca.token()).toBe("at-1");
    expect(paths()).toEqual(["/.well-known/client-attester", "/pf/mint", "/token"]);
    const body = bodyOf("/pf/mint");
    expect(Object.keys(body)).toEqual(["instance_key", "svid", "proof"]);
    const [header, claims] = decode(body.proof as string);
    expect(header.typ).toBe(PingFederateProfile.INSTANCE_PROOF_TYP);
    expect(header.typ).toBe("oauth-attestation-instance-proof+jwt");
    expect(claims.aud).toBe(base);
  });

  it("gets a token end to end through a custom profile", async () => {
    const ca = new ClientAttestation(base, { evidence: svid, profile: new AcmeProfile() });
    expect(await ca.token()).toBe("at-1");
    expect(paths()).toEqual(["/acme/config", "/acme/mint", "/token"]);
    const body = bodyOf("/acme/mint");
    expect(body.evidence).toBe("svid");
    const [header, claims] = decode(body.pop as string);
    expect(header.typ).toBe("acme-key-proof+jwt");
    expect(claims.aud).toBe("acme");
    expect(await ca.discovery()).toEqual({ audience: "acme-aud", mint_url: base + "/acme/mint", token_url: base + "/token" });
  });

  it("skips discovery with static metadata and mints with the default protocol", async () => {
    const metadata = { evidenceAudience: "aud-1", attestationEndpoint: base + "/pf/mint", tokenEndpoint: base + "/token" };
    const ca = new ClientAttestation({ metadata, evidence: svid });
    expect(ca.baseUrl).toBe("");
    expect(await ca.token()).toBe("at-1");
    expect(paths()).toEqual(["/pf/mint", "/token"]);
    const [header, claims] = decode(bodyOf("/pf/mint").proof as string);
    expect(header.typ).toBe("oauth-attestation-instance-proof+jwt");
    expect(claims.aud).toBe("aud-1");
    expect(await ca.discovery()).toEqual({
      evidence_audience: "aud-1",
      attestation_endpoint: base + "/pf/mint",
      token_endpoint: base + "/token",
    });
  });

  it("never discovers with static metadata and a custom profile", async () => {
    const metadata = { evidenceAudience: "aud-1", attestationEndpoint: base + "/acme/mint", tokenEndpoint: base + "/token" };
    const ca = new ClientAttestation(base, { metadata, evidence: svid, profile: new AcmeProfile() });
    expect(await ca.token()).toBe("at-1");
    expect(paths()).toEqual(["/acme/mint", "/token"]);
  });

  it("takes the attester URL from the options object", async () => {
    const ca = new ClientAttestation({ attesterUrl: base, evidence: svid });
    expect(ca.baseUrl).toBe(base);
    expect(await ca.token()).toBe("at-1");
  });

  it("needs a token endpoint in static metadata", async () => {
    const ca = new ClientAttestation({ metadata: { evidenceAudience: "a", attestationEndpoint: base + "/pf/mint" }, evidence: svid });
    await expect(ca.token()).rejects.toThrow("no token_endpoint");
  });

  it("still requires https for static endpoints, and labels a custom step", async () => {
    const insecure = { evidenceAudience: "a", attestationEndpoint: "http://attester.example/mint", tokenEndpoint: "https://as.example/t" };
    await expect(new ClientAttestation({ metadata: insecure, evidence: svid }).token()).rejects.toThrow(
      "attestation_endpoint must use https",
    );
    const odd: AttesterProfile = {
      discover: async (t) => {
        await t.requestJson("lookup", "GET", "http://attester.example/x");
        return {};
      },
      mint: async () => ({ attestation: ATTESTATION }),
    };
    await expect(new ClientAttestation("https://attester.example", { profile: odd }).discovery()).rejects.toThrow(
      "lookup URL must use https",
    );
  });

  it("requires an attester URL without metadata or a profile, and for PingFederate discovery", async () => {
    expect(() => new ClientAttestation()).toThrow("attesterUrl is required");
    await expect(new ClientAttestation({ profile: new PingFederateProfile() }).discovery()).rejects.toThrow(
      "attesterUrl is required",
    );
  });

  it("falls back to the standard PingFederate token path and rejects a mint with no attestation", async () => {
    const transport: AttesterTransport = { requestJson: async () => ({ evidence_audience: "aud", expires_in: "x" }) };
    const profile = new PingFederateProfile();
    const meta = await profile.discover(transport, "https://pf.example");
    expect(meta.tokenEndpoint).toBe("https://pf.example/as/token.oauth2");
    await expect(profile.mint(transport, {}, {} as MintRequest)).rejects.toThrow("no attestation_endpoint");
    const key = (await AttestationIssuanceClient.create("https://x", "c", "a", svid)).instanceKey;
    const request = new MintRequest({ instanceKey: key, evidence: "svid" });
    await expect(profile.mint(transport, { attestationEndpoint: "https://x" }, request)).rejects.toBeInstanceOf(
      ClientAttestationError,
    );
  });

  it("lets the issuance client use a custom profile", async () => {
    const client = await AttestationIssuanceClient.create(base + "/acme/mint", "client-1", "https://attester.example", svid, {
      profile: new AcmeProfile(),
    });
    const issued = await client.bootstrap();
    expect(issued.attestation).toBe(ATTESTATION);
    expect(issued.expiresIn).toBe(300);
    expect(decode(bodyOf("/acme/mint").pop as string)[0].typ).toBe("acme-key-proof+jwt");
  });

  it("keeps the issuance client's PingFederate body, client_id first", async () => {
    const client = await AttestationIssuanceClient.create(base + "/pf/mint", "client-1", "https://attester.example", svid);
    const issued = await client.bootstrap([{ type: "x" }], "chal");
    expect(issued.expiresIn).toBe(600);
    const body = bodyOf("/pf/mint");
    expect(Object.keys(body)).toEqual(["client_id", "instance_key", "svid", "proof", "authorization_details"]);
    const [, claims] = decode(body.proof as string);
    expect(claims.aud).toBe("https://attester.example");
    expect(claims.challenge).toBe("chal");
  });
});
