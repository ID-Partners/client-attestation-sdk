/**
 * Fail-closed behaviour: a required challenge that cannot be fetched, an explicitly configured evidence
 * source that is missing, and non-https endpoints.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { type AddressInfo } from "node:net";

import { decodeJwt } from "jose";
import { afterEach, describe, expect, it } from "vitest";

import {
  ClientAttestation,
  ClientAttestationError,
  ENV_SPIFFE_SOCKET,
  ENV_SVID,
  ENV_TOKEN_FILE,
  EvidenceNotFound,
  StaticSvidSource,
  autoDetectEvidence,
} from "../src/index.js";

const AUD = "https://attester.example"; // the evidence_audience the fake attester's discovery document names

const servers: Server[] = [];
const savedEnv = { ...process.env };

afterEach(async () => {
  process.env = { ...savedEnv };
  await Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => s.close(() => r()))));
});

async function listen(handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<string> {
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => handler(req, res));
  });
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

type Challenge = (res: ServerResponse) => void;

/** A fake attester + AS whose challenge endpoint and advertised endpoints the test controls. */
async function attester(opts: { challenge?: Challenge | null; discovery?: Record<string, string> } = {}) {
  const tokenPops: string[] = [];
  const url = await listen((req, res) => {
    const base = `http://${req.headers.host}`;
    if (req.url === "/.well-known/client-attester") {
      const doc: Record<string, string> = {
        attestation_endpoint: base + "/attest",
        token_endpoint: base + "/token",
        evidence_audience: AUD,
      };
      if (opts.challenge !== null) doc.challenge_endpoint = base + "/challenge";
      return json(res, 200, { ...doc, ...opts.discovery });
    }
    if (req.url === "/challenge") {
      return (opts.challenge ?? ((r) => json(r, 200, { attestation_challenge: "c" })))(res);
    }
    if (req.url === "/attest") {
      return json(res, 200, { attestation: `h.${Buffer.from('{"sub":"demo"}').toString("base64url")}.s` });
    }
    tokenPops.push(req.headers["oauth-client-attestation-pop"] as string);
    json(res, 200, { access_token: "AT", expires_in: 60 });
  });
  return { url, tokenPops };
}

const evidence = new StaticSvidSource("svid");

async function failure(p: Promise<unknown>): Promise<ClientAttestationError> {
  const err = await p.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(ClientAttestationError);
  return err as ClientAttestationError;
}

describe("challenge fails closed", () => {
  const broken: [string, Challenge][] = [
    ["a non-2xx status", (res) => json(res, 503, { error: "down" })],
    ["malformed JSON", (res) => res.end("{")],
    ["no attestation_challenge", (res) => json(res, 200, { expires_in: 30 })],
    ["a destroyed connection", (res) => res.socket?.destroy()],
  ];

  for (const [what, challenge] of broken) {
    it(`fails the flow on ${what}`, async () => {
      const as = await attester({ challenge });
      const err = await failure(new ClientAttestation(as.url, { evidence, evidenceAudience: AUD }).token());
      expect(err.message).toContain("/challenge");
      expect(as.tokenPops).toEqual([]);
    });

    it(`proceeds without a challenge on ${what} when requireChallenge is false`, async () => {
      const as = await attester({ challenge });
      expect(await new ClientAttestation(as.url, { evidence, evidenceAudience: AUD, requireChallenge: false }).token()).toBe("AT");
      expect(decodeJwt(as.tokenPops[0]).challenge).toBeUndefined();
    });
  }

  it("keeps the status of a failed challenge call", async () => {
    const as = await attester({ challenge: (res) => json(res, 503, {}) });
    expect((await failure(new ClientAttestation(as.url, { evidence, evidenceAudience: AUD }).token())).status).toBe(503);
  });

  it("needs no challenge when none is advertised", async () => {
    const as = await attester({ challenge: null });
    expect(await new ClientAttestation(as.url, { evidence, evidenceAudience: AUD }).token()).toBe("AT");
    expect(decodeJwt(as.tokenPops[0]).challenge).toBeUndefined();
  });
});

describe("evidence env vars fail closed", () => {
  it("names CLIENT_ATTESTATION_TOKEN_FILE when it points at a missing file", async () => {
    delete process.env[ENV_SVID];
    process.env[ENV_TOKEN_FILE] = "/nonexistent/attester-token";
    const err = await autoDetectEvidence().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(EvidenceNotFound);
    expect((err as Error).message).toContain(ENV_TOKEN_FILE);
  });

  it("names SPIFFE_ENDPOINT_SOCKET when it points at a missing socket", async () => {
    delete process.env[ENV_SVID];
    delete process.env[ENV_TOKEN_FILE];
    process.env[ENV_SPIFFE_SOCKET] = "unix:///nonexistent/agent.sock";
    const err = await autoDetectEvidence().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(EvidenceNotFound);
    expect((err as Error).message).toContain(ENV_SPIFFE_SOCKET);
  });

  it("uses an existing SPIFFE_ENDPOINT_SOCKET path", async () => {
    delete process.env[ENV_SVID];
    delete process.env[ENV_TOKEN_FILE];
    process.env[ENV_SPIFFE_SOCKET] = `unix://${process.cwd()}`; // any existing path will do
    expect((await autoDetectEvidence()).constructor.name).toBe("SpireWorkloadApiSvidSource");
  });
});

describe("transport security", () => {
  it("refuses a plain-http PingFederate host", () => {
    expect(() => new ClientAttestation("http://pf.example.com", { evidence })).toThrow(ClientAttestationError);
    expect(() => new ClientAttestation("http://pf.example.com")).toThrow("http://pf.example.com");
  });

  it("allows https, loopback, and http with allowInsecure", () => {
    for (const host of ["pf.example.com", "https://pf.example.com", "http://localhost:9031", "http://127.0.0.1", "http://[::1]:8080"]) {
      expect(() => new ClientAttestation(host)).not.toThrow();
    }
    expect(() => new ClientAttestation("http://pf.internal:9031", { allowInsecure: true })).not.toThrow();
  });

  for (const endpoint of ["token_endpoint", "attestation_endpoint", "challenge_endpoint"]) {
    it(`refuses a non-https ${endpoint} from discovery`, async () => {
      const as = await attester({ discovery: { [endpoint]: "http://evil.example/x" } });
      const err = await failure(new ClientAttestation(as.url, { evidence, evidenceAudience: AUD }).token());
      expect(err.message).toContain(endpoint);
      expect(err.message).toContain("http://evil.example/x");
    });
  }

  it("refuses an unparseable endpoint", async () => {
    const as = await attester({ discovery: { token_endpoint: "::not a url" } });
    expect((await failure(new ClientAttestation(as.url, { evidence, evidenceAudience: AUD }).token())).message).toContain("not a valid URL");
  });

  it("lets allowInsecure reach a plain-http endpoint", async () => {
    const as = await attester({ discovery: { token_endpoint: "http://pf.invalid/token" } });
    const err = await failure(new ClientAttestation(as.url, { evidence, evidenceAudience: AUD, allowInsecure: true, timeoutMs: 2000 }).token());
    expect(err.message).not.toContain("must use https");
  });
});
