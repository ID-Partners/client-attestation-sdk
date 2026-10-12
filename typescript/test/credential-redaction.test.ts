/**
 * Credentials stay out of errors and default string forms: a 2xx body that can't be used is never kept,
 * quoted or chained (it is where tokens, attestations and SVIDs travel), a non-2xx body is kept up to 512
 * characters, and JSON.stringify / util.inspect show no secret. Local servers on 127.0.0.1 only.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { type AddressInfo } from "node:net";
import { inspect } from "node:util";

import { afterEach, describe, expect, it } from "vitest";

import {
  AttestationIssuanceClient,
  ClientAttestation,
  ClientAttestationError,
  IssuanceError,
  IssuedAttestation,
  MintRequest,
  SigningKeyPair,
  StaticSvidSource,
} from "../src/index.js";

const AUD = "https://attester.example"; // the evidence_audience the fake attester's discovery document names

/** Starts with eyJ like every JWT, and carries a marker that must not show up anywhere. */
const SECRET = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.SECRET-MARKER";
const ATTESTATION = `h.${Buffer.from(JSON.stringify({ sub: "demo" })).toString("base64url")}.s`;

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (s) =>
        new Promise<void>((resolve) => {
          s.closeAllConnections();
          s.close(() => resolve());
        }),
    ),
  );
});

function raw(res: ServerResponse, status: number, body: string): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(body);
}

/** An attester whose mint and token endpoints answer the given raw (status, body). */
async function attester(mint: [number, string], token: [number, string]): Promise<string> {
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const base = `http://${req.headers.host}`;
    req.resume();
    req.on("end", () => {
      if (req.url === "/.well-known/client-attester") {
        return raw(res, 200, JSON.stringify({
          attestation_endpoint: base + "/attest",
          token_endpoint: base + "/token",
          evidence_audience: AUD,
        }));
      }
      if (req.url === "/attest") return raw(res, ...mint);
      if (req.url === "/token") return raw(res, ...token);
      raw(res, 404, "{}");
    });
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

async function failure(p: Promise<unknown>): Promise<ClientAttestationError> {
  const err = await p.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(Error);
  return err as ClientAttestationError;
}

/** Nothing in the chain (message, body or cause) carries the marker, or the start of a JWT. */
function expectNoSecret(err: unknown): void {
  for (let e = err as (Error & { body?: string }) | undefined; e; e = e.cause as typeof e) {
    expect(e.message).not.toContain("SECRET-MARKER");
    expect(e.message).not.toContain("eyJ");
    expect(e.body ?? "").not.toContain("SECRET-MARKER");
    expect(inspect(e)).not.toContain("SECRET-MARKER");
  }
}

const OK_MINT: [number, string] = [200, JSON.stringify({ attestation: ATTESTATION })];

describe("an unusable 2xx response keeps no body", () => {
  it.each([
    ["trailing data", `{"access_token":"${SECRET}","token_type":"Bearer"} trailing`],
    ["form encoded", `access_token=${SECRET}&token_type=Bearer`],
    ["a bare token", SECRET], // V8's own SyntaxError message quotes the start of this
    ["no access_token", `{"accessToken":"${SECRET}","token_type":"Bearer"}`],
  ])("from the token endpoint: %s", async (_name, body) => {
    const url = await attester(OK_MINT, [200, body]);
    const err = await failure(new ClientAttestation(url, { evidence: new StaticSvidSource("svid"), evidenceAudience: AUD }).token());
    expect(err.body).toBeUndefined();
    expectNoSecret(err);
  });

  it.each([
    ["trailing data", `{"attestation":"${SECRET}"} trailing`],
    ["wrong member", `{"client_attestation":"${SECRET}"}`],
  ])("from the mint: %s", async (_name, body) => {
    const url = await attester([200, body], [200, `{"access_token":"AT"}`]);
    const err = await failure(new ClientAttestation(url, { evidence: new StaticSvidSource("svid"), evidenceAudience: AUD }).token());
    expect(err.body).toBeUndefined();
    expectNoSecret(err);
  });
});

describe("a non-2xx body is capped at 512 characters", () => {
  const long = JSON.stringify({ error: "invalid_client", error_description: "d".repeat(2000) });

  it("from the token endpoint", async () => {
    const url = await attester(OK_MINT, [401, long]);
    const err = await failure(new ClientAttestation(url, { evidence: new StaticSvidSource("svid"), evidenceAudience: AUD }).token());
    expect(err.status).toBe(401);
    expect(err.body).toBe(long.slice(0, 512));
  });

  it("from the issuance endpoint", async () => {
    const url = await attester([403, long], [200, "{}"]);
    const client = await AttestationIssuanceClient.create(url + "/attest", "c", "aud", new StaticSvidSource("s"));
    const err = (await failure(client.bootstrap())) as unknown as IssuanceError;
    expect(err).toBeInstanceOf(IssuanceError);
    expect(err.body).toBe(long.slice(0, 512));
    expect(err.message.length).toBeLessThanOrEqual("attestation issuance failed: HTTP 403: ".length + 512);
  });
});

describe("default string forms", () => {
  it("leave the evidence, challenge, attestation and SVID out", async () => {
    const key = await SigningKeyPair.generate("ES256");
    const values = [
      new MintRequest({ instanceKey: key, evidence: SECRET, challenge: "CHALLENGE-SECRET-MARKER", clientId: "c-1" }),
      new IssuedAttestation(SECRET, 60, key),
      new StaticSvidSource(SECRET),
    ];
    for (const value of values) {
      expect(JSON.stringify(value)).not.toContain("SECRET-MARKER");
      expect(inspect(value, { depth: 5 })).not.toContain("SECRET-MARKER");
    }
    const request = values[0] as MintRequest;
    expect(request.evidence).toBe(SECRET); // still readable
    expect(request.challenge).toBe("CHALLENGE-SECRET-MARKER");
    expect(JSON.stringify(request)).toContain('"clientId":"c-1"');
    expect((values[1] as IssuedAttestation).attestation).toBe(SECRET);
    expect(await (values[2] as StaticSvidSource).fetch("aud")).toBe(SECRET);
  });
});
