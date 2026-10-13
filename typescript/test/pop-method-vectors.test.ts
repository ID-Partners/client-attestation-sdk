/**
 * The one-call client's PoP method setting against the shared vectors (vectors/pop-method.json). Every port
 * must agree. An accepted value is checked by the header sent at the token endpoint; a refused one fails the
 * constructor before any request or evidence fetch. Local server only.
 */
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { type AddressInfo } from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it, vi } from "vitest";

import { ClientAttestation, type ClientAttestationOptions } from "../src/index.js";

const VECTORS = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "vectors");

interface PopMethodCase {
  name: string;
  pop_method: unknown;
  expect: "attestation_pop_jwt" | "dpop_combined" | "refused";
}

const cases: PopMethodCase[] = JSON.parse(readFileSync(join(VECTORS, "pop-method.json"), "utf8")).cases;

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => s.close(() => r()))));
});

interface Seen {
  path: string;
  dpop: string | undefined;
  pop: string | undefined;
}

/** A mint and a token endpoint that record every request and the token request's proof headers. */
async function attester() {
  const seen: Seen[] = [];
  const srv = createServer((req, res) => {
    req.resume();
    seen.push({
      path: req.url ?? "",
      dpop: req.headers["dpop"] as string | undefined,
      pop: req.headers["oauth-client-attestation-pop"] as string | undefined,
    });
    res.writeHead(200, { "Content-Type": "application/json" });
    if (req.url === "/mint") {
      const sub = Buffer.from(JSON.stringify({ sub: "c-1" })).toString("base64url");
      return res.end(JSON.stringify({ attestation: `h.${sub}.s` }));
    }
    res.end(JSON.stringify({ access_token: "AT", token_type: "Bearer", expires_in: 3600 }));
  });
  servers.push(srv);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  const fetchEvidence = vi.fn(async () => "svid");
  const build = (opts: Record<string, unknown>) =>
    new ClientAttestation({
      evidence: { fetch: fetchEvidence },
      metadata: { evidenceAudience: "aud", attestationEndpoint: url + "/mint", tokenEndpoint: url + "/token" },
      ...opts,
    });
  return { seen, fetchEvidence, build, tokenRequests: () => seen.filter((s) => s.path === "/token") };
}

describe("shared pop-method vectors", () => {
  it.each(cases.map((c) => [c.name, c] as const))("%s", async (_name, c) => {
    const { seen, fetchEvidence, build, tokenRequests } = await attester();
    if (c.expect === "refused") {
      expect(() => build({ popMethod: c.pop_method })).toThrow(RangeError);
      expect(() => build({ popMethod: c.pop_method })).toThrow(/^popMethod must be "attestation_pop_jwt" or "dpop_combined", got /);
      expect(seen).toEqual([]);
      expect(fetchEvidence).not.toHaveBeenCalled();
      return;
    }
    await build({ popMethod: c.pop_method }).token();
    const [request, ...more] = tokenRequests();
    expect(more).toEqual([]);
    if (c.expect === "dpop_combined") {
      expect(request.dpop).toBeTruthy();
      expect(request.pop).toBeUndefined();
    } else {
      expect(request.pop).toBeTruthy();
      expect(request.dpop).toBeUndefined();
    }
  });
});

describe("popMethod", () => {
  it("is the default when left out", async () => {
    const { build, tokenRequests } = await attester();
    await build({}).token();
    expect(tokenRequests().map((r) => r.pop !== undefined)).toEqual([true]);
  });

  it.each([null, ""] as const)("takes a typed %j without a cast", (popMethod) => {
    // Type-checked by tsc: no cast. The vectors show what the client then sends.
    const opts: ClientAttestationOptions = { evidenceAudience: "aud", popMethod };
    expect(() => new ClientAttestation("https://attester.example", opts)).not.toThrow();
  });

  // JSON can't carry these. JSON.stringify throws on a BigInt and a cycle; the refusal is still a RangeError.
  const cycle: Record<string, unknown> = {};
  cycle.self = cycle;
  it.each([
    ["BigInt", 1n],
    ["cyclic object", cycle],
    ["symbol", Symbol("dpop_combined")],
    ["function", () => "dpop_combined"],
    ["String object", new String("dpop_combined")],
    ["object without a prototype", Object.create(null)],
  ])("refuses a %s with a RangeError", async (_name, value) => {
    const { seen, build } = await attester();
    expect(() => build({ popMethod: value })).toThrow(RangeError);
    expect(seen).toEqual([]);
  });
});
