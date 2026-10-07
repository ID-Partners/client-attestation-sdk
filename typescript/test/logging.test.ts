/**
 * Logging: the events docs/logging.md promises, and that no credential ever reaches a logger. Every flow
 * here runs with a recording logger at its most verbose (it captures every level), against local fakes
 * whose attestations, access tokens and SVIDs are all JWT-shaped (`eyJ...`), so a leak would show up.
 */
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { type AddressInfo } from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import { ClientAttestation, StaticSvidSource, TransportError, type Logger } from "../src/index.js";
import { emit, failureReason, urlParts } from "../src/logging.js";
import { AccessTokenValidator } from "../src/validator/index.js";

type Entry = { level: string; event: string; attrs: Record<string, unknown> };

function recorder(): { logger: Logger; entries: Entry[]; events: () => string[] } {
  const entries: Entry[] = [];
  const at = (level: string) => (event: string, attrs: Record<string, unknown> = {}) => {
    entries.push({ level, event, attrs });
  };
  return {
    logger: { debug: at("debug"), info: at("info"), warn: at("warn"), error: at("error") },
    entries,
    events: () => entries.map((e) => e.event),
  };
}

const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
const jwtish = (claims: Record<string, unknown>) => `${b64({ alg: "ES256", typ: "jwt" })}.${b64(claims)}.c2lnbmF0dXJl`;

const SVID = jwtish({ sub: "spiffe://example.org/workload", aud: "https://attester.example" });
const CHALLENGE = "challenge-value-never-logged";

/** No secret, no key material: no `eyJ`, no private JWK member, no challenge, no SVID. */
function assertNothingSecret(entries: Entry[]): void {
  const dump = JSON.stringify(entries);
  expect(dump).not.toContain("eyJ");
  expect(dump).not.toMatch(/"(d|p|q|dp|dq|qi|k)":/);
  expect(dump).not.toContain(CHALLENGE);
  expect(dump).not.toContain("AT-");
  expect(dump).not.toContain("?");
}

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => s.close(() => r()))));
});

async function listen(handler: (req: IncomingMessage, res: ServerResponse, body: string) => void): Promise<string> {
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => handler(req, res, Buffer.concat(chunks).toString("utf8")));
  });
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

function json(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { "Content-Type": "application/json", ...headers });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
}

interface FakeOptions {
  tokenType?: string;
  /** Demand this DPoP nonce at the token endpoint (400 use_dpop_nonce until a proof carries it). */
  asNonce?: string;
  expiresIn?: number | null;
  challenge?: (res: ServerResponse) => void;
  token?: (res: ServerResponse) => void;
  discovery?: (res: ServerResponse) => void;
}

/** Attester + AS whose attestation and access token are JWT-shaped. */
async function fakeAttester(opts: FakeOptions = {}): Promise<string> {
  let minted = 0;
  return listen((req, res, body) => {
    const base = `http://${req.headers.host}`;
    if (req.url === "/.well-known/client-attester") {
      if (opts.discovery) return opts.discovery(res);
      return json(res, 200, {
        attestation_endpoint: base + "/attest",
        challenge_endpoint: base + "/challenge?x=1",
        token_endpoint: base + "/token",
        evidence_audience: "https://attester.example",
      });
    }
    if (req.url?.startsWith("/challenge")) {
      if (opts.challenge) return opts.challenge(res);
      return json(res, 200, { attestation_challenge: CHALLENGE });
    }
    if (req.url === "/attest") {
      const instanceKey = JSON.parse(body).instance_key;
      return json(res, 200, { attestation: jwtish({ sub: "demo-client", cnf: { jwk: instanceKey } }) });
    }
    if (req.url === "/token") {
      if (opts.token) return opts.token(res);
      const dpop = req.headers["dpop"] as string | undefined;
      if (opts.asNonce && dpop) {
        const claims = JSON.parse(Buffer.from(dpop.split(".")[1], "base64url").toString("utf8"));
        if (claims.nonce !== opts.asNonce) return json(res, 400, { error: "use_dpop_nonce" }, { "DPoP-Nonce": opts.asNonce });
      }
      minted += 1;
      const response: Record<string, unknown> = {
        access_token: jwtish({ sub: "demo-client", n: minted }),
        token_type: opts.tokenType ?? "Bearer",
      };
      if (opts.expiresIn !== null) response.expires_in = opts.expiresIn ?? 3600;
      return json(res, 200, response);
    }
    json(res, 404, { error: "not_found" });
  });
}

/** A resource that demands a DPoP nonce once (RFC 9449 section 9), then answers 200. */
async function nonceResource(): Promise<string> {
  return listen((req, res) => {
    const dpop = req.headers["dpop"] as string;
    const claims = JSON.parse(Buffer.from(dpop.split(".")[1], "base64url").toString("utf8"));
    if (claims.nonce !== "rs-nonce") {
      res.writeHead(401, { "WWW-Authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": "rs-nonce" });
      return res.end();
    }
    json(res, 200, { ok: true });
  });
}

describe("token source logging", () => {
  it("logs the happy path (attestation PoP), the cache hit and a forced refresh, and nothing secret", async () => {
    const url = await fakeAttester();
    const rec = recorder();
    const ca = new ClientAttestation(url, { evidence: new StaticSvidSource(SVID), logger: rec.logger });

    await ca.token();
    expect(rec.events()).toEqual([
      "token.refreshing",
      "discovery.fetched",
      "evidence.obtained",
      "challenge.fetched",
      "attestation.minted",
      "token.obtained",
    ]);
    const host = new URL(url).host;
    expect(rec.entries[0].attrs).toEqual({ reason: "initial" });
    expect(rec.entries[2].attrs).toEqual({ source: "StaticSvidSource" });
    expect(rec.entries[4].attrs).toEqual({ host, client_id: "demo-client", alg: "ES256" });
    expect(rec.entries[5]).toEqual({
      level: "info",
      event: "token.obtained",
      attrs: { host, client_id: "demo-client", token_type: "Bearer", expires_in: 3600, pop_method: "attestation_pop_jwt" },
    });

    await ca.token();
    expect(rec.entries.at(-1)?.event).toBe("token.cache_hit");
    expect(rec.entries.at(-1)?.attrs.expires_in).toBeGreaterThan(3500);

    await ca.token({ forceRefresh: true });
    expect(rec.entries.find((e) => e.event === "token.refreshing" && e.attrs.reason === "forced")).toBeDefined();
    expect(rec.events()).toContain("discovery.cached");
    expect(rec.entries.every((e) => e.level !== "warn" && e.level !== "error")).toBe(true);
    assertNothingSecret(rec.entries);
  });

  it("logs DPoP nonce retries at the token endpoint and at a resource, and nothing secret", async () => {
    const url = await fakeAttester({ tokenType: "DPoP", asNonce: "as-nonce" });
    const resource = await nonceResource();
    const rec = recorder();
    const ca = new ClientAttestation(url, {
      evidence: new StaticSvidSource(SVID),
      popMethod: "dpop_combined",
      logger: rec.logger,
    });

    const res = await ca.fetch(resource + "/things?secret=1");
    expect(res.status).toBe(200);
    const retries = rec.entries.filter((e) => e.event === "dpop.nonce_retry");
    expect(retries.map((e) => e.attrs)).toEqual([
      { host: new URL(url).host, status: 400, at: "token_endpoint" },
      { host: new URL(resource).host, status: 401, at: "resource" },
    ]);
    expect(rec.events()).not.toContain("http.failed");
    expect(rec.entries.find((e) => e.event === "token.obtained")?.attrs).toMatchObject({
      token_type: "DPoP",
      pop_method: "dpop_combined",
    });
    assertNothingSecret(rec.entries);
  });

  it("gives the reason expired when the cached token has run out", async () => {
    const url = await fakeAttester({ expiresIn: null });
    const rec = recorder();
    const ca = new ClientAttestation(url, { evidence: new StaticSvidSource(SVID), logger: rec.logger });
    await ca.token();
    await ca.token();
    const reasons = rec.entries.filter((e) => e.event === "token.refreshing").map((e) => e.attrs.reason);
    expect(reasons).toEqual(["initial", "expired"]);
    expect(rec.entries.find((e) => e.event === "token.obtained")?.attrs.expires_in).toBeUndefined();
  });

  it("logs a non-2xx token endpoint as http.failed with the status", async () => {
    const url = await fakeAttester({ token: (res) => json(res, 401, { error: "invalid_client" }) });
    const rec = recorder();
    const ca = new ClientAttestation(url, { evidence: new StaticSvidSource(SVID), logger: rec.logger });
    await expect(ca.token()).rejects.toThrow();
    expect(rec.entries.at(-1)).toEqual({
      level: "warn",
      event: "http.failed",
      attrs: { step: "token", method: "POST", host: new URL(url).host, path: "/token", status: 401, reason: "status" },
    });
  });

  it("logs a token response without an access_token as malformed", async () => {
    const url = await fakeAttester({ token: (res) => json(res, 200, { token_type: "Bearer" }) });
    const rec = recorder();
    const ca = new ClientAttestation(url, { evidence: new StaticSvidSource(SVID), logger: rec.logger });
    await expect(ca.token()).rejects.toThrow();
    expect(rec.entries.at(-1)?.attrs).toMatchObject({ step: "token", status: 200, reason: "malformed" });
  });

  it("logs a token response that is not JSON as malformed", async () => {
    const url = await fakeAttester({ token: (res) => json(res, 200, "not json") });
    const rec = recorder();
    const ca = new ClientAttestation(url, { evidence: new StaticSvidSource(SVID), logger: rec.logger });
    await expect(ca.token()).rejects.toThrow();
    expect(rec.entries.at(-1)?.attrs).toMatchObject({ step: "token", reason: "malformed" });
  });

  it("logs malformed discovery JSON and an unreachable host", async () => {
    const url = await fakeAttester({ discovery: (res) => json(res, 200, "{nope") });
    const rec = recorder();
    const ca = new ClientAttestation(url, { evidence: new StaticSvidSource(SVID), logger: rec.logger });
    await expect(ca.token()).rejects.toThrow();
    expect(rec.entries.at(-1)?.attrs).toMatchObject({ step: "discover", method: "GET", reason: "malformed", status: 200 });

    const dead = await listen(() => undefined);
    await new Promise<void>((r) => servers.pop()?.close(() => r()));
    const rec2 = recorder();
    const gone = new ClientAttestation(dead, { evidence: new StaticSvidSource(SVID), logger: rec2.logger });
    await expect(gone.token()).rejects.toThrow();
    expect(rec2.entries.at(-1)?.attrs).toEqual({
      step: "discover",
      method: "GET",
      host: new URL(dead).host,
      path: "/.well-known/client-attester",
      reason: "network",
    });
  });

  it("logs challenge.skipped when the challenge fails and requireChallenge is off", async () => {
    const failing = await fakeAttester({ challenge: (res) => json(res, 503, { error: "down" }) });
    const rec = recorder();
    await new ClientAttestation(failing, {
      evidence: new StaticSvidSource(SVID),
      requireChallenge: false,
      logger: rec.logger,
    }).token();
    const failed = rec.entries.find((e) => e.event === "http.failed");
    expect(failed?.attrs).toMatchObject({ step: "challenge", method: "POST", path: "/challenge", status: 503, reason: "status" });
    expect(rec.entries.find((e) => e.event === "challenge.skipped")?.level).toBe("warn");

    const empty = await fakeAttester({ challenge: (res) => json(res, 200, {}) });
    const rec2 = recorder();
    await new ClientAttestation(empty, {
      evidence: new StaticSvidSource(SVID),
      requireChallenge: false,
      logger: rec2.logger,
    }).token();
    expect(rec2.events()).toContain("challenge.skipped");
    expect(rec2.events()).toContain("token.obtained");
    assertNothingSecret([...rec.entries, ...rec2.entries]);
  });

  it("is silent without a logger and survives a logger that throws", async () => {
    const url = await fakeAttester();
    expect(await new ClientAttestation(url, { evidence: new StaticSvidSource(SVID) }).token()).toMatch(/^eyJ/);
    const boom = () => {
      throw new Error("logger broke");
    };
    const ca = new ClientAttestation(url, {
      evidence: new StaticSvidSource(SVID),
      logger: { debug: boom, info: boom, warn: boom, error: boom },
    });
    expect(await ca.token()).toMatch(/^eyJ/);
  });
});

const VALIDATION = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "validation");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const vectors: any = JSON.parse(readFileSync(join(VALIDATION, "tokens.json"), "utf8"));
const tokenNamed = (name: string): string => vectors.cases.find((c: { name: string }) => c.name === name).token;

function validatorWith(logger: Logger, opts: { httpGet?: (url: string) => Promise<string> } = {}, extra = {}) {
  return new AccessTokenValidator(
    {
      issuer: vectors.issuer,
      audiences: [vectors.audience],
      jwksUri: "https://as.example.com/jwks?tenant=1",
      requiredScopes: vectors.required_scopes,
      acceptedAlgorithms: vectors.accepted_algorithms,
      introspection: { endpoint: "https://as.example.com/introspect?x=1", clientId: "rs", clientSecret: "s3cr3t-value" },
      ...extra,
    },
    { httpGet: opts.httpGet ?? (async () => JSON.stringify(vectors.jwks)), logger, ...opts },
  );
}

describe("validator logging", () => {
  it("logs verdicts, the JWKS fetch and a throttled refetch, and nothing secret", async () => {
    const rec = recorder();
    const validator = validatorWith(rec.logger);
    // only the cases that run under the shared config and the real clock
    const shared = vectors.cases.filter((c: { config?: unknown; now?: unknown }) => !c.config && c.now === undefined);
    for (const c of shared) await validator.validate(c.token);
    const alg = JSON.parse(Buffer.from(tokenNamed("valid").split(".")[0], "base64url").toString("utf8")).alg;
    await validator.validate(`${b64({ alg, kid: "unknown-kid" })}.${b64({})}.c2ln`);

    expect(rec.entries[0]).toEqual({
      level: "debug",
      event: "jwks.fetched",
      attrs: { host: "as.example.com", keys: Object.keys(vectors.jwks.keys).length },
    });
    const verdicts = rec.entries.filter((e) => e.event === "token.validated");
    expect(verdicts.map((e) => e.attrs.result)).toEqual([
      ...shared.map((c: { expect: string }) => c.expect),
      "key_not_found",
    ]);
    expect(verdicts.every((e) => e.attrs.mode === "jwt")).toBe(true);
    expect(verdicts.find((e) => e.attrs.result === "valid")?.level).toBe("debug");
    expect(verdicts.find((e) => e.attrs.result !== "valid")?.level).toBe("info");
    expect(rec.events()).toContain("jwks.refetch_throttled");
    expect(rec.entries.find((e) => e.event === "jwks.refetch_throttled")?.attrs).toEqual({ host: "as.example.com" });
    assertNothingSecret(rec.entries);
    expect(JSON.stringify(rec.entries)).not.toContain(vectors.issuer + "?");
  });

  it("logs a failed JWKS fetch with its reason and status", async () => {
    const rec = recorder();
    const failing = validatorWith(rec.logger, {
      httpGet: async () => {
        throw new TransportError("GET failed", "status", { status: 503 });
      },
    });
    await failing.validate(tokenNamed("valid"));
    expect(rec.entries[0]).toEqual({
      level: "warn",
      event: "jwks.fetch_failed",
      attrs: { host: "as.example.com", reason: "status", status: 503 },
    });

    const rec2 = recorder();
    await validatorWith(rec2.logger, { httpGet: async () => "{not json" }).validate(tokenNamed("valid"));
    expect(rec2.entries[0].attrs).toEqual({ host: "as.example.com", reason: "malformed" });

    const rec3 = recorder();
    await validatorWith(rec3.logger, { httpGet: async () => " ".repeat(512 * 1024 + 1) }).validate(tokenNamed("valid"));
    expect(rec3.entries[0].attrs).toEqual({ host: "as.example.com", reason: "too_large" });
  });

  it("logs introspection verdicts and a failed introspection call, and nothing secret", async () => {
    const rec = recorder();
    const active = new AccessTokenValidator(
      {
        issuer: vectors.issuer,
        audiences: [vectors.audience],
        jwks: vectors.jwks,
        introspection: { endpoint: "https://as.example.com/introspect?x=1", clientId: "rs", clientSecret: "s3cr3t-value" },
      },
      { httpPost: async () => ({ active: true, scope: "read", aud: vectors.audience }), logger: rec.logger },
    );
    await active.validateActive(tokenNamed("valid"));
    expect(rec.entries).toEqual([{ level: "debug", event: "token.validated", attrs: { result: "valid", mode: "introspection" } }]);

    const rec2 = recorder();
    const inactive = new AccessTokenValidator(
      { issuer: vectors.issuer, audiences: [vectors.audience], jwks: vectors.jwks, introspection: { endpoint: "https://as.example.com/introspect", clientId: "rs", clientSecret: "s3cr3t-value" } },
      { httpPost: async () => ({ active: false }), logger: rec2.logger },
    );
    await inactive.validateActive(tokenNamed("valid"));
    expect(rec2.entries[0]).toMatchObject({ level: "info", attrs: { result: "inactive", mode: "introspection" } });

    const rec3 = recorder();
    const broken = new AccessTokenValidator(
      { issuer: vectors.issuer, audiences: [vectors.audience], jwks: vectors.jwks, introspection: { endpoint: "https://as.example.com/introspect?x=1", clientId: "rs", clientSecret: "s3cr3t-value" } },
      {
        httpPost: async () => {
          throw new TransportError("introspection failed: 500", "status", { status: 500 });
        },
        logger: rec3.logger,
      },
    );
    await expect(broken.validateActive(tokenNamed("valid"))).rejects.toThrow();
    expect(rec3.entries).toEqual([
      {
        level: "warn",
        event: "http.failed",
        attrs: { step: "introspection", method: "POST", host: "as.example.com", path: "/introspect", status: 500, reason: "status" },
      },
    ]);
    const all = [...rec.entries, ...rec2.entries, ...rec3.entries];
    assertNothingSecret(all);
    expect(JSON.stringify(all)).not.toContain("s3cr3t");
  });
});

describe("logging helpers", () => {
  it("redacts any attribute containing eyJ and drops empty ones", () => {
    const rec = recorder();
    emit(rec.logger, "error", "x", { a: "eyJhbGciOi.e30.sig", b: undefined, c: null, d: "pf.example.com", n: 3 });
    expect(rec.entries[0]).toEqual({ level: "error", event: "x", attrs: { a: "<redacted:18 bytes>", d: "pf.example.com", n: 3 } });
  });

  it("splits URLs without their query and classifies failures", () => {
    expect(urlParts("https://h.example:8443/p/q?token=1#f")).toEqual({ host: "h.example:8443", path: "/p/q" });
    expect(urlParts("not a url")).toEqual({});
    expect(failureReason(new TransportError("t", "timeout"))).toBe("timeout");
    expect(failureReason(new TransportError("j", "json"))).toBe("malformed");
    expect(failureReason(new SyntaxError("s"))).toBe("malformed");
    expect(failureReason(new Error("e"))).toBe("network");
  });
});
