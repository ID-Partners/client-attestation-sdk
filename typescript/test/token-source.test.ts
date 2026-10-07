/**
 * Offline tests for the one-call token source: the full flow against a fake attester + token endpoint,
 * plus URL normalization, the jwt-sub helper, and evidence auto-detection precedence. No live PF needed.
 */
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { createServer as netServer, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { decodeJwt } from "jose";

import {
  ClientAttestation,
  StaticSvidSource,
  autoDetectEvidence,
  ENV_SPIFFE_SOCKET,
  ENV_SVID,
  ENV_TOKEN_FILE,
  EvidenceNotFound,
  FileTokenSvidSource,
  GoogleMetadataSvidSource,
  SpireWorkloadApiSvidSource,
} from "../src/index.js";
import { jwtSub, normalizeBaseUrl } from "../src/token-source.js";

function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

describe("normalizeBaseUrl", () => {
  it("adds https, strips trailing slash, keeps explicit scheme", () => {
    expect(normalizeBaseUrl("pf.example.com")).toBe("https://pf.example.com");
    expect(normalizeBaseUrl("https://pf.example.com/")).toBe("https://pf.example.com");
    expect(normalizeBaseUrl("http://pf.pf:9080")).toBe("http://pf.pf:9080");
    expect(() => normalizeBaseUrl("   ")).toThrow();
  });
});

describe("jwtSub", () => {
  it("reads the client id from the attestation sub claim", () => {
    const token = "h." + b64url({ sub: "demo-client" }) + ".sig";
    expect(jwtSub(token)).toBe("demo-client");
  });
});

// ── evidence auto-detection precedence ──────────────────────────────────────────────────────────

describe("autoDetectEvidence", () => {
  const saved = { ...process.env };
  let dir: string;
  let refusedBase: string;
  // Never the host's real default paths or the real GCP metadata server.
  const isolated = () => ({
    defaultTokenFile: join(dir, "no-default-token"),
    defaultSpiffeSocket: join(dir, "no-default-socket"),
    gcpMetadataBase: refusedBase,
    // the fake metadata server is local, but a loaded CI runner can take longer than the 300 ms default
    gcpProbeTimeoutMs: 5000,
  });

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), "evidence-"));
    delete process.env[ENV_SVID];
    delete process.env[ENV_TOKEN_FILE];
    delete process.env[ENV_SPIFFE_SOCKET];
    // A port that was just bound and released: connecting to it is refused at once.
    const probe = createServer();
    await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
    refusedBase = `http://127.0.0.1:${(probe.address() as AddressInfo).port}`;
    await new Promise<void>((resolve) => probe.close(() => resolve()));
  });
  afterEach(() => {
    process.env = { ...saved };
    rmSync(dir, { recursive: true, force: true });
  });

  it("prefers the explicit env token over everything", async () => {
    const file = join(dir, "t.tok");
    writeFileSync(file, "file-token");
    process.env[ENV_SVID] = " the-token\n";
    process.env[ENV_TOKEN_FILE] = file;
    process.env[ENV_SPIFFE_SOCKET] = file;
    const source = await autoDetectEvidence(isolated());
    expect(source).toBeInstanceOf(StaticSvidSource);
    expect(await source.fetch("aud")).toBe("the-token");
  });

  it("uses the token file named by the env var, ahead of SPIRE", async () => {
    const file = join(dir, "t.tok");
    writeFileSync(file, "file-token\n");
    process.env[ENV_TOKEN_FILE] = file;
    process.env[ENV_SPIFFE_SOCKET] = file;
    const source = await autoDetectEvidence(isolated());
    expect(source).toBeInstanceOf(FileTokenSvidSource);
    expect(await source.fetch("aud")).toBe("file-token");
  });

  it("uses the default projected token file, ahead of SPIRE", async () => {
    const opts = isolated();
    writeFileSync(opts.defaultTokenFile, "default-file-token");
    writeFileSync(opts.defaultSpiffeSocket, "");
    const source = await autoDetectEvidence(opts);
    expect(source).toBeInstanceOf(FileTokenSvidSource);
    expect(await source.fetch("aud")).toBe("default-file-token");
  });

  it("uses the SPIRE socket named by SPIFFE_ENDPOINT_SOCKET (unix:// stripped), ahead of GCP", async () => {
    const sock = join(dir, "agent.sock");
    const fake = netServer();
    await new Promise<void>((resolve) => fake.listen(sock, resolve));
    const gcp = await fakeMetadata();
    try {
      process.env[ENV_SPIFFE_SOCKET] = "unix://" + sock;
      const source = await autoDetectEvidence({ ...isolated(), gcpMetadataBase: gcp.base });
      expect(source).toBeInstanceOf(SpireWorkloadApiSvidSource);
      expect((source as unknown as { socketPath: string }).socketPath).toBe(sock);
      expect(gcp.hits).toBe(0);
    } finally {
      await new Promise<void>((resolve) => fake.close(() => resolve()));
      await gcp.close();
    }
  });

  it("uses the default SPIRE socket when present", async () => {
    const opts = isolated();
    writeFileSync(opts.defaultSpiffeSocket, "");
    const source = await autoDetectEvidence(opts);
    expect(source).toBeInstanceOf(SpireWorkloadApiSvidSource);
    expect((source as unknown as { socketPath: string }).socketPath).toBe(opts.defaultSpiffeSocket);
  });

  it("falls back to the GCP metadata server and fetches the identity token from it", async () => {
    const gcp = await fakeMetadata();
    try {
      const source = await autoDetectEvidence({ ...isolated(), gcpMetadataBase: gcp.base + "/" });
      expect(source).toBeInstanceOf(GoogleMetadataSvidSource);
      expect(await source.fetch("https://attester.example.com")).toBe("gcp-id-token");
      expect(gcp.lastIdentityUrl).toBe(
        "/computeMetadata/v1/instance/service-accounts/default/identity" +
          "?audience=https%3A%2F%2Fattester.example.com&format=full",
      );
      expect(gcp.lastFlavor).toBe("Google");
    } finally {
      await gcp.close();
    }
  });

  it("does not use a metadata server that answers non-200", async () => {
    const gcp = await fakeMetadata(500);
    try {
      await expect(autoDetectEvidence({ ...isolated(), gcpMetadataBase: gcp.base })).rejects.toBeInstanceOf(
        EvidenceNotFound,
      );
    } finally {
      await gcp.close();
    }
  });

  it("throws EvidenceNotFound when nothing applies (metadata probe refused)", async () => {
    await expect(autoDetectEvidence(isolated())).rejects.toBeInstanceOf(EvidenceNotFound);
  });
});

/** A local stand-in for the GCP metadata server. */
async function fakeMetadata(probeStatus = 200) {
  const state = { hits: 0, lastIdentityUrl: "", lastFlavor: "" as string | undefined };
  const server = createServer((req, res) => {
    state.hits++;
    state.lastFlavor = req.headers["metadata-flavor"] as string | undefined;
    if (req.url === "/computeMetadata/v1/") {
      res.writeHead(probeStatus);
      return res.end("ok");
    }
    if (req.url?.startsWith("/computeMetadata/v1/instance/service-accounts/default/identity")) {
      state.lastIdentityUrl = req.url;
      res.writeHead(200);
      return res.end("gcp-id-token\n");
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    base,
    get hits() {
      return state.hits;
    },
    get lastIdentityUrl() {
      return state.lastIdentityUrl;
    },
    get lastFlavor() {
      return state.lastFlavor;
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

// ── full flow against a fake attester that mirrors what the real one does ─────────────────────────

interface Fixture {
  baseUrl: string;
  server: Server;
}

let fixture: Fixture;
let lastTokenRequestHeaders: Record<string, string | string[] | undefined> = {};

beforeEach(async () => {
  lastTokenRequestHeaders = {};
  const server = createServer((req, res) => {
    const base = `http://${req.headers.host}`;
    const json = (code: number, obj: unknown) => {
      const body = JSON.stringify(obj);
      res.writeHead(code, { "Content-Type": "application/json" });
      res.end(body);
    };

    if (req.method === "GET" && req.url === "/.well-known/client-attester") {
      return json(200, {
        attestation_endpoint: base + "/federation/attestation",
        challenge_endpoint: base + "/federation/attestation-challenge",
        token_endpoint: base + "/as/token.oauth2",
        evidence_audience: "https://attester.example.com",
        pop_audience: "https://pf.issuer.example",
      });
    }

    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (req.url?.endsWith("/attestation-challenge")) {
        return json(200, { attestation_challenge: "chal-123", expires_in: 300 });
      }
      if (req.url?.endsWith("/federation/attestation")) {
        const body = JSON.parse(raw);
        expect(body.instance_key).toBeDefined();
        expect(body.svid).toBeDefined();
        expect(body.proof).toBeDefined();
        expect(body.client_id).toBeUndefined(); // evidence-first: the workload sends no client_id
        const attestation = "h." + b64url({ sub: "demo-client" }) + ".sig";
        return json(200, { attestation, expires_in: 300 });
      }
      if (req.url?.endsWith("/as/token.oauth2")) {
        lastTokenRequestHeaders = { ...req.headers };
        const hasPop = !!req.headers["oauth-client-attestation-pop"];
        const hasDpop = !!req.headers["dpop"];
        if (!req.headers["oauth-client-attestation"] || (!hasPop && !hasDpop)) {
          return json(401, { error: "invalid_client" });
        }
        expect(raw).toContain("grant_type=client_credentials");
        expect(raw).not.toContain("client_secret");
        expect(raw).not.toContain("client_id");
        return json(200, { access_token: "AT-xyz", expires_in: 3600, token_type: "Bearer" });
      }
      return json(404, { error: "not_found" });
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  fixture = { server, baseUrl: `http://127.0.0.1:${port}` };
});

afterEach(async () => {
  await new Promise<void>((resolve) => fixture.server.close(() => resolve()));
});

describe("ClientAttestation full flow", () => {
  it("returns and caches a token", async () => {
    const ca = new ClientAttestation(fixture.baseUrl, { evidence: new StaticSvidSource("fake-svid") });
    const token = await ca.token();
    expect(token).toBe("AT-xyz");
    expect((await ca.authorizationHeader()).Authorization).toBe("Bearer AT-xyz");
    // Cached: a second call returns the same token without re-minting.
    expect(await ca.token()).toBe("AT-xyz");

    // Default PoP method: the token request carries the dedicated PoP JWT, and it carries the
    // fetched challenge (regression test for the bug where the challenge was fetched but dropped
    // before it reached the PopBuilder that produces this header).
    const pop = lastTokenRequestHeaders["oauth-client-attestation-pop"];
    expect(typeof pop).toBe("string");
    const popClaims = decodeJwt(pop as string);
    expect(popClaims.challenge).toBe("chal-123");
    expect(lastTokenRequestHeaders["dpop"]).toBeUndefined();
  });

  it("uses a DPoP-combined proof (with the challenge as nonce) when popMethod is dpop_combined", async () => {
    const ca = new ClientAttestation(fixture.baseUrl, {
      evidence: new StaticSvidSource("fake-svid"),
      popMethod: "dpop_combined",
    });
    const token = await ca.token();
    expect(token).toBe("AT-xyz");

    // No dedicated PoP header in this mode ...
    expect(lastTokenRequestHeaders["oauth-client-attestation-pop"]).toBeUndefined();
    // ... instead a DPoP proof carrying the fetched challenge as its nonce.
    const dpop = lastTokenRequestHeaders["dpop"];
    expect(typeof dpop).toBe("string");
    const dpopClaims = decodeJwt(dpop as string);
    expect(dpopClaims.nonce).toBe("chal-123");
    expect(dpopClaims.htm).toBe("POST");
  });
});

// ── SPIRE Workload API source against a fake spire-agent binary ───────────────────────────────────

describe("SpireWorkloadApiSvidSource with a fake spire-agent", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "spire-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  /** A shell script standing in for spire-agent: records its argv, prints `output`. */
  function fakeAgent(output: string): string {
    const bin = join(dir, "spire-agent");
    writeFileSync(bin, `#!/bin/sh\necho "$@" > "${dir}/argv"\nprintf '%s' '${output}'\n`);
    chmodSync(bin, 0o755);
    return bin;
  }

  it("parses the token(...) line and passes audience and socket", async () => {
    const bin = fakeAgent("token(spiffe://example.org/wl):\teyJh.eyJw.sig\n");
    const source = new SpireWorkloadApiSvidSource("/run/agent.sock", bin);
    expect(await source.fetch("https://attester.example.com")).toBe("eyJh.eyJw.sig");
    expect(readFileSync(join(dir, "argv"), "utf8").trim()).toBe(
      "api fetch jwt -audience https://attester.example.com -socketPath /run/agent.sock",
    );
  });

  it("accepts a bare JWT line", async () => {
    const source = new SpireWorkloadApiSvidSource("/run/agent.sock", fakeAgent("header\naaa.bbb.ccc\n"));
    expect(await source.fetch("aud")).toBe("aaa.bbb.ccc");
  });

  it("throws when the output has no SVID", async () => {
    const source = new SpireWorkloadApiSvidSource("/run/agent.sock", fakeAgent("nothing here\n"));
    await expect(source.fetch("aud")).rejects.toThrow(/could not parse SVID/);
  });
});
