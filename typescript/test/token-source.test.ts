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

import type { AttesterMetadata, SvidSource } from "../src/index.js";
import {
  ClientAttestation,
  ClientAttestationError,
  StaticSvidSource,
  TransportError,
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

const AUD = "https://attester.example.com"; // the evidence_audience the fake attester's discovery document names

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

  it("does not use a server that answers 200 without Metadata-Flavor: Google", async () => {
    for (const flavor of ["", "Other"]) {
      const gcp = await fakeMetadata(200, flavor);
      try {
        await expect(autoDetectEvidence({ ...isolated(), gcpMetadataBase: gcp.base })).rejects.toBeInstanceOf(
          EvidenceNotFound,
        );
        // nor does the identity fetch accept a token from it
        const source = new GoogleMetadataSvidSource(5000, gcp.base + "/computeMetadata/v1/instance/service-accounts/default/identity");
        await expect(source.fetch("aud")).rejects.toThrow(/Metadata-Flavor/);
      } finally {
        await gcp.close();
      }
    }
  });

  it("does not use a metadata server that answers 2xx other than 200", async () => {
    const gcp = await fakeMetadata(204);
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

/** A local stand-in for the GCP metadata server; it sets `Metadata-Flavor: flavor` unless that is empty. */
async function fakeMetadata(probeStatus = 200, flavor = "Google") {
  const state = { hits: 0, lastIdentityUrl: "", lastFlavor: "" as string | undefined };
  const server = createServer((req, res) => {
    state.hits++;
    state.lastFlavor = req.headers["metadata-flavor"] as string | undefined;
    if (flavor) res.setHeader("Metadata-Flavor", flavor);
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
        evidence_audience: AUD,
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
    const ca = new ClientAttestation(fixture.baseUrl, { evidence: new StaticSvidSource("fake-svid"), evidenceAudience: AUD });
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
      evidence: new StaticSvidSource("fake-svid"), evidenceAudience: AUD,
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

/** An evidence source that records the audiences it was asked for. */
class RecordingSource implements SvidSource {
  readonly audiences: string[] = [];

  async fetch(audience: string): Promise<string> {
    this.audiences.push(audience);
    return "svid";
  }
}

describe("evidenceAudience pin", () => {
  it("is required before any request", async () => {
    // Without a pin the discovery document would choose the audience the workload's identity token is for.
    const source = new RecordingSource();
    const ca = new ClientAttestation("https://attester.invalid", { evidence: source }); // not resolvable: any request would fail
    const err = await ca.token().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ClientAttestationError);
    expect(err).not.toBeInstanceOf(TransportError);
    expect((err as Error).message).toContain("evidenceAudience is required");
    expect(source.audiences).toEqual([]);
  });

  it("fetches no evidence when the discovered audience is not the pin", async () => {
    const source = new RecordingSource();
    const ca = new ClientAttestation(fixture.baseUrl, { evidence: source, evidenceAudience: "https://other-service.example" });
    await expect(ca.token()).rejects.toThrow(
      'the attester asks for evidence for "https://attester.example.com", but evidenceAudience is "https://other-service.example"',
    );
    expect(source.audiences).toEqual([]);
  });

  it("needs no pin with static metadata, but must match one", async () => {
    const metadata: AttesterMetadata = {
      evidenceAudience: "aud-1",
      attestationEndpoint: "https://attester.invalid/mint",
      tokenEndpoint: "https://attester.invalid/token",
    };
    const source = new RecordingSource();
    await expect(new ClientAttestation({ metadata, evidence: source, evidenceAudience: "aud-2" }).token()).rejects.toThrow(
      'but evidenceAudience is "aud-2"',
    );
    expect(source.audiences).toEqual([]);
    // no pin needed: the flow gets as far as minting
    const err = await new ClientAttestation({ metadata, evidence: source, timeoutMs: 1000 }).token().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(TransportError);
    expect(source.audiences).toEqual(["aud-1"]);
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

  /** A shell script standing in for spire-agent: records its argv, writes `stderr` then `output`. */
  function fakeAgent(output: string, stderr = "", exitCode = 0): string {
    const bin = join(dir, "spire-agent");
    writeFileSync(join(dir, "stdout"), output);
    writeFileSync(join(dir, "stderr"), stderr);
    writeFileSync(
      bin,
      `#!/bin/sh\necho "$@" > "${dir}/argv"\ncat "${dir}/stderr" >&2\ncat "${dir}/stdout"\nexit ${exitCode}\n`,
    );
    chmodSync(bin, 0o755);
    return bin;
  }

  // Two JWT-SVIDs shaped like real ones: an ES256 header with a kid, a SPIFFE sub, a 64-byte signature.
  const SVID =
    "eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiSldUIn0.eyJhdWQiOlsiaHR0cHM6Ly9hdWQiXSwiZXhwIjo0MTAyNDQ0ODAwLCJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLm9yZy93bCJ9.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw";
  const OTHER_SVID =
    "eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiSldUIn0.eyJhdWQiOlsiaHR0cHM6Ly9hdWQiXSwiZXhwIjo0MTAyNDQ0ODAwLCJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLm9yZy9vdGhlciJ9.QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-fw";
  const BUNDLE =
    '{"keys":[{"kty":"EC","kid":"k1","crv":"P-256","x":"WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis","y":"y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"}]}';
  // What `spire-agent api fetch jwt` prints for two SVIDs, one with a hint, and a bundle: the layout of
  // printPrettyResult in SPIRE's cmd/spire-agent/cli/api/fetch_jwt.go (v1.5 to v1.15),
  // "token(%s):\n\t%s\n", "hint(%s):\n\t%s\n" and "bundle(%s):\n\t%s\n".
  const OUTPUT =
    `token(spiffe://example.org/wl):\n\t${SVID}\n` +
    "hint(spiffe://example.org/wl):\n\texternal\n" +
    `token(spiffe://example.org/other):\n\t${OTHER_SVID}\n` +
    `bundle(spiffe://example.org):\n\t${BUNDLE}\n`;

  it("parses SPIRE's two-line output, takes the first token, and passes audience and socket", async () => {
    const source = new SpireWorkloadApiSvidSource("/run/agent.sock", fakeAgent(OUTPUT));
    expect(await source.fetch("https://attester.example.com")).toBe(SVID);
    expect(readFileSync(join(dir, "argv"), "utf8").trim()).toBe(
      "api fetch jwt -audience https://attester.example.com -socketPath /run/agent.sock",
    );
  });

  it("accepts the single-line token(...) form and a bare JWT line", async () => {
    const single = fakeAgent(`token(spiffe://example.org/wl):\t${SVID}\n`);
    expect(await new SpireWorkloadApiSvidSource("/run/agent.sock", single).fetch("aud")).toBe(SVID);
    const bare = fakeAgent(`header\n  ${SVID}  \n`);
    expect(await new SpireWorkloadApiSvidSource("/run/agent.sock", bare).fetch("aud")).toBe(SVID);
  });

  it("does not read stderr as output", async () => {
    const withToken = fakeAgent(OUTPUT, "1.9.6\n");
    expect(await new SpireWorkloadApiSvidSource("/s", withToken).fetch("aud")).toBe(SVID);
    const without = fakeAgent("", "1.9.6\n");
    await expect(new SpireWorkloadApiSvidSource("/s", without).fetch("aud")).rejects.toBeInstanceOf(EvidenceNotFound);
  });

  it.each([
    "1.9.6\n",
    "level=info msg=starting version=v1.9.6\n",
    "a.b.c\n",
    "token(spiffe://example.org/wl):\n\t1.9.6\n",
    "token(spiffe://example.org/wl):\n",
    "eyJ0eXAiOiJKV1QifQ.e30.c2ln\n", // a JSON header with no alg
    "bnVsbA.e30.c2ln\n", // a header of null
    "eyJhbGciOiJFUzI1NiJ9.e30.\n", // no signature
    "nothing here\n",
    "eyJhbGciOiJFUzI1NiIsfQ.e30.c2ln\n", // {"alg":"ES256",}: not strict JSON
    "eyJhbGciOiJFUzI1NiIsImFsZyI6IkVTMjU2In0.e30.c2ln\n", // a duplicate "alg"
    "77u_eyJhbGciOiJFUzI1NiJ9.e30.c2ln\n", // a header with a BOM
    `\ufeff${SVID}\n`, // a BOM is not whitespace
    `\u00a0${SVID}\u00a0\n`, // nor is an NBSP
    `token(spiffe://example.org/wl):\n\u00a0${SVID}\n`,
    `token(spiffe://example.org/wl): \ufeff${SVID}\n`,
    `\v${SVID}\f\n`,
  ])("refuses output without a compact JWS: %j", async (output) => {
    const err = await new SpireWorkloadApiSvidSource("/s", fakeAgent(output)).fetch("aud").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(EvidenceNotFound);
    expect((err as Error).message).toMatch(/could not parse a JWT-SVID/);
  });

  it("ignores only ASCII space, tab and CR around a value", async () => {
    const bin = fakeAgent(`token(spiffe://example.org/wl):\r\n \t${SVID}\t \r\n`);
    expect(await new SpireWorkloadApiSvidSource("/s", bin).fetch("aud")).toBe(SVID);
  });

  it.each([
    `hint(spiffe://example.org/wl):\ntoken(spiffe://example.org/wl): ${SVID}\n`,
    `token(spiffe://example.org/wl):\ntoken(spiffe://example.org/other): ${SVID}\n`,
    `bundle(spiffe://example.org):\n\ttoken(spiffe://example.org/wl): ${SVID}\n`,
  ])("a label with no value does not take the next label as its value: %j", async (output) => {
    expect(await new SpireWorkloadApiSvidSource("/s", fakeAgent(output)).fetch("aud")).toBe(SVID);
  });

  it("caps stdout at 1 MiB", async () => {
    const line = `token(spiffe://example.org/wl): ${SVID}\n`;
    const atCap = line + "x".repeat((1 << 20) - line.length);
    expect(await new SpireWorkloadApiSvidSource("/s", fakeAgent(atCap)).fetch("aud")).toBe(SVID);
    // One byte more while the agent is still running fails the fetch.
    const over = fakeAgent(atCap + "x");
    writeFileSync(over, `#!/bin/sh\ncat "${dir}/stdout"\nexec sleep 5\n`);
    const err = (await new SpireWorkloadApiSvidSource("/s", over).fetch("aud").catch((e: unknown) => e)) as Error;
    expect(err.message).toBe("spire-agent fetch failed: output is larger than 1048576 bytes");
  });

  it("an agent that writes past the cap and exits always fails", async () => {
    // The agent itself writes 1 MiB + 1 byte and exits at once, so the last bytes may be read either side of
    // its exit. They were written while it ran, so the fetch fails every time, as in the other ports.
    const bin = fakeAgent("");
    writeFileSync(bin, "#!/bin/sh\nexec head -c 1048577 /dev/zero\n");
    let ok = 0;
    for (let i = 0; i < 50; i++) {
      const err = await new SpireWorkloadApiSvidSource("/s", bin).fetch("aud").then(
        () => undefined,
        (e: unknown) => e as Error,
      );
      if (err === undefined || err instanceof EvidenceNotFound) {
        ok++; // read as post-exit output: cut at the cap, no token in it
      } else {
        expect(err.message).toBe("spire-agent fetch failed: output is larger than 1048576 bytes");
      }
    }
    expect(`${ok} of 50 runs did not fail with the size error`).toBe("0 of 50 runs did not fail with the size error");
  }, 30_000);

  it("discards a flood of stderr", async () => {
    const bin = fakeAgent(OUTPUT, "e".repeat(4 << 20));
    expect(await new SpireWorkloadApiSvidSource("/s", bin).fetch("aud")).toBe(SVID);
  });

  it("a missing agent fails with ENOENT", async () => {
    const bin = join(dir, "no-such-spire-agent");
    const err = (await new SpireWorkloadApiSvidSource("/s", bin).fetch("aud").catch((e: unknown) => e)) as Error;
    expect(err.message).toBe(`spire-agent fetch failed: could not run ${bin} (ENOENT)`);
    expect((err as { code?: unknown }).code).toBe("ENOENT");
  });

  it("does not show the output in the error", async () => {
    const output = `secret-not-a-jwt\nbundle(spiffe://example.org):\n\t${BUNDLE}\n`;
    const err = (await new SpireWorkloadApiSvidSource("/s", fakeAgent(output, SVID))
      .fetch("aud")
      .catch((e: unknown) => e)) as Error;
    expect(err).toBeInstanceOf(EvidenceNotFound);
    expect(err.message).not.toContain("secret-not-a-jwt");
    expect(err.message).not.toContain("WKn-ZIG");
    expect(err.message).not.toContain(SVID);
    expect(err.message).toContain(`${output.length} bytes, 3 lines`);
  });

  it("fails when the agent fails, without its output", async () => {
    const bin = fakeAgent(OUTPUT, `error: ${SVID}\n`, 1);
    const err = (await new SpireWorkloadApiSvidSource("/s", bin).fetch("aud").catch((e: unknown) => e)) as Error;
    expect(err.message).toBe("spire-agent fetch failed: exit status 1");
    expect((err as { code?: unknown }).code).toBe(1);
  });
});
