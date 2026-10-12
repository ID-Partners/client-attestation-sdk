/**
 * Bounds on what the client reads from places it does not control: a resource's 400 body, a token
 * file, a spire-agent that never exits, and a token endpoint's expires_in. Local servers and files only.
 */
import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ClientAttestation, EvidenceNotFound, FileTokenSvidSource, StaticSvidSource } from "../src/index.js";

const servers: Server[] = [];

afterEach(async () => {
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

/**
 * An attester + AS on static metadata (no discovery, no challenge) whose token endpoint answers
 * `{"access_token":"AT-<n>", "expires_in": <expiresIn>}`, `expiresIn` spliced in as raw JSON (undefined
 * leaves the member out). `calls()` counts token requests; `set()` changes expiresIn for later ones.
 */
async function attester(expiresIn: string | undefined, extra: Record<string, unknown> = {}) {
  let current = expiresIn;
  let calls = 0;
  const url = await listen((req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    if (req.url === "/mint") {
      const sub = Buffer.from(JSON.stringify({ sub: "demo" })).toString("base64url");
      return res.end(JSON.stringify({ attestation: `h.${sub}.s` }));
    }
    calls += 1;
    const tail = current === undefined ? "" : `,"expires_in":${current}`;
    res.end(`{"access_token":"AT-${calls}","token_type":${JSON.stringify(extra.tokenType ?? "Bearer")}${tail}}`);
  });
  const ca = new ClientAttestation({
    evidence: new StaticSvidSource("svid"),
    metadata: { evidenceAudience: "aud", attestationEndpoint: url + "/mint", tokenEndpoint: url + "/token" },
    ...extra,
  });
  return { ca, calls: () => calls, set: (e: string | undefined) => (current = e) };
}

describe("expires_in", () => {
  it.each([
    ["3600", true],
    ["3600.5", true],
    ['"3600"', true], // a numeric string, as some servers send
    [undefined, false], // missing: no expiry, not cached
    ["null", false],
    ["0", false],
    ["-60", false],
    ["1e400", false], // JSON.parse reads this as Infinity
    ['"soon"', false],
    ['"1e3"', false],
    ['"0x10"', false],
    ["true", false],
    ["[3600]", false],
  ])("expires_in %s cached=%s", async (expiresIn, cached) => {
    const { ca, calls } = await attester(expiresIn);
    const first = await ca.token();
    const second = await ca.token();
    expect(first === second && calls() === 1).toBe(cached);
  });

  it("caches for at most 24 hours", async () => {
    const { ca, calls } = await attester("1e15");
    const start = performance.now();
    await ca.token();
    const now = vi.spyOn(performance, "now");
    try {
      now.mockReturnValue(start + 23 * 3600_000);
      await ca.token();
      expect(calls()).toBe(1);
      now.mockReturnValue(start + 24 * 3600_000 + 1000);
      await ca.token();
      expect(calls()).toBe(2);
    } finally {
      now.mockRestore();
    }
  });

  it("follows the monotonic clock, not the wall clock", async () => {
    const { ca, calls } = await attester("300"); // cached for 270 seconds
    const wall = Date.now();
    const mono = performance.now();
    await ca.token();
    const dateNow = vi.spyOn(Date, "now");
    const perfNow = vi.spyOn(performance, "now");
    try {
      // The wall clock jumps forward two hours (an NTP step): the token is still fresh.
      dateNow.mockReturnValue(wall + 7200_000);
      perfNow.mockReturnValue(mono);
      await ca.token();
      expect(calls()).toBe(1);
      // An hour passes, but the wall clock is stepped back two hours: the token has still expired.
      dateNow.mockReturnValue(wall - 3600_000);
      perfNow.mockReturnValue(mono + 3600_000);
      await ca.token();
      expect(calls()).toBe(2);
    } finally {
      dateNow.mockRestore();
      perfNow.mockRestore();
    }
  });

  it("a forced refresh with an invalid expires_in does not keep the old expiry", async () => {
    const { ca, calls, set } = await attester("3600");
    await ca.token();
    set('"soon"');
    const refreshed = await ca.token({ forceRefresh: true });
    expect(await ca.token()).not.toBe(refreshed);
    expect(calls()).toBe(3);
  });
});

describe("expirySkewSeconds", () => {
  it.each([-1, Number.NaN, Number.POSITIVE_INFINITY])("rejects %s", (skew) => {
    expect(() => new ClientAttestation("https://attester.example", { expirySkewSeconds: skew })).toThrow(RangeError);
  });

  it("accepts zero", () => {
    expect(() => new ClientAttestation("https://attester.example", { expirySkewSeconds: 0 })).not.toThrow();
  });
});

describe("fetch: the 400 nonce-challenge body", () => {
  it("is not a challenge when longer than 64 KiB, and the caller still gets all of it", async () => {
    const body = JSON.stringify({ error: "use_dpop_nonce" }) + " ".repeat(64 * 1024);
    let hits = 0;
    const rs = await listen((_req, res) => {
      hits += 1;
      res.writeHead(400, { "Content-Type": "application/json", "DPoP-Nonce": "n-1" });
      res.end(body);
    });
    const { ca } = await attester("3600", { popMethod: "dpop_combined", tokenType: "DPoP" });
    const res = await ca.fetch(rs + "/data");
    expect(res.status).toBe(400);
    expect(await res.text()).toBe(body);
    expect(hits).toBe(1);
  });

  it("stops reading an endless body after 64 KiB and hands the response back", async () => {
    let hits = 0;
    const rs = await listen((_req, res) => {
      hits += 1;
      res.writeHead(400, { "Content-Type": "application/json", "DPoP-Nonce": "n-1" });
      const chunk = Buffer.alloc(16 * 1024, 0x20);
      const pump = () => {
        while (!res.destroyed && res.write(chunk));
        if (!res.destroyed) res.once("drain", pump);
      };
      res.write('{"error":"use_dpop_nonce"}');
      pump();
    });
    const { ca } = await attester("3600", { popMethod: "dpop_combined", tokenType: "DPoP" });
    const res = await ca.fetch(rs + "/data");
    expect(res.status).toBe(400);
    expect(hits).toBe(1);
    await res.body?.cancel();
  });

  it("gives up on a body that stalls, after the client's timeout", async () => {
    let hits = 0;
    const rs = await listen((_req, res) => {
      hits += 1;
      res.writeHead(400, { "Content-Type": "application/json", "DPoP-Nonce": "n-1" });
      res.write('{"error":'); // and never finishes
    });
    const { ca } = await attester("3600", { popMethod: "dpop_combined", tokenType: "DPoP", timeoutMs: 300 });
    const started = Date.now();
    const res = await ca.fetch(rs + "/data");
    expect(res.status).toBe(400);
    expect(Date.now() - started).toBeLessThan(5000);
    expect(hits).toBe(1);
    await res.body?.cancel();
  });

  it("is not a challenge when the body fails mid-read, and the response is handed back", async () => {
    let hits = 0;
    const rs = await listen((_req, res) => {
      hits += 1;
      res.writeHead(400, { "Content-Type": "application/json", "DPoP-Nonce": "n-1" });
      res.write('{"error":"use_dpop', () => res.destroy());
    });
    const { ca } = await attester("3600", { popMethod: "dpop_combined", tokenType: "DPoP" });
    const res = await ca.fetch(rs + "/data");
    expect(res.status).toBe(400);
    expect(hits).toBe(1);
    await res.body?.cancel().catch(() => undefined);
  });
});

describe("FileTokenSvidSource limits", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "token-file-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("refuses a file over 64 KiB and reads one at exactly 64 KiB", async () => {
    const big = join(dir, "big");
    writeFileSync(big, "a".repeat(64 * 1024 + 1));
    const err = await new FileTokenSvidSource(big).fetch("aud").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(EvidenceNotFound);
    expect((err as Error).message).toContain("larger than");
    const max = join(dir, "max");
    writeFileSync(max, "b".repeat(64 * 1024));
    expect((await new FileTokenSvidSource(max).fetch("aud")).length).toBe(64 * 1024);
  });

  it.skipIf(process.platform === "win32")("refuses a FIFO and /dev/zero without blocking", async () => {
    const fifo = join(dir, "fifo");
    execFileSync("mkfifo", [fifo]);
    for (const path of [fifo, "/dev/zero"]) {
      const err = await new FileTokenSvidSource(path).fetch("aud").catch((e: unknown) => e);
      expect(err).toBeInstanceOf(EvidenceNotFound);
      expect((err as Error).message).toContain("not a regular file");
    }
  }, 5000);
});

describe("SpireWorkloadApiSvidSource timeout", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "spire-hang-"));
  });
  afterEach(() => {
    vi.doUnmock("../src/runtime.js");
    vi.resetModules();
    rmSync(dir, { recursive: true, force: true });
  });

  it.skipIf(process.platform === "win32")("kills a spire-agent that does not exit (30 s, SIGKILL)", async () => {
    const bin = join(dir, "spire-agent");
    writeFileSync(bin, "#!/bin/sh\nexec sleep 30\n");
    chmodSync(bin, 0o755);
    const options: unknown[] = [];
    vi.resetModules();
    vi.doMock("../src/runtime.js", async (importOriginal) => {
      const actual = await importOriginal<typeof import("../src/runtime.js")>();
      return {
        ...actual,
        importNodeBuiltin: async (name: string, feature: string) => {
          const mod = await actual.importNodeBuiltin<typeof import("node:child_process")>(name, feature);
          if (name !== "child_process") return mod;
          // Record the options, and shorten the 30 s bound so the test is quick.
          const spawn = (file: string, args: string[], opts: Parameters<typeof mod.spawn>[2]) => {
            options.push(opts);
            return mod.spawn(file, args, { ...opts, timeout: 200 });
          };
          return { ...mod, spawn };
        },
      };
    });
    const { SpireWorkloadApiSvidSource } = await import("../src/svid-source.js");
    const err = (await new SpireWorkloadApiSvidSource("/run/agent.sock", bin).fetch("aud").catch((e: unknown) => e)) as {
      killed?: boolean;
      signal?: string;
    };
    expect(options[0]).toMatchObject({ timeout: 30_000, killSignal: "SIGKILL", stdio: ["ignore", "pipe", "ignore"] });
    expect(err.killed).toBe(true);
    expect(err.signal).toBe("SIGKILL");
  }, 5000);

  it.skipIf(process.platform === "win32")("kills at the timeout even if a helper holds stdout open", async () => {
    const bin = join(dir, "spire-agent");
    writeFileSync(bin, "#!/bin/sh\nsleep 30 &\nexec sleep 30\n");
    chmodSync(bin, 0o755);
    vi.resetModules();
    vi.doMock("../src/runtime.js", async (importOriginal) => {
      const actual = await importOriginal<typeof import("../src/runtime.js")>();
      return {
        ...actual,
        importNodeBuiltin: async (name: string, feature: string) => {
          const mod = await actual.importNodeBuiltin<typeof import("node:child_process")>(name, feature);
          if (name !== "child_process") return mod;
          const spawn = (file: string, args: string[], opts: Parameters<typeof mod.spawn>[2]) =>
            mod.spawn(file, args, { ...opts, timeout: 200 });
          return { ...mod, spawn };
        },
      };
    });
    const { SpireWorkloadApiSvidSource } = await import("../src/svid-source.js");
    const started = Date.now();
    const err = (await new SpireWorkloadApiSvidSource("/run/agent.sock", bin).fetch("aud").catch((e: unknown) => e)) as {
      killed?: boolean;
    };
    expect(err.killed).toBe(true);
    expect(Date.now() - started).toBeLessThan(3000);
  }, 10000);

  it("an agent that cannot start fails with its code and nothing from Node's message", async () => {
    // Node's message for a process that failed can carry its stderr, even with a string code (a negative exit
    // status is reported as the errno name), so only the code may reach the error.
    const failure = Object.assign(new Error("Command failed: spire-agent\nerror: SECRET-STDERR"), { code: "EACCES" });
    vi.resetModules();
    vi.doMock("../src/runtime.js", async (importOriginal) => {
      const actual = await importOriginal<typeof import("../src/runtime.js")>();
      const { EventEmitter } = await import("node:events");
      return {
        ...actual,
        importNodeBuiltin: async (name: string, feature: string) => {
          const mod = await actual.importNodeBuiltin<typeof import("node:child_process")>(name, feature);
          if (name !== "child_process") return mod;
          const spawn = () => {
            const child = Object.assign(new EventEmitter(), { stdout: new EventEmitter(), killed: false });
            setImmediate(() => {
              child.emit("error", failure);
              child.emit("close", -13, null);
            });
            return child;
          };
          const execFile = (_file: string, _args: string[], _opts: unknown, cb: (err: Error) => void) =>
            setImmediate(() => cb(failure));
          return { ...mod, spawn, execFile };
        },
      };
    });
    const { SpireWorkloadApiSvidSource } = await import("../src/svid-source.js");
    const source = new SpireWorkloadApiSvidSource("/s", "/opt/spire-agent");
    const err = (await source.fetch("aud").catch((e: unknown) => e)) as { message: string; code?: unknown };
    expect(err.message).toBe("spire-agent fetch failed: could not run /opt/spire-agent (EACCES)");
    expect(err.code).toBe("EACCES");
  });
});
