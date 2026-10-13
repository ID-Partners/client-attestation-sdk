/**
 * Pluggable sources for a workload's SPIFFE JWT-SVID — the infra-identity input to attestation
 * bootstrapping ({@link AttestationIssuanceClient}). The default {@link SpireWorkloadApiSvidSource}
 * fetches it from a real SPIRE agent; the others cover dev and tests.
 */
import { EvidenceNotFound } from "./evidence.js";
import { jsonOk, request } from "./http.js";
import { importNodeBuiltin, utf8Encode } from "./runtime.js";
import { decodeSegment, Malformed, parseObject } from "./validator/strict.js";

/** Per-call timeout for {@link HttpSvidSource}. */
const HTTP_SVID_TIMEOUT_MS = 20_000;
/** How long `spire-agent` may run before it is killed (as in the other ports). */
const SPIRE_AGENT_TIMEOUT_MS = 30_000;
/**
 * The most stdout read from `spire-agent` (as in the other ports). More while the agent is running fails the
 * fetch; once it has exited, reading stops there.
 */
const SPIRE_AGENT_MAX_OUTPUT = 1 << 20;
/**
 * How long stdout is still read after `spire-agent` has exited (as in the other ports). A helper the agent
 * started can inherit the pipe and hold it open; after this the pipe is closed.
 */
const SPIRE_AGENT_STDOUT_GRACE_MS = 250;

/** Anything that can produce a compact JWT-SVID for an audience. */
export interface SvidSource {
  fetch(audience: string): Promise<string>;
}

/** A fixed, pre-fetched SVID — for tests, or when the caller already holds one. */
export class StaticSvidSource implements SvidSource {
  readonly #svid: string; // private, so JSON.stringify and console.log don't show it

  constructor(svid: string) {
    this.#svid = svid;
  }

  async fetch(_audience: string): Promise<string> {
    return this.#svid;
  }
}

/**
 * GET a URL returning `{"svid":"<jwt>"}` — e.g. the demo harness `/dev/svid` endpoint.
 *
 * For development and testing only. It trusts whatever the URL returns and the endpoint has no caller
 * authentication, so anyone who can reach it can obtain the workload's SVID. In production use a SPIRE,
 * file or cloud source.
  *
  * @experimental See docs/api.md: a development and test source with no caller authentication.
 */
export class HttpSvidSource implements SvidSource {
  constructor(private readonly url: string) {}
  async fetch(_audience: string): Promise<string> {
    const res = await request(this.url, { method: "GET", timeoutMs: HTTP_SVID_TIMEOUT_MS });
    const body = jsonOk<{ svid?: unknown }>(res);
    if (typeof body.svid !== "string" || !body.svid) throw new Error(`no svid in response from ${this.url}`);
    return body.svid;
  }
}

/**
 * The default source: fetch a JWT-SVID from a real SPIRE agent's Workload API via the `spire-agent`
 * CLI. Swap for a native Workload API client by implementing {@link SvidSource} if you prefer no
 * subprocess. An agent that has not exited within 30 s is killed and `fetch` rejects. `fetch` returns the
 * first JWT-SVID the agent prints on stdout and throws {@link EvidenceNotFound} if there is none. The
 * agent's stderr is discarded, never read as output or held in memory.
 *
 * The agent's exit decides the outcome, as in the other ports. While the agent is running, more than
 * 1 MiB of stdout kills it and `fetch` rejects. Once it has exited, stdout is read for at most 250 ms more
 * and at most 1 MiB in all (a helper the agent started can inherit the pipe and keep writing to it or hold
 * it open), then the pipe is closed. On exit status 0 what was read is parsed; on any other status, or if
 * the agent was killed, `fetch` rejects. So output a helper writes after the agent has exited never turns a
 * success into a failure, and never keeps `fetch` waiting longer than that. If reading stopped at the
 * 1 MiB or at the end of the 250 ms, the last line may be cut off, so a token is only taken from a line
 * that ends in a newline.
 *
 * Needs Node.js (it spawns a process): `node:child_process` is loaded on the first `fetch`, which throws
 * a `ClientAttestationError` on a runtime without it.
  *
  * @experimental See docs/api.md: it shells out to the spire-agent CLI, and its constructor will change
  * when it moves to the Workload API socket.
 */
export class SpireWorkloadApiSvidSource implements SvidSource {
  constructor(
    private readonly socketPath = "/tmp/spire-agent/public/api.sock",
    private readonly spireAgentBin = "spire-agent",
  ) {}

  async fetch(audience: string): Promise<string> {
    const { spawn } = await importNodeBuiltin<typeof import("node:child_process")>(
      "child_process",
      "SpireWorkloadApiSvidSource",
    );
    // stdout only: stderr goes to the null device, so a log line or version string the agent writes there
    // is never parsed, and a flood of it is never held in memory.
    const { stdout, complete } = await new Promise<{ stdout: string; complete: boolean }>((resolve, reject) => {
      const args = ["api", "fetch", "jwt", "-audience", audience, "-socketPath", this.socketPath];
      const child = spawn(this.spireAgentBin, args, {
        stdio: ["ignore", "pipe", "ignore"],
        timeout: SPIRE_AGENT_TIMEOUT_MS,
        killSignal: "SIGKILL",
      });
      const chunks: Uint8Array[] = [];
      let size = 0;
      let over = false; // past the cap while the agent was running
      let ended = false; // stdout was read to its end
      let exited: { code: number | null; signal: NodeJS.Signals | null } | undefined;
      let settled = false;
      let grace: ReturnType<typeof setTimeout> | undefined;
      // Settle once, and let go of stdout: a helper the agent started can inherit the pipe and hold it open
      // after the agent is gone, so neither the timeout nor the size cap may wait for stdout to close.
      const settle = (code: number | null, signal: NodeJS.Signals | null) => {
        if (settled) return;
        settled = true;
        if (grace) clearTimeout(grace);
        child.stdout?.destroy?.();
        if (over) {
          const message = `spire-agent fetch failed: output is larger than ${SPIRE_AGENT_MAX_OUTPUT} bytes`;
          reject(Object.assign(new Error(message), { code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER" }));
        } else if (code === 0) {
          resolve({ stdout: concatUtf8(chunks, size), complete: ended });
        } else {
          reject(spireAgentExitFailure(code, signal, child.killed));
        }
      };
      child.stdout?.on("data", (chunk: Uint8Array) => {
        if (over || settled) return;
        if (size + chunk.length > SPIRE_AGENT_MAX_OUTPUT) {
          if (exited) {
            // The agent has exited: stop at the cap, and let its exit status decide.
            chunks.push(chunk.subarray(0, SPIRE_AGENT_MAX_OUTPUT - size));
            size = SPIRE_AGENT_MAX_OUTPUT;
            settle(exited.code, exited.signal);
            return;
          }
          // Still running: kill it and fail.
          over = true;
          chunks.length = 0;
          child.kill("SIGKILL");
          settle(null, "SIGKILL");
          return;
        }
        size += chunk.length;
        chunks.push(chunk);
      });
      child.stdout?.on("end", () => {
        if (!settled) ended = true;
      });
      child.stdout?.on("error", () => {}); // the outcome comes from "exit" or "close"
      child.on("error", (err: NodeJS.ErrnoException) => {
        if (settled) return;
        settled = true;
        if (grace) clearTimeout(grace);
        child.stdout?.destroy?.();
        reject(spireAgentStartFailure(this.spireAgentBin, err));
      });
      // The agent has exited (on its own, or killed at the timeout): what it wrote is in the pipe, so give
      // stdout a moment to drain, then settle whether or not something else still holds it open.
      child.on("exit", (code, signal) => {
        exited = { code, signal };
        if (!settled) grace = setTimeout(() => settle(code, signal), SPIRE_AGENT_STDOUT_GRACE_MS);
      });
      child.on("close", (code, signal) => settle(code, signal));
    });
    // If reading stopped before the end of stdout (at the cap or the end of the grace period), the line
    // after the last newline may have been cut off.
    const svid = parseSpireJwtOutput(complete ? stdout : stdout.slice(0, stdout.lastIndexOf("\n") + 1));
    if (svid) return svid;
    // The output may hold a token or bundle that failed to parse, so the error gives only its size.
    const lines = stdout.split("\n").length - (stdout === "" || stdout.endsWith("\n") ? 1 : 0);
    throw new EvidenceNotFound(
      `could not parse a JWT-SVID from spire-agent output (${utf8Encode(stdout).length} bytes, ${lines} lines; not shown)`,
    );
  }
}

/** stdout as text: invalid UTF-8 becomes U+FFFD and a leading BOM is kept, as in the other ports. */
function concatUtf8(chunks: Uint8Array[], size: number): string {
  const all = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) {
    all.set(chunk, at);
    at += chunk.length;
  }
  return new TextDecoder("utf-8", { ignoreBOM: true }).decode(all);
}

/**
 * The error for a `spire-agent` that could not be started: its `code` (`ENOENT` when it is not installed)
 * and nothing else from Node's error.
 */
function spireAgentStartFailure(bin: string, err: NodeJS.ErrnoException): Error {
  const code = typeof err.code === "string" ? err.code : "unknown error";
  return Object.assign(new Error(`spire-agent fetch failed: could not run ${bin} (${code})`), { code: err.code });
}

/**
 * The error for a `spire-agent` that ran and failed: how it ended, never its output. `code`, `killed` and
 * `signal` are kept.
 */
function spireAgentExitFailure(code: number | null, signal: NodeJS.Signals | null, killed: boolean): Error {
  const how = signal ? `killed with ${signal}` : `exit status ${code}`;
  return Object.assign(new Error(`spire-agent fetch failed: ${how}`), { code, killed, signal });
}

const SPIRE_SECTION = /^(token|hint|bundle)\(.*?\):(.*)$/s;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

/**
 * `s` without the ASCII spaces, tabs and CRs around it, and nothing else: not a BOM, an NBSP or other
 * Unicode space (as `String#trim` would), so every port reads the same output the same way.
 */
function trimSpireSpace(s: string): string {
  return s.replace(/^[ \t\r]+|[ \t\r]+$/g, "");
}

/**
 * The first JWT-SVID in the output of `spire-agent api fetch jwt`, or `undefined`.
 *
 * SPIRE prints each SVID as `token(<spiffe id>):` with the JWT on the next, tab-indented line, then
 * `hint(<spiffe id>):` and `bundle(<trust domain>):` sections laid out the same way. The single-line form
 * `token(<spiffe id>): <jwt>` and a bare JWT line are accepted too. Only a syntactically valid compact JWS
 * is returned; the values of hint and bundle sections are skipped. A label with no value takes the next
 * line as its value only if that line is not itself a label. Only ASCII space, tab and CR around a line or
 * value are ignored.
 */
function parseSpireJwtOutput(out: string): string | undefined {
  const lines = out.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = trimSpireSpace(lines[i]);
    const section = SPIRE_SECTION.exec(line);
    if (!section) {
      if (isCompactJws(line)) return line; // a bare compact JWT line
      continue;
    }
    let value = trimSpireSpace(section[2]);
    if (!value && i + 1 < lines.length) {
      // the value is on the next line, unless that is another label
      const following = trimSpireSpace(lines[i + 1]);
      if (!SPIRE_SECTION.test(following)) {
        value = following;
        i++;
      }
    }
    if (section[1] === "token" && isCompactJws(value)) return value;
  }
  return undefined;
}

/**
 * Three non-empty base64url segments whose first is the canonical encoding of a strict JSON object (the
 * token validator's reader) with a non-empty string `alg`. It verifies nothing; it tells a JWT from a
 * version string or log line.
 */
function isCompactJws(s: string): boolean {
  const parts = s.split(".");
  if (parts.length !== 3 || !parts.every((p) => BASE64URL.test(p))) return false;
  try {
    const alg = parseObject(decodeSegment(parts[0]), "header").alg;
    return typeof alg === "string" && alg !== "";
  } catch (err) {
    if (err instanceof Malformed) return false;
    throw err;
  }
}
