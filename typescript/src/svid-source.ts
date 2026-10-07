/**
 * Pluggable sources for a workload's SPIFFE JWT-SVID — the infra-identity input to attestation
 * bootstrapping ({@link AttestationIssuanceClient}). The default {@link SpireWorkloadApiSvidSource}
 * fetches it from a real SPIRE agent; the others cover dev and tests.
 */
import { jsonOk, request } from "./http.js";
import { importNodeBuiltin } from "./runtime.js";

/** Per-call timeout for {@link HttpSvidSource}. */
const HTTP_SVID_TIMEOUT_MS = 20_000;

/** Anything that can produce a compact JWT-SVID for an audience. */
export interface SvidSource {
  fetch(audience: string): Promise<string>;
}

/** A fixed, pre-fetched SVID — for tests, or when the caller already holds one. */
export class StaticSvidSource implements SvidSource {
  constructor(private readonly svid: string) {}
  async fetch(_audience: string): Promise<string> {
    return this.svid;
  }
}

/**
 * GET a URL returning `{"svid":"<jwt>"}` — e.g. the demo harness `/dev/svid` endpoint.
 *
 * For development and testing only. It trusts whatever the URL returns and the endpoint has no caller
 * authentication, so anyone who can reach it can obtain the workload's SVID. In production use a SPIRE,
 * file or cloud source.
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
 * subprocess.
 *
 * Needs Node.js (it spawns a process): `node:child_process` is loaded on the first `fetch`, which throws
 * a `ClientAttestationError` on a runtime without it.
 */
export class SpireWorkloadApiSvidSource implements SvidSource {
  constructor(
    private readonly socketPath = "/tmp/spire-agent/public/api.sock",
    private readonly spireAgentBin = "spire-agent",
  ) {}

  async fetch(audience: string): Promise<string> {
    const { execFile } = await importNodeBuiltin<typeof import("node:child_process")>(
      "child_process",
      "SpireWorkloadApiSvidSource",
    );
    const stdout = await new Promise<string>((resolve, reject) => {
      execFile(
        this.spireAgentBin,
        ["api", "fetch", "jwt", "-audience", audience, "-socketPath", this.socketPath],
        (err, out) => (err ? reject(err) : resolve(String(out))),
      );
    });
    for (let line of stdout.split("\n")) {
      line = line.trim();
      if (line.startsWith("token(")) {
        const idx = line.indexOf("):");
        if (idx >= 0) return line.slice(idx + 2).trim();
      }
      if ((line.match(/\./g) ?? []).length === 2) return line;
    }
    throw new Error(`could not parse SVID from spire-agent output:\n${stdout}`);
  }
}
