/**
 * Pluggable sources for a workload's SPIFFE JWT-SVID — the infra-identity input to attestation
 * bootstrapping ({@link AttestationIssuanceClient}). The default {@link SpireWorkloadApiSvidSource}
 * fetches it from a real SPIRE agent; the others cover dev and tests.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { jsonOk, request } from "./http.js";

const execFileAsync = promisify(execFile);
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

/** GET a URL returning `{"svid":"<jwt>"}` — e.g. the demo harness `/dev/svid` endpoint. */
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
 */
export class SpireWorkloadApiSvidSource implements SvidSource {
  constructor(
    private readonly socketPath = "/tmp/spire-agent/public/api.sock",
    private readonly spireAgentBin = "spire-agent",
  ) {}

  async fetch(audience: string): Promise<string> {
    const { stdout } = await execFileAsync(this.spireAgentBin, [
      "api", "fetch", "jwt", "-audience", audience, "-socketPath", this.socketPath,
    ]);
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
