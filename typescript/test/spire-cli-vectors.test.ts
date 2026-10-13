/**
 * The SPIRE CLI source against the shared cases (vectors/spire-cli.json): a fake spire-agent that starts a
 * helper holding its stdout. Every port must agree.
 */
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { EvidenceNotFound, SpireWorkloadApiSvidSource } from "../src/index.js";

const VECTORS = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "vectors");

interface SpireCliCase {
  name: string;
  script: string;
  token?: string;
  error?: string;
  not_found?: string;
  max_ms: number;
}

const cases: SpireCliCase[] = JSON.parse(readFileSync(join(VECTORS, "spire-cli.json"), "utf8")).cases;

describe.skipIf(process.platform === "win32")("shared SPIRE CLI vectors", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "spire-cli-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it.each(cases.map((c) => [c.name, c] as const))(
    "%s",
    async (name, c) => {
      const bin = join(dir, "spire-agent");
      writeFileSync(bin, "#!/bin/sh\n" + c.script);
      chmodSync(bin, 0o755);
      const started = Date.now();
      const outcome = await new SpireWorkloadApiSvidSource("/s", bin).fetch("aud").catch((e: unknown) => e);
      const elapsed = Date.now() - started;
      console.log(`${name}: ${elapsed}ms`);
      if (c.token !== undefined) {
        expect(outcome).toBe(c.token);
      } else if (c.error !== undefined) {
        expect(outcome).toBeInstanceOf(Error);
        expect((outcome as Error).message).toBe(c.error);
      } else {
        expect(outcome).toBeInstanceOf(EvidenceNotFound);
        expect((outcome as Error).message).toBe(c.not_found);
      }
      expect(elapsed).toBeLessThanOrEqual(c.max_ms);
    },
    40_000,
  );

  // Not in spire-cli.json: these need a helper's output to pass the cap, or the grace period to end, after
  // the agent has exited, and in Java the JDK closes the pipe as the agent exits, so a helper's later output
  // never arrives there (Java tests its reader for these cases directly).
  const SVID = cases[0].token as string;
  const HEAD = "token(spiffe://example.org/wl): ";
  // The signature's first 10 characters: still a compact JWS, so only the newline rule keeps it out.
  const CUT = SVID.slice(0, SVID.lastIndexOf(".") + 11);
  const FILLER = (1 << 20) - 1 - HEAD.length - CUT.length;

  async function fetchWith(body: string): Promise<{ outcome: unknown; elapsed: number }> {
    const bin = join(dir, "spire-agent");
    writeFileSync(bin, "#!/bin/sh\n" + body);
    chmodSync(bin, 0o755);
    const started = Date.now();
    const outcome = await new SpireWorkloadApiSvidSource("/s", bin).fetch("aud").catch((e: unknown) => e);
    return { outcome, elapsed: Date.now() - started };
  }

  it("a token line cut off at the cap after the agent exits is not taken", async () => {
    const { outcome, elapsed } = await fetchWith(
      `(sleep 0.1; head -c ${FILLER} /dev/zero | tr '\\0' x; printf '\\n${HEAD}%s\\n' '${SVID}'; ` +
        "head -c 2000000 /dev/zero | tr '\\0' x) &\nexit 0\n",
    );
    console.log(`token cut off at the cap: ${elapsed}ms`);
    expect(outcome).toBeInstanceOf(EvidenceNotFound);
    expect((outcome as Error).message).toBe(
      "could not parse a JWT-SVID from spire-agent output (1048576 bytes, 2 lines; not shown)",
    );
    expect(elapsed).toBeLessThan(3000);
  });

  it("a last line without a newline is not taken when the grace period ends", async () => {
    const { outcome, elapsed } = await fetchWith(`(printf '${HEAD}%s' '${SVID}'; sleep 4) &\nexit 0\n`);
    console.log(`unterminated line, helper holds stdout: ${elapsed}ms`);
    expect(outcome).toBeInstanceOf(EvidenceNotFound);
    expect((outcome as Error).message).toBe(
      "could not parse a JWT-SVID from spire-agent output (267 bytes, 1 lines; not shown)",
    );
    expect(elapsed).toBeLessThan(3000);
  });

  it("a last line without a newline counts when stdout ends", async () => {
    const { outcome } = await fetchWith(`printf '${HEAD}%s' '${SVID}'\nexit 0\n`);
    expect(outcome).toBe(SVID);
  });
});
