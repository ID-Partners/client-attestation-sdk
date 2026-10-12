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
});
