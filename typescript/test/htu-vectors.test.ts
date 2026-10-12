/** DPoP htu and nonce-origin normalisation against the shared vectors (vectors/htu.json). Every port must agree. */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";

import { htuParts, normalizeHtu } from "../src/builders.js";
import { DpopProofBuilder, SigningKeyPair } from "../src/index.js";

const VECTORS = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "vectors");

interface HtuCase {
  name: string;
  url: string;
  htu?: string;
  origin?: string;
  error?: string;
}

const cases: HtuCase[] = JSON.parse(readFileSync(join(VECTORS, "htu.json"), "utf8")).cases;

describe("shared htu vectors", () => {
  it.each(cases.map((c) => [c.name, c] as const))("%s", async (_name, c) => {
    const key = await SigningKeyPair.generate("ES256");
    const build = new DpopProofBuilder(key).uri(c.url).build();
    if (c.error !== undefined) {
      await expect(build).rejects.toThrow(new Error(c.error));
      expect(() => htuParts(c.url)).toThrow(c.error);
      return;
    }
    expect(decodeJwt(await build).htu).toBe(c.htu);
    expect(normalizeHtu(c.url)).toBe(c.htu);
    expect(htuParts(c.url)[0]).toBe(c.origin);
  });

  it("refuses a lone surrogate in the path (not in htu.json: JSON parsers disagree on one)", () => {
    expect(() => normalizeHtu("https://as.example.com/a\ud800")).toThrow("uri (htu) has an invalid path");
  });
});
