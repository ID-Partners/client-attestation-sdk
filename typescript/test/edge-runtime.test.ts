/**
 * The package must load and work on edge runtimes (Cloudflare Workers, Vercel Edge, Deno Deploy without
 * Node compatibility). Two checks:
 *
 * 1. Bundle both entry points with esbuild for a neutral (non-Node) platform, as an edge bundler would.
 *    A static import of a Node builtin anywhere in the graph fails to resolve, so the build fails.
 * 2. Run that bundle in a child Node process with the Node-only globals (`process`, `Buffer`, `require`)
 *    removed before it loads, and drive the builders and the validator through it.
 *
 * Both are a simulation in Node. `npm run test:edge` (test/edge/) runs the same bundle in workerd, the real
 * Cloudflare Workers runtime, in CI.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { build, type BuildOptions } from "esbuild";
import { afterAll, describe, expect, it } from "vitest";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const VECTORS = readFileSync(join(ROOT, "..", "validation", "tokens.json"), "utf8");

// what wrangler and other edge bundlers use: no Node platform, worker/browser export conditions
const EDGE: BuildOptions = {
  bundle: true,
  platform: "neutral",
  format: "esm",
  target: "es2022",
  conditions: ["workerd", "worker", "browser"],
  mainFields: ["module", "main"],
  write: false,
  logLevel: "silent",
};

const work = mkdtempSync(join(tmpdir(), "ca-edge-"));
afterAll(() => rmSync(work, { recursive: true, force: true }));

async function bundle(entry: string): Promise<string> {
  const result = await build({ ...EDGE, entryPoints: [join(ROOT, entry)] });
  expect(result.errors).toEqual([]);
  return result.outputFiles[0]!.text;
}

const CHILD = `
// Node loads its own web globals (undici) lazily, and that code reads Buffer: load them first
void [fetch, Headers, Request, Response];
for (const name of ["process", "Buffer", "require"]) delete globalThis[name];
if (typeof process !== "undefined" || typeof Buffer !== "undefined") throw new Error("Node globals still present");

const sdk = await import("./sdk.mjs");
const v = await import("./validator.mjs");
const vectors = ${VECTORS};

const attester = await sdk.SigningKeyPair.generate("ES256");
const instance = await sdk.SigningKeyPair.generate("ES256");
const attestation = await new sdk.ClientAttestationBuilder(attester, "https://attester.example.com")
  .clientId("https://rp.example.com").confirmationKey(instance).expiresIn(300).build();
const pop = await new sdk.PopBuilder(instance).clientId("https://rp.example.com").audience("https://as.example.com").build();
const dpop = await new sdk.DpopProofBuilder(instance)
  .method("GET").uri("https://api.example.com/things?q=1").accessToken("token-abc").build();
const dpopClaims = JSON.parse(atob(dpop.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));

function validatorFor(v, vectors, c) {
  // the shared config plus the case's overrides (present wins, even when empty), key set and clock; a case
  // with a fetch error gets a jwksUri whose fetch fails
  const o = c.config ?? {};
  const fetchError = c.jwks_fetch_error;
  const cfg = {
    issuer: vectors.issuer,
    audiences: [vectors.audience],
    jwks: fetchError === undefined ? (c.jwks ?? vectors.jwks) : undefined,
    jwksUri: fetchError === undefined ? undefined : "https://keys.internal.example:8443/jwks",
    requiredScopes: vectors.required_scopes,
    acceptedAlgorithms: vectors.accepted_algorithms,
  };
  if ("accepted_algorithms" in o) cfg.acceptedAlgorithms = o.accepted_algorithms;
  if ("accepted_token_types" in o) cfg.acceptedTokenTypes = o.accepted_token_types;
  if ("leeway_seconds" in o) cfg.leewaySeconds = o.leeway_seconds;
  const httpGet = async () => {
    throw new Error(fetchError);
  };
  return new v.AccessTokenValidator(cfg, c.now === undefined ? { httpGet } : { httpGet, clock: () => c.now * 1000 });
}
const verdicts = [];
for (const c of vectors.cases) {
  const r = await validatorFor(v, vectors, c).validate(c.token);
  verdicts.push([r.valid ? "valid" : r.error, c.expect]);
}

let envDetect;
try { await sdk.autoDetectEvidence({ gcpMetadataBase: "http://127.0.0.1:9" }); } catch (e) { envDetect = e.name; }

// a stand-in fetch, so the shared HTTP transport (timeouts, capped streaming read) runs too. Not Node's
// Response: its implementation reads Buffer, which is gone.
const svidBody = new TextEncoder().encode(JSON.stringify({ svid: "a.b.c" }));
globalThis.fetch = async () => ({
  status: 200,
  type: "basic",
  headers: new Headers(),
  body: new ReadableStream({ start(c) { c.enqueue(svidBody); c.close(); } }),
});
const svid = await new sdk.HttpSvidSource("https://harness.example.com/dev/svid").fetch("aud");


console.log("EDGE_RESULT " + JSON.stringify({
  sub: JSON.parse(atob(attestation.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))).sub,
  parts: [attestation, pop, dpop].map((j) => j.split(".").length),
  ath: dpopClaims.ath,
  htu: dpopClaims.htu,
  verdicts,
  svid,
  envDetect,
}));
`;

describe("edge runtime", () => {
  it("control: a static Node builtin import fails the neutral-platform build", async () => {
    const entry = join(work, "control.ts");
    writeFileSync(entry, 'import { readFileSync } from "node:fs";\nexport const f = readFileSync;\n');
    await expect(build({ ...EDGE, entryPoints: [entry] })).rejects.toThrow(/node:fs/);
  });

  it("bundles for a neutral platform and runs without Node globals", async () => {
    const sdk = await bundle("src/index.ts");
    const validator = await bundle("src/validator/index.ts");
    expect(sdk).not.toMatch(/from\s*["']node:/);
    expect(validator).not.toMatch(/from\s*["']node:/);
    // Node-only globals would load but throw when reached; none may be referenced at all
    for (const code of [sdk, validator]) expect(code).not.toMatch(/\b(Buffer|process|require|global)\s*[.(]/);
    writeFileSync(join(work, "sdk.mjs"), sdk);
    writeFileSync(join(work, "validator.mjs"), validator);
    writeFileSync(join(work, "child.mjs"), CHILD);

    const run = spawnSync(process.execPath, ["child.mjs"], { cwd: work, encoding: "utf8", timeout: 30_000 });
    expect(run.stderr).toBe("");
    expect(run.status).toBe(0);
    const line = run.stdout.split("\n").find((l) => l.startsWith("EDGE_RESULT "));
    const out = JSON.parse(line!.slice("EDGE_RESULT ".length));

    expect(out.sub).toBe("https://rp.example.com");
    expect(out.parts).toEqual([3, 3, 3]);
    // RFC 9449 ath: base64url(SHA-256("token-abc"))
    expect(out.ath).toBe("CWFXsznPQZ28DI3vSfwr6STcEw-6zfp7h5vuCjB4zsQ");
    expect(out.htu).toBe("https://api.example.com/things");
    for (const [got, want] of out.verdicts) expect(got).toBe(want);
    expect(out.verdicts.length).toBeGreaterThan(0);
    expect(out.svid).toBe("a.b.c");
    // no process.env: detection reports nothing found rather than crashing on the missing global
    expect(out.envDetect).toBe("EvidenceNotFound");
  }, 30_000);
});
