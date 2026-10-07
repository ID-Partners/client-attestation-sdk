// `npm run test:edge`: run the SDK in a real Workers runtime, not a simulation.
//
// Bundles worker.mjs (which imports the SDK, the validator and validation/tokens.json) for a neutral,
// non-Node platform as wrangler would, then runs it with `workerd test` with Node compatibility switched
// off, so no Node builtin or global is available. A non-zero exit fails CI.
//
// At recent compatibility dates (2026-09-01 has it, 2026-07-01 does not) workerd turns Node compatibility
// on by default (it defines `process` and
// `Buffer`), so the config opts out explicitly with `no_nodejs_compat` and `no_nodejs_compat_v2`; worker.mjs
// asserts both globals are absent, so a workerd upgrade that changes this fails loudly.
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";
import workerd from "workerd";

const HERE = dirname(fileURLToPath(import.meta.url));
// pinned rather than workerd's newest date, so a workerd bump alone does not change runtime behaviour
const COMPATIBILITY_DATE = "2026-10-01";

const result = await build({
  entryPoints: [join(HERE, "worker.mjs")],
  bundle: true,
  platform: "neutral",
  format: "esm",
  target: "es2022",
  conditions: ["workerd", "worker", "browser"],
  mainFields: ["module", "main"],
  write: false,
  logLevel: "error",
});

const work = mkdtempSync(join(tmpdir(), "ca-workerd-"));
try {
  writeFileSync(join(work, "worker.js"), result.outputFiles[0].text);
  writeFileSync(
    join(work, "config.capnp"),
    `using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [ (name = "edge-check", worker = .worker) ],
);

const worker :Workerd.Worker = (
  modules = [ (name = "worker", esModule = embed "worker.js") ],
  compatibilityDate = "${COMPATIBILITY_DATE}",
  compatibilityFlags = [ "no_nodejs_compat", "no_nodejs_compat_v2" ],
);
`,
  );

  // the package's default export is the path of the platform binary it installed
  const bin = workerd.default;
  console.log(`workerd ${workerd.version}, compatibility date ${COMPATIBILITY_DATE}, no nodejs_compat`);
  const run = spawnSync(bin, ["test", "--verbose", join(work, "config.capnp")], {
    stdio: "inherit",
    timeout: 60_000,
  });
  if (run.error) throw run.error;
  process.exitCode = run.status ?? 1;
} finally {
  rmSync(work, { recursive: true, force: true });
}
