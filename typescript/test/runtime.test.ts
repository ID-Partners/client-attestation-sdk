/**
 * The runtime-neutral helpers behind edge support, and how the Node-only features fail on a runtime
 * that lacks the Node builtin they need.
 */
import { afterEach, describe, expect, it, vi } from "vitest";

import { ClientAttestationError } from "../src/errors.js";
import { base64Encode, envVar, importNodeBuiltin, utf8Decode, utf8Encode } from "../src/runtime.js";

describe("runtime helpers", () => {
  it("base64-encodes like Buffer, including inputs larger than one chunk", () => {
    const big = new Uint8Array(0x8000 * 2 + 7).map((_, i) => (i * 31) & 0xff);
    for (const bytes of [new Uint8Array(), utf8Encode("héllo wörld"), big]) {
      expect(base64Encode(bytes)).toBe(Buffer.from(bytes).toString("base64"));
    }
  });

  it("decodes malformed UTF-8 to U+FFFD rather than throwing", () => {
    expect(utf8Decode(new Uint8Array([0x61, 0xff, 0x62]))).toBe("a�b");
  });

  it("reads an environment variable, and answers undefined with no process global", () => {
    process.env.CA_RUNTIME_TEST = "x";
    try {
      expect(envVar("CA_RUNTIME_TEST")).toBe("x");
      vi.stubGlobal("process", undefined);
      expect(envVar("CA_RUNTIME_TEST")).toBeUndefined();
    } finally {
      vi.unstubAllGlobals();
      delete process.env.CA_RUNTIME_TEST;
    }
  });

  it("loads a Node builtin lazily", async () => {
    const os = await importNodeBuiltin<typeof import("node:os")>("os", "test");
    expect(typeof os.platform).toBe("function");
  });

  it("names the feature when the runtime has no such builtin", async () => {
    const err = await importNodeBuiltin("no-such-builtin", "SomeFeature").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ClientAttestationError);
    expect((err as Error).message).toBe(
      "SomeFeature needs the Node.js module 'node:no-such-builtin', which this runtime does not provide",
    );
  });
});

describe("Node-only features on a runtime without Node builtins", () => {
  afterEach(() => {
    vi.doUnmock("../src/runtime.js");
    vi.resetModules();
  });

  async function withoutBuiltins() {
    vi.resetModules();
    vi.doMock("../src/runtime.js", async (importOriginal) => {
      const actual = await importOriginal<typeof import("../src/runtime.js")>();
      return {
        ...actual,
        importNodeBuiltin: (name: string, feature: string) => actual.importNodeBuiltin("missing-" + name, feature),
      };
    });
    return import("../src/index.js");
  }

  it("SpireWorkloadApiSvidSource and FileTokenSvidSource throw ClientAttestationError on fetch", async () => {
    const sdk = await withoutBuiltins();
    const spire = await new sdk.SpireWorkloadApiSvidSource().fetch("aud").catch((e: unknown) => e);
    expect(spire).toBeInstanceOf(sdk.ClientAttestationError);
    expect((spire as Error).message).toContain("SpireWorkloadApiSvidSource");
    const file = await new sdk.FileTokenSvidSource("/x").fetch("aud").catch((e: unknown) => e);
    expect(file).toBeInstanceOf(sdk.ClientAttestationError);
    expect((file as Error).message).toContain("FileTokenSvidSource");
  });

  it("autoDetectEvidence treats every file and socket source as absent", async () => {
    const sdk = await withoutBuiltins();
    const saved = { ...process.env };
    try {
      delete process.env[sdk.ENV_SVID];
      delete process.env[sdk.ENV_TOKEN_FILE];
      process.env[sdk.ENV_SPIFFE_SOCKET] = `unix://${process.cwd()}`; // exists, but cannot be seen
      const err = await sdk.autoDetectEvidence().catch((e: unknown) => e);
      expect(err).toBeInstanceOf(sdk.EvidenceNotFound);
      expect((err as Error).message).toContain(sdk.ENV_SPIFFE_SOCKET);
    } finally {
      process.env = saved;
    }
  });
});
