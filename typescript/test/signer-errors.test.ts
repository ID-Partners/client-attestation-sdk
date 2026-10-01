import { generateKeyPairSync } from "node:crypto";

import { afterEach, describe, expect, it, vi } from "vitest";

import { OpenBaoTransitSigner } from "../src/index.js";

const PEM = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({
  type: "spki",
  format: "pem",
}) as string;

const METADATA = {
  data: { type: "ecdsa-p256", latest_version: 1, keys: { "1": { public_key: PEM } } },
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

describe("OpenBao transit signer error paths", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("rejects transit keys with unsupported types for JWS signing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse({ data: { type: "rsa-2048", latest_version: 1, keys: {} } }),
      ),
    );
    await expect(OpenBaoTransitSigner.create("https://bao.example.com", "t", "k")).rejects.toThrow(
      "unsupported type for JWS signing: rsa-2048",
    );
  });

  it("wraps non-Error fetch failures as 'OpenBao unreachable'", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        // eslint-disable-next-line @typescript-eslint/no-throw-literal
        throw "socket hang up";
      }),
    );
    await expect(OpenBaoTransitSigner.create("https://bao.example.com", "t", "k")).rejects.toThrow(
      "OpenBao unreachable at https://bao.example.com: socket hang up",
    );
  });

  it("rejects a 200 response that carries no data", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({})));
    await expect(OpenBaoTransitSigner.create("https://bao.example.com", "t", "k")).rejects.toThrow(
      "OpenBao response carried no data",
    );
  });

  it("rejects a sign response without a signature", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(jsonResponse(METADATA))
        .mockResolvedValueOnce(jsonResponse({ data: { key_version: 1 } })),
    );
    const signer = await OpenBaoTransitSigner.create("https://bao.example.com/", "t", "k");
    await expect(signer.sign(new TextEncoder().encode("header.payload"))).rejects.toThrow(
      "transit sign response carried no signature",
    );
  });
});
