import { generateKeyPairSync } from "node:crypto";

import { afterEach, describe, expect, it, vi } from "vitest";

import { ClientAttestationError, OpenBaoTransitSigner } from "../src/index.js";

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

describe("OpenBao transit signer address and key name", () => {
  afterEach(() => vi.unstubAllGlobals());

  /** Answers every request with key metadata and records where it went, so nothing touches the network. */
  function recordFetch(): string[] {
    const urls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL) => {
        urls.push(String(url));
        return jsonResponse(METADATA);
      }),
    );
    return urls;
  }

  it("refuses plain http to a non-loopback vault before any request", async () => {
    // The vault token must not travel in cleartext, and a key read from whoever answers would become the
    // attester's published JWK.
    const urls = recordFetch();
    const err = await OpenBaoTransitSigner.create("http://openbao.example:8200", "t", "k").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ClientAttestationError);
    expect((err as Error).message).toContain("must use https");
    expect(urls).toEqual([]);
  });

  it("allows https and loopback vaults", async () => {
    const urls = recordFetch();
    await OpenBaoTransitSigner.create("https://openbao.example:8200/", "t", "k");
    await OpenBaoTransitSigner.create("http://localhost:8200", "t", "k");
    await OpenBaoTransitSigner.create("http://[::1]:8200", "t", "k");
    expect(urls).toEqual([
      "https://openbao.example:8200/v1/transit/keys/k",
      "http://localhost:8200/v1/transit/keys/k",
      "http://[::1]:8200/v1/transit/keys/k",
    ]);
  });

  it("lifts the https rule with allowInsecure", async () => {
    const urls = recordFetch();
    const signer = await OpenBaoTransitSigner.create("http://openbao.example:8200", "t", "k", { allowInsecure: true });
    expect(signer.algorithm).toBe("ES256");
    expect(urls).toEqual(["http://openbao.example:8200/v1/transit/keys/k"]);
  });

  it.each(["../../sys/raw/x", "k/../../../sys/seal", "k?x=1", "k#frag", "a/b", "%2e%2e", ".", "..", "", "k y", "k\n"])(
    "refuses the key name %j before any request",
    async (name) => {
      const urls = recordFetch();
      await expect(OpenBaoTransitSigner.create("https://openbao.example", "t", name)).rejects.toThrow(
        "invalid transit key name",
      );
      expect(urls).toEqual([]);
    },
  );
});
