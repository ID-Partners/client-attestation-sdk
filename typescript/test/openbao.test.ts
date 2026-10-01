import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";
import type { AddressInfo } from "node:net";

import { decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { ClientAttestationBuilder, OpenBaoTransitSigner, SigningKeyPair } from "../src/index.js";

const KEY_NAME = "attestation-es256";
const TOKEN = "unit-test-token";

/** In-process fake of the OpenBao transit API surface, holding a real P-256 key. */
class FakeBao {
  readonly token: string;
  readonly #server: Server;
  readonly #privateKey: KeyObject;
  readonly #publicKey: KeyObject;
  #port = 0;

  constructor(token = TOKEN) {
    this.token = token;
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.#privateKey = privateKey;
    this.#publicKey = publicKey;
    this.#server = createServer((req, res) => this.#handle(req, res));
  }

  async start(): Promise<void> {
    await new Promise<void>((resolve) => this.#server.listen(0, "127.0.0.1", resolve));
    this.#port = (this.#server.address() as AddressInfo).port;
  }

  get url(): string {
    return `http://127.0.0.1:${this.#port}`;
  }

  close(): void {
    this.#server.close();
  }

  #handle(req: IncomingMessage, res: ServerResponse): void {
    if (req.headers["x-vault-token"] !== this.token) {
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end('{"errors":["permission denied"]}');
      return;
    }
    if (req.method === "GET") {
      const pem = this.#publicKey.export({ type: "spki", format: "pem" }) as string;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ data: { type: "ecdsa-p256", latest_version: 1, keys: { "1": { public_key: pem } } } }));
      return;
    }
    let body = "";
    req.on("data", (chunk: Buffer) => (body += chunk));
    req.on("end", () => {
      const parsed = JSON.parse(body || "{}");
      if (parsed.marshaling_algorithm !== "jws") {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end('{"errors":["expected marshaling_algorithm=jws"]}');
        return;
      }
      const input = Buffer.from(parsed.input, "base64");
      const raw = cryptoSign("sha256", input, { key: this.#privateKey, dsaEncoding: "ieee-p1363" });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ data: { signature: `vault:v1:${raw.toString("base64url")}`, key_version: 1 } }));
    });
  }
}

describe("OpenBao transit signer", () => {
  let bao: FakeBao;

  beforeEach(async () => {
    bao = new FakeBao();
    await bao.start();
  });

  afterEach(() => bao.close());

  it("derives an EC public JWK and kid from key metadata", async () => {
    const signer = await OpenBaoTransitSigner.create(bao.url, TOKEN, KEY_NAME);
    const jwk = signer.publicJwk();
    expect(signer.algorithm).toBe("ES256");
    expect(jwk.kty).toBe("EC");
    expect(jwk.crv).toBe("P-256");
    expect(jwk.kid).toBe(signer.keyId);
    expect(jwk.alg).toBe("ES256");
  });

  it("signs an attestation inside the vault that verifies against the derived key", async () => {
    const signer = await OpenBaoTransitSigner.create(bao.url, TOKEN, KEY_NAME);
    const instance = await SigningKeyPair.generate("ES256");
    const attestation = await new ClientAttestationBuilder(signer, "https://attester.example.com")
      .clientId("https://rp.example.com")
      .confirmationKey(instance)
      .expiresIn(300)
      .build();

    const publicKey = await importJWK(signer.publicJwk(), "ES256");
    const { payload } = await jwtVerify(attestation, publicKey);
    expect(payload.iss).toBe("https://attester.example.com");
    expect(payload.sub).toBe("https://rp.example.com");
    expect((payload.cnf as { jwk: { x: string } }).jwk.x).toBe(instance.publicJwk().x);

    const header = decodeProtectedHeader(attestation);
    expect(header.typ).toBe("oauth-client-attestation+jwt");
    expect(header.kid).toBe(signer.keyId);
  });

  it("fails closed on a wrong token", async () => {
    await expect(OpenBaoTransitSigner.create(bao.url, "wrong-token", KEY_NAME)).rejects.toThrow();
  });

  it("fails closed when the vault is unreachable", async () => {
    const signer = await OpenBaoTransitSigner.create(bao.url, TOKEN, KEY_NAME);
    bao.close();
    await expect(signer.sign(new TextEncoder().encode("header.payload"))).rejects.toThrow();
  });
});
