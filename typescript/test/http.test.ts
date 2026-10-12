/**
 * The shared HTTP transport (src/http.ts): timeouts, no redirects, a body-size cap enforced while
 * streaming, and typed errors — exercised against real local servers on 127.0.0.1, then through the
 * call sites that use it.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { type AddressInfo } from "node:net";

import { afterEach, describe, expect, it, vi } from "vitest";

import { displayUrl, hasUserinfo, jsonOk, parseJsonObject, request, DEFAULT_MAX_BYTES } from "../src/http.js";
import {
  AttestationIssuanceClient,
  ClientAttestation,
  ClientAttestationError,
  GoogleMetadataSvidSource,
  HttpSvidSource,
  IssuanceError,
  OpenBaoTransitSigner,
  StaticSvidSource,
  TransportError,
} from "../src/index.js";
import { jwtSub } from "../src/token-source.js";

const AUD = "https://attester.example"; // the evidence_audience the fake attester's discovery document names

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

const servers: Server[] = [];

async function serve(handler: Handler): Promise<string> {
  const server = createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

afterEach(async () => {
  vi.unstubAllGlobals();
  await Promise.all(
    servers.splice(0).map(
      (s) =>
        new Promise<void>((resolve) => {
          s.closeAllConnections();
          s.close(() => resolve());
        }),
    ),
  );
});

async function transportError(p: Promise<unknown>): Promise<TransportError> {
  const err = await p.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(TransportError);
  expect(err).toBeInstanceOf(ClientAttestationError);
  return err as TransportError;
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

describe("request", () => {
  it("returns status, headers and body, and sends method, headers and body", async () => {
    let seen: { method?: string; header?: string; body?: string } = {};
    const url = await serve((req, res) => {
      let body = "";
      req.on("data", (c: Buffer) => (body += c));
      req.on("end", () => {
        seen = { method: req.method, header: req.headers["x-test"] as string, body };
        res.writeHead(201, { "X-Reply": "yes" });
        res.end("created");
      });
    });
    const res = await request(url, { method: "PUT", headers: { "X-Test": "1" }, body: "payload" });
    expect(res).toMatchObject({ status: 201, ok: true, body: "created", method: "PUT", url });
    expect(res.headers.get("x-reply")).toBe("yes");
    expect(seen).toEqual({ method: "PUT", header: "1", body: "payload" });
  });

  it("returns a non-2xx response without throwing", async () => {
    const url = await serve((_req, res) => json(res, 400, { error: "invalid_client" }));
    const res = await request(url);
    expect(res.status).toBe(400);
    expect(res.ok).toBe(false);
    expect(JSON.parse(res.body)).toEqual({ error: "invalid_client" });
  });

  it("refuses a redirect and never contacts the target", async () => {
    let targetHits = 0;
    const target = await serve((_req, res) => {
      targetHits += 1;
      json(res, 200, { stolen: true });
    });
    const url = await serve((_req, res) => {
      res.writeHead(302, { Location: target + "/collect" });
      res.end();
    });
    const err = await transportError(
      request(url, { method: "POST", headers: { Authorization: "Bearer secret" }, body: "x" }),
    );
    expect(err.kind).toBe("redirect");
    expect(err.status).toBe(302);
    expect(targetHits).toBe(0);
  });

  it("refuses a body over the cap while streaming (no content-length)", async () => {
    let wrote = 0;
    const url = await serve((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/octet-stream" }); // chunked: no content-length
      const chunk = Buffer.alloc(64 * 1024, 0x61);
      const pump = () => {
        while (wrote < 8 * 1024 * 1024) {
          wrote += chunk.length;
          if (!res.write(chunk)) return void res.once("drain", pump);
        }
        res.end();
      };
      res.on("error", () => undefined);
      pump();
    });
    const err = await transportError(request(url));
    expect(err.kind).toBe("too_large");
    expect(err.message).toContain(`larger than ${DEFAULT_MAX_BYTES} bytes`);
    expect(wrote).toBeLessThan(8 * 1024 * 1024); // the read stopped early
  });

  it("refuses a declared content-length over the cap", async () => {
    const url = await serve((_req, res) => {
      res.writeHead(200, { "Content-Length": "2048" });
      res.end("y".repeat(2048));
    });
    const err = await transportError(request(url, { maxBytes: 1024 }));
    expect(err.kind).toBe("too_large");
  });

  it("accepts a body exactly at the cap", async () => {
    const url = await serve((_req, res) => res.end("z".repeat(1024)));
    expect((await request(url, { maxBytes: 1024 })).body).toHaveLength(1024);
  });

  it("times out when the server never answers", async () => {
    const url = await serve(() => undefined);
    const err = await transportError(request(url, { timeoutMs: 100 }));
    expect(err.kind).toBe("timeout");
    expect(err.message).toContain("timed out after 100 ms");
  });

  it("times out when the body stalls after the headers", async () => {
    const url = await serve((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.write('{"partial":');
    });
    const err = await transportError(request(url, { timeoutMs: 150 }));
    expect(err.kind).toBe("timeout");
  });

  it("reports an unreachable host as a network error", async () => {
    const url = await serve(() => undefined);
    const dead = servers.pop() as Server;
    await new Promise<void>((resolve) => dead.close(() => resolve()));
    const err = await transportError(request(url, { timeoutMs: 2000 }));
    expect(err.kind).toBe("network");
    expect(err.message).toContain(`GET ${url} failed`);
  });

  it("refuses a URL with userinfo without naming the userinfo or contacting the host", async () => {
    let hits = 0;
    const url = await serve((_req, res) => {
      hits += 1;
      res.end();
    });
    const withUser = url.replace("://", "://alice:s3cret@");
    for (const target of [`${withUser}/x?q=1`, "https://alice:s3cret@example.invalid/x", "https://alice@example.invalid/"]) {
      const err = await transportError(request(target));
      expect(err.message).toContain("userinfo");
      expect(err.message).not.toContain("s3cret");
      expect(err.message).not.toContain("alice");
    }
    expect(hits).toBe(0);
  });

  it("keeps the query out of error messages", async () => {
    const url = await serve((_req, res) => json(res, 401, { error: "invalid_client" }));
    const err = await transportError(request(`${url}/token?client_secret=s3cret#frag`).then((r) => jsonOk(r)));
    expect(err.message).toContain(`GET ${url}/token returned HTTP 401`);
    expect(err.message).not.toContain("s3cret");
    const dead = await serve(() => undefined);
    const server = servers.pop() as Server;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    const net = await transportError(request(`${dead}/x?code=s3cret`, { timeoutMs: 2000 }));
    expect(net.message).toContain(`GET ${dead}/x failed`);
    expect(net.message).not.toContain("s3cret");
  });

  it("treats an opaque redirect from a stand-in fetch as a redirect", async () => {
    vi.stubGlobal("fetch", async () => ({ type: "opaqueredirect", status: 0, body: null }));
    expect((await transportError(request("https://x.example"))).kind).toBe("redirect");
  });

  it("caps a body read without a stream (stand-in fetch)", async () => {
    vi.stubGlobal("fetch", async () => ({
      status: 200,
      headers: new Headers(),
      body: null,
      text: async () => "w".repeat(2000),
    }));
    expect((await transportError(request("https://x.example", { maxBytes: 1000 }))).kind).toBe("too_large");
  });

  it("still reports too_large when cancelling the oversized stream itself fails", async () => {
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new Uint8Array(2000));
      },
      cancel() {
        throw new Error("cancel failed");
      },
    });
    vi.stubGlobal("fetch", async () => ({ status: 200, headers: new Headers(), body }));
    expect((await transportError(request("https://x.example", { maxBytes: 1000 }))).kind).toBe("too_large");
  });

  it("reports a failure mid-read as a network error", async () => {
    vi.stubGlobal("fetch", async () => ({
      status: 200,
      headers: new Headers(),
      body: null,
      text: async () => {
        throw new Error("connection reset");
      },
    }));
    const err = await transportError(request("https://x.example"));
    expect(err.kind).toBe("network");
    expect(err.message).toContain("connection reset");
  });
});

describe("displayUrl and hasUserinfo", () => {
  it("strip userinfo, query and fragment, and spot userinfo even in an unparseable URL", () => {
    expect(displayUrl("https://alice:s3cret@as.example.com:8443/token?code=x#f")).toBe("https://as.example.com:8443/token");
    expect(displayUrl("https://as.example.com/x?u=a@b")).toBe("https://as.example.com/x");
    expect(displayUrl("https://as.example.com/a@b")).toBe("https://as.example.com/a@b");
    expect(hasUserinfo("https://alice@as.example.com/")).toBe(true);
    expect(hasUserinfo("https://as.example.com/x?u=a@b")).toBe(false);
    expect(hasUserinfo("https://a:b@[::1/x")).toBe(true); // not a valid URL
    expect(hasUserinfo("https://[::1/x")).toBe(false);
  });
});

describe("jsonOk", () => {
  it("parses a JSON object", async () => {
    const url = await serve((_req, res) => json(res, 200, { a: 1 }));
    expect(jsonOk(await request(url))).toEqual({ a: 1 });
  });

  it("throws a typed error for non-2xx, with the status and at most 512 chars of the body", async () => {
    const url = await serve((_req, res) => {
      res.writeHead(503);
      res.end("e".repeat(5000));
    });
    const err = await transportError(request(url).then((r) => jsonOk(r)));
    expect(err.kind).toBe("status");
    expect(err.status).toBe(503);
    expect(err.body).toHaveLength(512);
    expect(err.message).toContain("returned HTTP 503");
    expect(err.message.length).toBeLessThan(700);
  });

  it("throws a typed error for malformed JSON", async () => {
    const url = await serve((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end("{not json");
    });
    const err = await transportError(request(url).then((r) => jsonOk(r)));
    expect(err.kind).toBe("json");
    expect(err.status).toBe(200);
    expect(err.message).toContain("malformed JSON");
  });

  it("throws a typed error for JSON that is not an object", async () => {
    const url = await serve((_req, res) => res.end("[1,2]"));
    const res = await request(url);
    expect(() => jsonOk(res)).toThrow(TransportError);
    expect(() => parseJsonObject({ ...res, body: "null" })).toThrow("did not return a JSON object");
  });

  it("reads an empty body as {} only when allowed", async () => {
    const url = await serve((_req, res) => res.end());
    const res = await request(url);
    expect(jsonOk(res, { allowEmpty: true })).toEqual({});
    expect(() => jsonOk(res)).toThrow(TransportError);
  });
});

// ── call sites ──────────────────────────────────────────────────────────────────────────────────

describe("AttestationIssuanceClient over the transport", () => {
  const client = (url: string) =>
    AttestationIssuanceClient.create(url, "client-1", "https://attester.example", new StaticSvidSource("svid"));

  it("mints an attestation", async () => {
    const url = await serve((_req, res) => json(res, 200, { attestation: "h.p.s", expires_in: 60 }));
    const issued = await (await client(url)).bootstrap();
    expect(issued.attestation).toBe("h.p.s");
    expect(issued.expiresIn).toBe(60);
  });

  it("keeps IssuanceError for a non-2xx response", async () => {
    const url = await serve((_req, res) => json(res, 400, { error: "invalid_request" }));
    const err = await (await client(url)).bootstrap().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(IssuanceError);
    expect((err as IssuanceError).status).toBe(400);
    expect((err as IssuanceError).body).toContain("invalid_request");
  });

  it("surfaces malformed JSON as a TransportError", async () => {
    const url = await serve((_req, res) => res.end("<html>oops</html>"));
    expect((await transportError((await client(url)).bootstrap())).kind).toBe("json");
  });

  it("refuses to follow a redirect with the SVID in the body", async () => {
    let targetHits = 0;
    const target = await serve((_req, res) => {
      targetHits += 1;
      json(res, 200, { attestation: "h.p.s" });
    });
    const url = await serve((_req, res) => {
      res.writeHead(307, { Location: target });
      res.end();
    });
    expect((await transportError((await client(url)).bootstrap())).kind).toBe("redirect");
    expect(targetHits).toBe(0);
  });
});

describe("ClientAttestation over the transport", () => {
  it("surfaces malformed discovery JSON as a TransportError", async () => {
    const url = await serve((_req, res) => res.end("{"));
    const ca = new ClientAttestation(url, { evidence: new StaticSvidSource("svid"), evidenceAudience: AUD });
    expect((await transportError(ca.token())).kind).toBe("json");
  });

  it("times out a hung attester with the configured timeout", async () => {
    const url = await serve(() => undefined);
    const ca = new ClientAttestation(url, { evidence: new StaticSvidSource("svid"), evidenceAudience: AUD, timeoutMs: 100 });
    expect((await transportError(ca.discovery())).kind).toBe("timeout");
  });

  /** A fake attester whose token endpoint is supplied by the test. */
  async function attester(token: Handler): Promise<string> {
    return serve((req, res) => {
      const base = `http://${req.headers.host}`;
      req.resume();
      req.on("end", () => {
        if (req.url === "/.well-known/client-attester") {
          return json(res, 200, {
            attestation_endpoint: base + "/attest",
            challenge_endpoint: base + "/challenge",
            token_endpoint: base + "/token",
            evidence_audience: AUD,
          });
        }
        if (req.url === "/challenge") return json(res, 200, { attestation_challenge: "c" });
        if (req.url === "/attest") {
          const sub = Buffer.from(JSON.stringify({ sub: "demo" })).toString("base64url");
          return json(res, 200, { attestation: `h.${sub}.s` });
        }
        return token(req, res);
      });
    });
  }

  it("keeps the token endpoint's non-2xx error: status and full body", async () => {
    const url = await attester((_req, res) => json(res, 401, { error: "invalid_client" }));
    const ca = new ClientAttestation(url, { evidence: new StaticSvidSource("svid"), evidenceAudience: AUD });
    const err = (await ca.token().catch((e: unknown) => e)) as ClientAttestationError;
    expect(err).toBeInstanceOf(ClientAttestationError);
    expect(err).not.toBeInstanceOf(TransportError);
    expect(err.message).toBe("token endpoint returned HTTP 401");
    expect(err.status).toBe(401);
    expect(JSON.parse(err.body as string)).toEqual({ error: "invalid_client" });
  });

  it("refuses a redirect from the token endpoint (the attestation headers stay put)", async () => {
    let targetHits = 0;
    const target = await serve((_req, res) => {
      targetHits += 1;
      json(res, 200, { access_token: "stolen" });
    });
    const url = await attester((_req, res) => {
      res.writeHead(308, { Location: target });
      res.end();
    });
    const ca = new ClientAttestation(url, { evidence: new StaticSvidSource("svid"), evidenceAudience: AUD });
    expect((await transportError(ca.token())).kind).toBe("redirect");
    expect(targetHits).toBe(0);
  });

  it("surfaces a malformed token response as a TransportError", async () => {
    const url = await attester((_req, res) => res.end("not-json"));
    const ca = new ClientAttestation(url, { evidence: new StaticSvidSource("svid"), evidenceAudience: AUD });
    expect((await transportError(ca.token())).kind).toBe("json");
  });

  it("jwtSub rejects a malformed attestation with a typed error", () => {
    expect(() => jwtSub("h.!!!.s")).toThrow(ClientAttestationError);
  });
});

describe("HttpSvidSource over the transport", () => {
  it("returns the svid", async () => {
    const url = await serve((_req, res) => json(res, 200, { svid: "a.b.c" }));
    expect(await new HttpSvidSource(url).fetch("aud")).toBe("a.b.c");
  });

  it("throws a typed error for non-2xx", async () => {
    const url = await serve((_req, res) => json(res, 500, { error: "boom" }));
    const err = await transportError(new HttpSvidSource(url).fetch("aud"));
    expect(err.status).toBe(500);
  });

  it("rejects a response without an svid", async () => {
    const url = await serve((_req, res) => json(res, 200, {}));
    await expect(new HttpSvidSource(url).fetch("aud")).rejects.toThrow("no svid in response");
  });
});

describe("GoogleMetadataSvidSource over the transport", () => {
  it("sends Metadata-Flavor without following redirects and returns the token", async () => {
    const fetchMock = vi.fn(async () => new Response(" id-token \n", { headers: { "Metadata-Flavor": "Google" } }));
    vi.stubGlobal("fetch", fetchMock);
    expect(await new GoogleMetadataSvidSource().fetch("https://aud.example")).toBe("id-token");
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("audience=https%3A%2F%2Faud.example"),
      expect.objectContaining({ headers: { "Metadata-Flavor": "Google" }, redirect: "manual" }),
    );
  });

  it("throws a typed error for non-2xx", async () => {
    vi.stubGlobal("fetch", async () => new Response("nope", { status: 404 }));
    const err = await transportError(new GoogleMetadataSvidSource().fetch("aud"));
    expect(err.status).toBe(404);
  });
});

describe("OpenBaoTransitSigner over the transport", () => {
  it("reports a hung vault as unreachable (timeout)", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new DOMException("The operation was aborted due to timeout", "TimeoutError");
    });
    const err = await transportError(OpenBaoTransitSigner.create("https://bao.example", "t", "k"));
    expect(err.kind).toBe("timeout");
    expect(err.message).toBe("OpenBao unreachable at https://bao.example: timed out after 5000 ms");
  });

  it("does not follow a redirect with the vault token", async () => {
    let targetHits = 0;
    const target = await serve((_req, res) => {
      targetHits += 1;
      json(res, 200, { data: {} });
    });
    const url = await serve((_req, res) => {
      res.writeHead(301, { Location: target });
      res.end();
    });
    expect((await transportError(OpenBaoTransitSigner.create(url, "t", "k"))).kind).toBe("redirect");
    expect(targetHits).toBe(0);
  });

  it("reports a non-200 with the status", async () => {
    const url = await serve((_req, res) => json(res, 403, { errors: ["permission denied"] }));
    const err = await transportError(OpenBaoTransitSigner.create(url, "t", "k"));
    expect(err.status).toBe(403);
    expect(err.message).toBe("OpenBao returned HTTP 403 for /v1/transit/keys/k");
  });

  it("reports malformed JSON as a typed error", async () => {
    const url = await serve((_req, res) => res.end("{oops"));
    expect((await transportError(OpenBaoTransitSigner.create(url, "t", "k"))).kind).toBe("json");
  });
});
