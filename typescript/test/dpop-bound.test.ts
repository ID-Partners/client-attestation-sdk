/**
 * dpop_combined end to end: a fake attester + AS that issues DPoP-bound tokens, and a fake resource that
 * verifies every proof the way an RFC 9449 resource server does (signature with the header jwk, jwk
 * thumbprint = the key the token was bound to, htm, htu, ath, nonce). Local servers only.
 */
import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { type AddressInfo } from "node:net";

import { calculateJwkThumbprint, compactVerify, decodeJwt, decodeProtectedHeader, importJWK, type JWK } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ClientAttestation,
  ClientAttestationError,
  DpopProofBuilder,
  SigningKeyPair,
  StaticSvidSource,
} from "../src/index.js";

const AUD = "https://attester.example"; // the evidence_audience the fake attester's discovery document names

const servers: Server[] = [];

describe("credential redirects", () => {
  it.each([false, true])("does not follow resource redirects, DPoP=%s", async (dpop) => {
    let targetHits = 0;
    const target = await listen((_req, res) => { targetHits++; res.end("leaked"); });
    const front = await listen((req, res) => {
      expect(req.headers.authorization).toBe(`${dpop ? "DPoP" : "Bearer"} secret`);
      res.writeHead(307, { Location: target });
      res.end();
    });
    const ca = new ClientAttestation("https://attester.example");
    vi.spyOn(ca, "requestHeaders").mockResolvedValue(dpop ? { Authorization: "DPoP secret", DPoP: "proof" } : { Authorization: "Bearer secret" });
    for (const input of [front, new Request(front, { redirect: "follow" })]) {
      const response = await ca.fetch(input, { redirect: "follow" });
      expect(response.status).toBe(307);
      await response.body?.cancel();
    }
    expect(targetHits).toBe(0);
  });

  it("refuses a plain-http resource unless it is loopback or allowInsecure is set", async () => {
    const as = await authorizationServer();
    const ca = client(as.url);
    await expect(ca.requestHeaders("GET", "http://api.example.com/things")).rejects.toThrow(
      "resource URL must use https",
    );
    await expect(ca.fetch("http://api.example.com/things")).rejects.toThrow("resource URL must use https");
    expect((await ca.requestHeaders("GET", `${as.url}/things`)).Authorization).toMatch(/^DPoP /);
    const insecure = client(as.url, { allowInsecure: true });
    expect((await insecure.requestHeaders("GET", "http://api.example.com/things")).Authorization).toMatch(/^DPoP /);
  });
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => s.close(() => r()))));
});

async function listen(handler: (req: IncomingMessage, res: ServerResponse, body: string) => void): Promise<string> {
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => handler(req, res, Buffer.concat(chunks).toString("utf8")));
  });
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

function json(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { "Content-Type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

/** Verify a DPoP proof's signature with its own header jwk; return its claims and jwk thumbprint. */
async function verifyProof(proof: string): Promise<{ claims: Record<string, unknown>; jkt: string }> {
  const header = decodeProtectedHeader(proof);
  expect(header.typ).toBe("dpop+jwt");
  const jwk = header.jwk as JWK;
  const { payload } = await compactVerify(proof, await importJWK(jwk, header.alg as string));
  return { claims: JSON.parse(new TextDecoder().decode(payload)), jkt: await calculateJwkThumbprint(jwk, "sha256") };
}

interface AsOptions {
  tokenType?: string;
  /** When set, the token endpoint demands this DPoP nonce (400 use_dpop_nonce until it gets it). */
  asNonce?: string;
}

/** Attester + AS. Records, per issued access token, the thumbprint of the key that proved possession. */
async function authorizationServer(opts: AsOptions = {}) {
  const boundKeys = new Map<string, string>();
  const tokenProofs: Record<string, unknown>[] = [];
  let minted = 0;
  const url = await listen(async (req, res, body) => {
    const base = `http://${req.headers.host}`;
    if (req.url === "/.well-known/client-attester") {
      return json(res, 200, {
        attestation_endpoint: base + "/attest",
        challenge_endpoint: base + "/challenge",
        token_endpoint: base + "/token",
        evidence_audience: AUD,
      });
    }
    if (req.url === "/challenge") return json(res, 200, { attestation_challenge: "attester-chal" });
    if (req.url === "/attest") {
      const instanceKey = JSON.parse(body).instance_key as JWK;
      const sub = Buffer.from(JSON.stringify({ sub: "demo", cnf: { jwk: instanceKey } })).toString("base64url");
      return json(res, 200, { attestation: `h.${sub}.s` });
    }
    if (req.url === "/token") {
      const { claims, jkt } = await verifyProof(req.headers["dpop"] as string);
      tokenProofs.push(claims);
      // The proof key must be the attestation's cnf key.
      const attestationClaims = decodeJwt(req.headers["oauth-client-attestation"] as string);
      const cnfJkt = await calculateJwkThumbprint((attestationClaims.cnf as { jwk: JWK }).jwk, "sha256");
      expect(jkt).toBe(cnfJkt);
      if (opts.asNonce && claims.nonce !== opts.asNonce) {
        return json(res, 400, { error: "use_dpop_nonce" }, { "DPoP-Nonce": opts.asNonce });
      }
      minted += 1;
      const accessToken = `AT-${minted}`;
      boundKeys.set(accessToken, jkt);
      return json(res, 200, { access_token: accessToken, expires_in: 3600, token_type: opts.tokenType ?? "DPoP" });
    }
    json(res, 404, { error: "not_found" });
  });
  return { url, boundKeys, tokenProofs };
}

interface ResourceOptions {
  /** Nonce challenge style: RFC 9449 401 + WWW-Authenticate (default) or a 400 JSON error. */
  style?: "401" | "400";
}

/** A DPoP resource server that requires a server nonce. */
async function resourceServer(boundKeys: Map<string, string>, opts: ResourceOptions = {}) {
  const nonce = "rs-nonce-1";
  const seen: { proof: Record<string, unknown>; jkt: string; body: string }[] = [];
  const url = await listen(async (req, res, body) => {
    const auth = req.headers.authorization ?? "";
    const [scheme, token] = auth.split(" ");
    if (scheme === "Bearer") return json(res, 200, { ok: true, scheme, token, dpop: req.headers["dpop"] ?? null });
    expect(scheme).toBe("DPoP");
    const { claims, jkt } = await verifyProof(req.headers["dpop"] as string);
    seen.push({ proof: claims, jkt, body });
    expect(jkt).toBe(boundKeys.get(token));
    expect(claims.htm).toBe(req.method);
    expect(claims.htu).toBe(`http://${req.headers.host}${(req.url as string).split("?")[0]}`);
    expect(claims.ath).toBe(createHash("sha256").update(token, "ascii").digest("base64url"));
    if (claims.nonce !== nonce) {
      if (opts.style === "400") return json(res, 400, { error: "use_dpop_nonce" }, { "DPoP-Nonce": nonce });
      res.writeHead(401, {
        "WWW-Authenticate": 'DPoP error="use_dpop_nonce", error_description="nonce required"',
        "DPoP-Nonce": nonce,
      });
      return res.end();
    }
    json(res, 200, { ok: true, jkt, body });
  });
  return { url, seen, nonce };
}

function client(asUrl: string, extra: Record<string, unknown> = {}): ClientAttestation {
  return new ClientAttestation(asUrl, {
    evidence: new StaticSvidSource("svid"), evidenceAudience: AUD,
    popMethod: "dpop_combined",
    ...extra,
  });
}

describe("dpop_combined: DPoP-bound tokens at a resource", () => {
  it("presents the token with a verified proof and retries once on a 401 nonce challenge", async () => {
    const as = await authorizationServer();
    const rs = await resourceServer(as.boundKeys);
    const ca = client(as.url);

    const res = await ca.fetch(`${rs.url}/things?page=2#frag`, { method: "post", body: "payload" });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ok: true, body: "payload" });
    // first attempt carried no nonce; the retry carried the server's, with the body resent
    expect(rs.seen.map((s) => s.proof.nonce)).toEqual([undefined, rs.nonce]);
    expect(rs.seen.map((s) => s.body)).toEqual(["payload", "payload"]);
    expect(rs.seen[0].proof.jti).not.toBe(rs.seen[1].proof.jti);

    // the nonce is remembered for that origin: the next request needs no retry
    const before = rs.seen.length;
    expect((await ca.fetch(`${rs.url}/more`)).status).toBe(200);
    expect(rs.seen.length).toBe(before + 1);
  });

  it("retries once on a 400 JSON use_dpop_nonce, with string, URLSearchParams and ArrayBuffer bodies", async () => {
    const as = await authorizationServer();
    const rs = await resourceServer(as.boundKeys, { style: "400" });
    const ca = client(as.url);
    expect((await ca.fetch(`${rs.url}/a`, { method: "PUT", body: new URLSearchParams({ a: "1" }) })).status).toBe(200);
    expect(rs.seen.map((s) => s.body)).toEqual(["a=1", "a=1"]);
    expect((await ca.fetch(`${rs.url}/b`, { method: "PUT", body: new TextEncoder().encode("bin").buffer })).status).toBe(200);
    expect(rs.seen.at(-1)?.body).toBe("bin");
  });

  it("accepts a Request as input and resends its body", async () => {
    const as = await authorizationServer();
    const rs = await resourceServer(as.boundKeys);
    const ca = client(as.url);
    const res = await ca.fetch(new Request(`${rs.url}/req`, { method: "POST", body: "from-request" }));
    expect(res.status).toBe(200);
    expect(rs.seen.map((s) => s.body)).toEqual(["from-request", "from-request"]);
  });

  it("does not retry a non-replayable stream body", async () => {
    const as = await authorizationServer();
    const rs = await resourceServer(as.boundKeys);
    const ca = client(as.url);
    const stream = new ReadableStream({
      start(c) {
        c.enqueue(new TextEncoder().encode("once"));
        c.close();
      },
    });
    const res = await ca.fetch(`${rs.url}/s`, { method: "POST", body: stream, duplex: "half" } as RequestInit);
    expect(res.status).toBe(401);
    expect(res.headers.get("DPoP-Nonce")).toBe(rs.nonce);
    expect(rs.seen.length).toBe(1);
  });

  it("retries a nonce challenge even when discarding the challenge's body fails", async () => {
    const as = await authorizationServer();
    const rs = await resourceServer(as.boundKeys);
    const ca = client(as.url);
    const realFetch = globalThis.fetch;
    let challenged = false;
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
      if (!String(input).startsWith(rs.url) || challenged) return realFetch(input, init);
      challenged = true;
      const body = new ReadableStream({
        cancel() {
          throw new Error("cancel failed");
        },
      });
      return new Response(body, {
        status: 401,
        headers: { "WWW-Authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": rs.nonce },
      });
    });
    try {
      const res = await ca.fetch(`${rs.url}/things`);
      expect(res.status).toBe(200);
      expect(rs.seen.map((s) => s.proof.nonce)).toEqual([rs.nonce]);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("returns a non-nonce failure as is, without retrying", async () => {
    const as = await authorizationServer();
    const ca = client(as.url);
    let hits = 0;
    const plain = await listen((_req, res) => {
      hits += 1;
      json(res, 403, { error: "insufficient_scope" });
    });
    expect((await ca.fetch(plain)).status).toBe(403);
    // a 401 with a Bearer challenge and a 400 without use_dpop_nonce are not nonce challenges either
    const other = await listen((req, res) => {
      hits += 1;
      if (req.url === "/bearer") {
        res.writeHead(401, { "WWW-Authenticate": 'Bearer error="use_dpop_nonce"', "DPoP-Nonce": "n" });
        return res.end();
      }
      json(res, 400, { error: "invalid_request" }, { "DPoP-Nonce": "n" });
    });
    expect((await ca.fetch(`${other}/bearer`)).status).toBe(401);
    expect((await ca.fetch(`${other}/bad`)).status).toBe(400);
    expect(hits).toBe(3);
  });

  it("remembers a DPoP-Nonce from any response, and ignores a 400 with a non-JSON body", async () => {
    const as = await authorizationServer();
    const ca = client(as.url);
    let hits = 0;
    const rs = await listen((req, res) => {
      hits += 1;
      if (req.url === "/ok") {
        res.writeHead(200, { "DPoP-Nonce": "fresh" });
        return res.end("ok");
      }
      res.writeHead(400, { "DPoP-Nonce": "n2" });
      res.end("not json");
    });
    expect((await ca.fetch(`${rs}/ok`)).status).toBe(200);
    expect(decodeJwt((await ca.requestHeaders("GET", `${rs}/next`)).DPoP).nonce).toBe("fresh");
    expect((await ca.fetch(`${rs}/bad`)).status).toBe(400);
    expect(hits).toBe(2);
    // a url with no scheme or host gets no credential
    await expect(ca.requestHeaders("GET", "relative/path")).rejects.toThrow("resource URL is not a valid URL");
  });

  it("requestHeaders gives the DPoP scheme, a proof with htm/htu/ath and the remembered nonce", async () => {
    const as = await authorizationServer();
    const rs = await resourceServer(as.boundKeys);
    const ca = client(as.url);
    const headers = await ca.requestHeaders("get", `${rs.url}/x?q=1`);
    expect(headers.Authorization).toBe("DPoP AT-1");
    const { claims } = await verifyProof(headers.DPoP);
    expect(claims.htm).toBe("GET");
    expect(claims.htu).toBe(`${rs.url}/x`);
    expect(claims.nonce).toBeUndefined();
    expect(claims.ath).toBe(createHash("sha256").update("AT-1", "ascii").digest("base64url"));

    // authorizationHeader names the DPoP scheme for a DPoP-bound token
    expect(await ca.authorizationHeader()).toEqual({ Authorization: "DPoP AT-1" });

    await ca.fetch(`${rs.url}/x`); // learns the nonce
    const again = await ca.requestHeaders("GET", `${rs.url}/y`);
    expect(decodeJwt(again.DPoP).nonce).toBe(rs.nonce);
    // nonces are per origin
    expect(decodeJwt((await ca.requestHeaders("GET", "http://127.0.0.1:1/z")).DPoP).nonce).toBeUndefined();
  });

  it("keeps the bound key while the token is cached and replaces it with the token on refresh", async () => {
    const as = await authorizationServer();
    const rs = await resourceServer(as.boundKeys);
    const ca = client(as.url);
    await ca.fetch(`${rs.url}/1`);
    await ca.fetch(`${rs.url}/2`);
    const firstKeys = new Set(rs.seen.map((s) => s.jkt));
    expect(firstKeys.size).toBe(1);
    expect(as.boundKeys.size).toBe(1);

    await ca.token({ forceRefresh: true });
    await ca.fetch(`${rs.url}/3`);
    const last = rs.seen.at(-1) as { jkt: string };
    expect(firstKeys.has(last.jkt)).toBe(false);
    expect(last.jkt).toBe(as.boundKeys.get("AT-2"));
  });

  it("retries the token request once with the AS's DPoP nonce", async () => {
    const as = await authorizationServer({ asNonce: "as-nonce" });
    const ca = client(as.url);
    expect(await ca.token()).toBe("AT-1");
    expect(as.tokenProofs.map((p) => p.nonce)).toEqual(["attester-chal", "as-nonce"]);
    expect(as.tokenProofs.map((p) => p.htu)).toEqual([`${as.url}/token`, `${as.url}/token`]);
  });

  it("does not retry a token-endpoint 400 that is not a nonce demand", async () => {
    let n = 0;
    const tokenUrl = await listen((_req, res) => {
      n += 1;
      res.writeHead(400, { "DPoP-Nonce": "x" });
      res.end("plain");
    });
    const url = await listen((req, res) => {
      if (req.url === "/.well-known/client-attester") {
        return json(res, 200, {
          attestation_endpoint: `http://${req.headers.host}/attest`,
          token_endpoint: tokenUrl + "/token",
          evidence_audience: AUD,
        });
      }
      json(res, 200, { attestation: `h.${Buffer.from('{"sub":"d"}').toString("base64url")}.s` });
    });
    await expect(client(url).token()).rejects.toMatchObject({ status: 400 });
    expect(n).toBe(1);
  });

  it("gives up after one token-endpoint nonce retry", async () => {
    // a server that keeps rotating its nonce: the client retries once, then reports the 400
    let n = 0;
    const rotating = await listen((_req, res) => {
      n += 1;
      json(res, 400, { error: "use_dpop_nonce" }, { "DPoP-Nonce": `n-${n}` });
    });
    const url = await listen((req, res, body) => {
      const base = `http://${req.headers.host}`;
      if (req.url === "/.well-known/client-attester") {
        return json(res, 200, {
          attestation_endpoint: base + "/attest",
          token_endpoint: rotating + "/token",
          evidence_audience: AUD,
        });
      }
      const sub = Buffer.from(JSON.stringify({ sub: "demo", k: body.length })).toString("base64url");
      json(res, 200, { attestation: `h.${sub}.s` });
    });
    await expect(client(url).token()).rejects.toMatchObject({ status: 400 });
    expect(n).toBe(2);
  });
});

describe("Bearer tokens are unchanged", () => {
  it("fetch and requestHeaders send only Authorization: Bearer", async () => {
    const as = await authorizationServer({ tokenType: "bearer" });
    const rs = await resourceServer(as.boundKeys);
    const ca = client(as.url);
    expect(await ca.requestHeaders("GET", rs.url)).toEqual({ Authorization: "Bearer AT-1" });
    const res = await ca.fetch(rs.url, { headers: { "X-Extra": "1" } });
    expect(await res.json()).toEqual({ ok: true, scheme: "Bearer", token: "AT-1", dpop: null });
    expect(await ca.authorizationHeader()).toEqual({ Authorization: "Bearer AT-1" });
  });

  it("treats an absent token_type as Bearer", async () => {
    const url = await listen((req, res) => {
      const base = `http://${req.headers.host}`;
      if (req.url === "/.well-known/client-attester") {
        return json(res, 200, { attestation_endpoint: base + "/attest", token_endpoint: base + "/token", evidence_audience: AUD });
      }
      if (req.url === "/attest") return json(res, 200, { attestation: `h.${Buffer.from('{"sub":"d"}').toString("base64url")}.s` });
      json(res, 200, { access_token: "AT-plain" });
    });
    const ca = new ClientAttestation(url, { evidence: new StaticSvidSource("svid"), evidenceAudience: AUD });
    expect(await ca.requestHeaders("GET", "https://api.example/x")).toEqual({ Authorization: "Bearer AT-plain" });
  });
});

describe("DpopProofBuilder normalisation", () => {
  it("upper-cases htm, strips query and fragment from htu, and sets ath", async () => {
    const key = await SigningKeyPair.generate("ES256");
    const proof = await new DpopProofBuilder(key)
      .method("patch")
      .uri("HTTPS://API.Example.com:443/a/b?x=1#frag")
      .accessToken("tok")
      .build();
    const claims = decodeJwt(proof);
    expect(claims.htm).toBe("PATCH");
    expect(claims.htu).toBe("https://api.example.com/a/b");
    expect(claims.ath).toBe(createHash("sha256").update("tok").digest("base64url"));
  });

  it("keeps a non-default port, adds no path to a bare origin, and refuses a URL with no htu", async () => {
    const key = await SigningKeyPair.generate("ES256");
    const htu = async (uri: string) => decodeJwt(await new DpopProofBuilder(key).uri(uri).accessToken(null).build()).htu;
    expect(await htu("https://as.example:8443/token?x")).toBe("https://as.example:8443/token");
    expect(await htu("https://as.example?x")).toBe("https://as.example");
    await expect(htu("not-a-url#frag")).rejects.toThrow("uri (htu) must be an absolute http or https URL with a host");
    expect(decodeJwt(await new DpopProofBuilder(key).uri("https://a/").build()).ath).toBeUndefined();
  });
});

describe("the DPoP nonce memory", () => {
  /** Stubs fetch for every URL outside the AS: `handler` answers those. */
  function stubResources(asUrl: string, handler: (url: string, init?: RequestInit) => Promise<Response> | Response) {
    const realFetch = globalThis.fetch;
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) =>
      String(input).startsWith(asUrl) ? realFetch(input, init) : handler(String(input), init));
  }

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const nonceOf = async (ca: ClientAttestation, url: string) =>
    decodeJwt((await ca.requestHeaders("GET", url)).DPoP).nonce;

  it("ignores a DPoP-Nonce over 1024 characters, and does not answer a challenge carrying one", async () => {
    const as = await authorizationServer();
    const ca = client(as.url);
    const long = "n".repeat(1025);
    let hits = 0;
    stubResources(as.url, (url) => {
      hits += 1;
      if (url.endsWith("/fits")) return new Response("ok", { headers: { "DPoP-Nonce": "n".repeat(1024) } });
      return new Response(null, {
        status: 401,
        headers: { "WWW-Authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": long },
      });
    });
    expect((await ca.fetch("https://rs.example/data")).status).toBe(401);
    expect(hits).toBe(1);
    expect(await nonceOf(ca, "https://rs.example/next")).toBeUndefined();
    await ca.fetch("https://rs.example/fits");
    expect(await nonceOf(ca, "https://rs.example/next")).toBe("n".repeat(1024));
  });

  it("remembers at most 256 origins, forgetting the one stored longest ago", async () => {
    const as = await authorizationServer();
    const ca = client(as.url);
    stubResources(as.url, (url) => new Response("ok", { headers: { "DPoP-Nonce": "n-" + new URL(url).hostname } }));
    const count = 256 + 44;
    for (let i = 0; i < count; i++) {
      await ca.fetch(`https://h${i}.example/p${i}`);
      await ca.fetch("https://h1.example/"); // kept fresh, so never the oldest
    }
    expect(await nonceOf(ca, "https://h0.example/")).toBeUndefined();
    expect(await nonceOf(ca, "https://h1.example/")).toBe("n-h1.example");
    expect(await nonceOf(ca, `https://h${count - 1}.example/`)).toBe(`n-h${count - 1}.example`);
  });

  it("answers a challenge with its own nonce, even if another response stored one meanwhile", async () => {
    const as = await authorizationServer();
    const ca = client(as.url);
    const proofs: Record<string, unknown>[] = [];
    stubResources(as.url, (url, init) => {
      if (url.endsWith("/other")) return new Response("ok", { headers: { "DPoP-Nonce": "other-nonce" } });
      proofs.push(decodeJwt(new Headers(init?.headers).get("DPoP") as string));
      if (proofs.length > 1) return new Response("ok");
      // While the client reads this challenge's body, a concurrent response stores another nonce.
      const body = new ReadableStream({
        async pull(controller) {
          await ca.fetch("https://rs.example/other");
          controller.enqueue(new TextEncoder().encode('{"error":"use_dpop_nonce"}'));
          controller.close();
        },
      });
      return new Response(body, { status: 400, headers: { "DPoP-Nonce": "challenge-nonce" } });
    });
    expect((await ca.fetch("https://rs.example/data")).status).toBe(200);
    expect(proofs.map((p) => p.nonce)).toEqual([undefined, "challenge-nonce"]);
  });
});

describe("URLs that parsers disagree on", () => {
  const ambiguous = [
    "https://evil.example\\@as.example/t",
    "https://as.example/a\\b",
    " https://as.example/t",
    "https://as.example/t ",
    "https://as.example\t/t",
    "https://as.example/t\n",
    "https://as.example/\x00t",
    "https://as.example/\x7ft",
  ];

  it.each(ambiguous)("requestHeaders and DpopProofBuilder refuse %j", async (url) => {
    const as = await authorizationServer();
    const ca = client(as.url);
    await expect(ca.requestHeaders("GET", url)).rejects.toThrow(ClientAttestationError);
    const key = await SigningKeyPair.generate("ES256");
    await expect(new DpopProofBuilder(key).uri(url).build()).rejects.toThrow(
      /backslash, whitespace or control character/,
    );
  });

  const noHtu = ["https://b\u00fccher.example/t"];

  it.each(noHtu.flatMap((url) => ["DPoP", "Bearer"].map((tokenType) => [url, tokenType])))(
    "a dpop_combined client refuses %j (%s token), which has no htu, before fetching the token",
    async (url, tokenType) => {
      const as = await authorizationServer({ tokenType });
      const ca = client(as.url);
      const err = await ca.requestHeaders("GET", url).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(ClientAttestationError);
      expect((err as Error).message).toMatch(/^uri \(htu\) /);
      expect(as.tokenProofs).toHaveLength(0); // a cold cache: no mint and no token request
    },
  );

  /** An attester + AS for the attestation_pop_jwt method, issuing tokens of `tokenType`. */
  async function popJwtServer(tokenType: string) {
    return listen((req, res) => {
      const base = `http://${req.headers.host}`;
      if (req.url === "/.well-known/client-attester") {
        return json(res, 200, { attestation_endpoint: base + "/attest", token_endpoint: base + "/token", evidence_audience: "a" });
      }
      if (req.url === "/attest") return json(res, 200, { attestation: `h.${Buffer.from('{"sub":"d"}').toString("base64url")}.s` });
      json(res, 200, { access_token: "AT-plain", token_type: tokenType });
    });
  }

  it.each(noHtu)("a client not configured for DPoP sends a Bearer token to %j, as before", async (url) => {
    const ca = new ClientAttestation(await popJwtServer("Bearer"), { evidence: new StaticSvidSource("svid"), evidenceAudience: "a" });
    expect(await ca.requestHeaders("GET", url)).toEqual({ Authorization: "Bearer AT-plain" });
  });

  it.each(noHtu)("a DPoP token the AS chose still refuses %j", async (url) => {
    const ca = new ClientAttestation(await popJwtServer("DPoP"), { evidence: new StaticSvidSource("svid"), evidenceAudience: "a" });
    const err = await ca.requestHeaders("GET", url).catch((e: unknown) => e);
    expect((err as Error).message).toMatch(/^uri \(htu\) /);
  });

  // fetch (WHATWG) sends "[", "]", "|" and a lone "%" as written (and escapes "^"), so the proof's htu must
  // name the target exactly as sent: a conforming resource (RFC 9449 section 4.3) compares after RFC 3986 section 6.2.2
  // normalisation, which decodes only unreserved characters, so "%5B" is not "[".
  it("fetch signs the request target it sends, with [ ] | and a lone % as written", async () => {
    const as = await authorizationServer();
    const seen: { target: string; htu: unknown }[] = [];
    const rs = await listen(async (req, res) => {
      const { claims } = await verifyProof(req.headers["dpop"] as string);
      seen.push({ target: `http://${req.headers.host}${(req.url as string).split("?")[0]}`, htu: claims.htu });
      json(res, 200, { ok: true });
    });
    const ca = client(as.url);
    for (const path of ["/items[0]", "/a[b]/c|d^e", "/100%", "/caf\u00e9[x]"]) {
      expect((await ca.fetch(`${rs}${path}?q=1`)).status).toBe(200);
    }
    // The proof names exactly the target the server received. How fetch writes "^" differs between Node
    // versions (raw on 20 and 22, %5E later), so only what every version sends as written is pinned.
    expect(seen).toHaveLength(4);
    for (const { target, htu } of seen) expect(htu).toBe(target);
    expect(seen[0].target).toBe(`${rs}/items[0]`);
    expect(seen[1].target).toMatch(/\/a\[b\]\/c\|d(\^|%5E)e$/);
    expect(seen[2].target).toBe(`${rs}/100%`);
    expect(seen[3].target).toBe(`${rs}/caf%C3%A9[x]`);
  });

  it("leaves what follows the path alone, and fetch signs the URL it sends", async () => {
    const key = await SigningKeyPair.generate("ES256");
    const proof = await new DpopProofBuilder(key).uri("https://as.example/t?q=a\\b c#a b").build();
    expect(decodeJwt(proof).htu).toBe("https://as.example/t");

    // fetch parses the URL as WHATWG does (a backslash is a slash), and the proof names that URL.
    const as = await authorizationServer();
    const rs = await resourceServer(as.boundKeys);
    const ca = client(as.url);
    expect((await ca.fetch(`${rs.url}/a\\b`)).status).toBe(200);
    expect(rs.seen.at(-1)?.proof.htu).toBe(`${rs.url}/a/b`);
  });
});
