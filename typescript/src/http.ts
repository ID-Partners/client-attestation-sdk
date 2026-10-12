/**
 * The one internal HTTP transport every outbound call in the SDK goes through. Not exported from the
 * package index.
 *
 * Uniform behaviour, because these requests carry credentials (Authorization, DPoP, client attestation
 * headers, X-Vault-Token, SVIDs and proofs in bodies):
 *
 * - every call has a timeout, covering the body read as well as the headers;
 * - redirects are never followed — a 3xx is a {@link TransportError}, and the target is never contacted;
 * - the response body is capped (default 1 MiB), by `content-length` and again while streaming;
 * - {@link request} returns non-2xx responses as data; {@link jsonOk} turns them, and malformed JSON,
 *   into a {@link TransportError};
 * - a URL with userinfo (`user:password@`) is refused, and errors name a URL without its userinfo, query or
 *   fragment.
 *
 * Proxies: `fetch` uses no proxy from the environment by default (Node, Deno, Bun without configuration,
 * edge runtimes). Node started with `NODE_USE_ENV_PROXY=1` or `--use-env-proxy` sends every request,
 * plain http included, to `HTTP_PROXY` / `HTTPS_PROXY`; the SDK can't pick a dispatcher per request
 * without depending on undici, so the other ports' rule (a proxy only for https to a remote host) is
 * then the operator's to keep, with `NO_PROXY`.
 */
import { ClientAttestationError, TransportError } from "./errors.js";
import { utf8Decode, utf8Encode } from "./runtime.js";

/** @internal */
export const DEFAULT_MAX_BYTES = 1024 * 1024;
/** @internal */
export const DEFAULT_TIMEOUT_MS = 20_000;
/**
 * At most this many characters of a non-2xx response body are carried in an error. A 2xx body never is:
 * that is where access tokens, attestations and SVIDs travel.
 *
 * @internal
 */
export const ERROR_BODY_CHARS = 512;

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

/**
 * Refuse a non-https URL unless it is loopback or the caller passed `allowInsecure`. Shared by every SDK
 * client that sends credentials.
 *
 * @internal
 */
export function checkSecure(url: string, what: string, allowInsecure: boolean): void {
  if (allowInsecure) return;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new ClientAttestationError(`${what} is not a valid URL: ${url}`);
  }
  if (parsed.protocol === "https:" || LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase())) return;
  throw new ClientAttestationError(
    `${what} must use https: ${url} (loopback hosts are exempt; pass allowInsecure: true to override)`,
  );
}

/** @internal */
export interface HttpRequestOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  /** Whole-call timeout in milliseconds (connect, headers and body). Defaults to 20 s. */
  timeoutMs?: number;
  /** Largest response body accepted, in bytes. Defaults to 1 MiB. */
  maxBytes?: number;
}

/** @internal */
export interface HttpResponse {
  method: string;
  url: string;
  status: number;
  ok: boolean;
  headers: Headers;
  body: string;
}

/**
 * The first {@link ERROR_BODY_CHARS} characters of a body, for an error message.
 *
 * @internal
 */
export function snippet(body: string): string {
  return body.length > ERROR_BODY_CHARS ? body.slice(0, ERROR_BODY_CHARS) : body;
}

/**
 * `url` without its userinfo, query or fragment, for error messages: a query can carry a secret, and
 * userinfo is one.
 *
 * @internal
 */
export function displayUrl(url: string): string {
  const beforeQuery = url.split(/[?#]/, 1)[0] ?? "";
  return beforeQuery.replace(/^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)[^/\\]*@/, "$1");
}

/**
 * Whether `url` carries userinfo, read as `fetch` would read it; an unparseable URL is checked by hand.
 *
 * @internal
 */
export function hasUserinfo(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.username !== "" || parsed.password !== "";
  } catch {
    return /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/?#\\]*@/.test(url);
  }
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function isAbort(err: unknown): boolean {
  const name = (err as { name?: unknown } | null)?.name;
  return name === "TimeoutError" || name === "AbortError";
}

/**
 * Make one HTTP request. Resolves with the status, headers and body text for any non-3xx response
 * (non-2xx included); rejects with a {@link TransportError} for a network failure, timeout, redirect or
 * oversized body.
 *
 * @internal
 */
export async function request(url: string, opts: HttpRequestOptions = {}): Promise<HttpResponse> {
  const method = opts.method ?? "GET";
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
  const where = `${method} ${displayUrl(url)}`;
  if (hasUserinfo(url)) {
    // fetch refuses these too, but its error would come after `where` held the userinfo
    throw new TransportError(`${where}: URLs with userinfo (user:password@) are not supported`, "network");
  }
  const timedOut = (cause: unknown) =>
    new TransportError(`${where} timed out after ${timeoutMs} ms`, "timeout", { cause });

  let res: Response;
  try {
    res = await fetch(url, {
      method,
      headers: opts.headers,
      body: opts.body,
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    if (isAbort(err)) throw timedOut(err);
    throw new TransportError(`${where} failed: ${describe(err)}`, "network", { cause: err });
  }

  const status = res.status;
  if (res.type === "opaqueredirect" || (status >= 300 && status < 400)) {
    await discard(res);
    throw new TransportError(`${where} answered with a redirect (HTTP ${status}); redirects are not followed`, "redirect", {
      status,
    });
  }

  const tooLarge = () =>
    new TransportError(`${where} response is larger than ${maxBytes} bytes`, "too_large", { status });
  const declared = Number(res.headers?.get("content-length") ?? NaN);
  if (declared > maxBytes) {
    await discard(res);
    throw tooLarge();
  }

  let body: string;
  try {
    body = await readCapped(res, maxBytes, tooLarge);
  } catch (err) {
    if (err instanceof TransportError) throw err;
    if (isAbort(err)) throw timedOut(err);
    throw new TransportError(`${where} failed reading the response: ${describe(err)}`, "network", { cause: err });
  }

  return {
    method,
    url,
    status,
    ok: status >= 200 && status < 300,
    headers: res.headers ?? new Headers(),
    body,
  };
}

async function discard(res: Response): Promise<void> {
  try {
    await res.body?.cancel();
  } catch {
    // nothing to do: the response is being refused anyway
  }
}

async function readCapped(res: Response, maxBytes: number, tooLarge: () => TransportError): Promise<string> {
  if (!res.body) {
    // only reached by stand-in Response objects (tests); a real fetch always has a stream
    const text = await res.text();
    if (utf8Encode(text).byteLength > maxBytes) throw tooLarge();
    return text;
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw tooLarge();
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    all.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return utf8Decode(all);
}

/**
 * Parse `res.body` as a JSON object. Throws a {@link TransportError} for a non-2xx status (carrying the
 * status and at most 512 characters of the body) and for a body that is not a JSON object. An empty body
 * reads as `{}` when `allowEmpty` is set.
 *
 * @internal
 */
export function jsonOk<T = Record<string, unknown>>(res: HttpResponse, opts: { allowEmpty?: boolean } = {}): T {
  if (!res.ok) {
    const body = snippet(res.body);
    throw new TransportError(`${res.method} ${displayUrl(res.url)} returned HTTP ${res.status}: ${body}`, "status", {
      status: res.status,
      body,
    });
  }
  return parseJsonObject<T>(res, opts);
}

/**
 * Parse `res.body` as a JSON object regardless of status; a {@link TransportError} if it is not one. The
 * error carries no body, no cause and not the parser's message, which quotes part of the text: the body
 * parsed here is a 2xx one, which carries tokens, attestations and SVIDs.
 *
 * @internal
 */
export function parseJsonObject<T = Record<string, unknown>>(
  res: HttpResponse,
  opts: { allowEmpty?: boolean } = {},
): T {
  if (opts.allowEmpty && res.body === "") return {} as T;
  let parsed: unknown;
  try {
    parsed = JSON.parse(res.body);
  } catch {
    throw new TransportError(`${res.method} ${displayUrl(res.url)} returned malformed JSON`, "json", { status: res.status });
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new TransportError(`${res.method} ${displayUrl(res.url)} did not return a JSON object`, "json", {
      status: res.status,
    });
  }
  return parsed as T;
}
