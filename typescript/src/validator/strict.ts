/**
 * The strict parsing every port applies to a token before trusting any of it (validation/SEMANTICS.md):
 * compact serialisation, strict JSON objects, NumericDates and claim types. A failure throws
 * {@link Malformed}; its message is generic and never quotes token bytes.
 */
import { base64url } from "jose";

/**
 * Deepest object/array nesting a header, payload or introspection response may have.
 *
 * @internal
 */
export const MAX_DEPTH = 64;
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const SEGMENT = /^[A-Za-z0-9_-]*$/;

/**
 * The input is not well-formed; the token is invalid.
 *
 * @internal
 */
export class Malformed extends Error {}

/** @internal */
export type JsonObject = Record<string, unknown>;

/** @internal */
export interface CompactParts {
  header: JsonObject;
  payload: Uint8Array;
}

function decodeSegment(segment: string): Uint8Array {
  if (!SEGMENT.test(segment) || segment.length % 4 === 1) {
    throw new Malformed("malformed token");
  }
  const data = base64url.decode(segment);
  if (base64url.encode(data) !== segment) {
    throw new Malformed("malformed token"); // non-zero padding bits: not the canonical encoding
  }
  return data;
}

/**
 * The header object and payload bytes of a compact JWS. The payload is returned undecoded: it is only
 * parsed once the signature over it verifies.
 *
 * @internal
 */
export function splitCompact(token: unknown): CompactParts {
  if (typeof token !== "string") {
    throw new Malformed("malformed token");
  }
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Malformed("malformed token");
  }
  const [headerBytes, payload] = parts.map(decodeSegment);
  const header = parseObject(headerBytes, "header");
  if ("crit" in header) {
    // we implement no JWS extension, so RFC 7515 section 4.1.11 says reject any crit
    throw new Malformed("header has crit");
  }
  return { header, payload };
}

/**
 * `data` as a strict RFC 8259 JSON object: UTF-8 without a BOM, no duplicate member names at any depth,
 * at most {@link MAX_DEPTH} levels deep. (`JSON.parse` already refuses NaN, trailing commas and the like.)
 *
 * @internal
 */
export function parseObject(data: Uint8Array, what = "payload"): JsonObject {
  let text: string;
  try {
    // fatal: invalid UTF-8 is an error, not U+FFFD; ignoreBOM: keep a BOM so JSON.parse refuses it
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data);
  } catch {
    throw new Malformed(`${what} is not UTF-8`);
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Malformed(`${what} is not JSON`);
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Malformed(`${what} is not a JSON object`);
  }
  checkStructure(text, what);
  return value as JsonObject;
}

/**
 * Walk JSON text that `JSON.parse` has already accepted, refusing a duplicate member name in any object
 * (names compared after unescaping) and nesting deeper than {@link MAX_DEPTH}. Iterative, so depth can't
 * exhaust the stack.
 */
function checkStructure(text: string, what: string): void {
  // one frame per open container: a Set of member names for an object, null for an array
  const stack: (Set<string> | null)[] = [];
  let expectName = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"') {
      let j = i + 1;
      while (text[j] !== '"') {
        j += text[j] === "\\" ? 2 : 1;
      }
      const top = stack[stack.length - 1];
      if (expectName && top) {
        const name = JSON.parse(text.slice(i, j + 1)) as string;
        if (top.has(name)) {
          throw new Malformed(`${what} is not a strict JSON object (duplicate member name)`);
        }
        top.add(name);
        expectName = false;
      }
      i = j;
    } else if (ch === "{" || ch === "[") {
      stack.push(ch === "{" ? new Set() : null);
      if (stack.length > MAX_DEPTH) {
        throw new Malformed(`${what} is nested too deeply`);
      }
      expectName = ch === "{";
    } else if (ch === "}" || ch === "]") {
      stack.pop();
    } else if (ch === ",") {
      expectName = stack[stack.length - 1] != null;
    }
  }
}

/**
 * A NumericDate claim as an integer (fractions truncate toward zero), `undefined` when absent or null.
 * Anything but a finite JSON number within ±(2^53 − 1) is malformed.
 *
 * @internal
 */
export function numericDate(claims: JsonObject, name: string): number | undefined {
  const value = claims[name];
  if (value == null) {
    return undefined;
  }
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Malformed(`${name} is not a NumericDate`);
  }
  if (Math.abs(value) > MAX_SAFE) {
    throw new Malformed(`${name} is out of range`);
  }
  return Math.trunc(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === "string");
}

/**
 * `aud` as a list: absent or null is empty, a string is one entry, an array must hold only strings.
 *
 * @internal
 */
export function audience(claims: JsonObject): string[] {
  const value = claims.aud;
  if (value == null) {
    return [];
  }
  if (typeof value === "string") {
    return [value];
  }
  if (isStringArray(value)) {
    return [...value];
  }
  throw new Malformed("aud is not a string or an array of strings");
}

/** Split on U+0020 only, as RFC 6749 section 3.3 says; runs of spaces make no empty scopes. */
function split(text: string): string[] {
  return text.split(" ").filter((s) => s.length > 0);
}

/**
 * Granted scopes: from `scope` (a space-delimited string) when present, else `scp` (a space-delimited string,
 * as Microsoft Entra ID issues it, or an array of strings). Either one present with any other shape is
 * malformed.
 *
 * @internal
 */
export function scopes(claims: JsonObject): string[] {
  const { scope, scp } = claims;
  if (scope != null && typeof scope !== "string") {
    throw new Malformed("scope is not a string");
  }
  if (scp != null && typeof scp !== "string" && !isStringArray(scp)) {
    throw new Malformed("scp is not a string or an array of strings");
  }
  if (scope != null) {
    return split(scope);
  }
  if (typeof scp === "string") {
    return split(scp);
  }
  return scp != null ? [...scp] : [];
}

/**
 * `sub`, `undefined` when absent or null; any other non-string is malformed.
 *
 * @internal
 */
export function subject(claims: JsonObject): string | undefined {
  const value = claims.sub;
  if (value != null && typeof value !== "string") {
    throw new Malformed("sub is not a string");
  }
  return value ?? undefined;
}
