/**
 * Runtime-neutral helpers, so the package loads on edge runtimes (Cloudflare Workers, Vercel Edge,
 * Deno Deploy) as well as Node. Nothing here, or anywhere else in `src`, imports a Node builtin
 * statically: the few features that need one load it lazily through {@link importNodeBuiltin}.
 * Not exported from the package index.
 */
import { ClientAttestationError } from "./errors.js";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

/**
 * UTF-8 bytes of a string.
 *
 * @internal
 */
export function utf8Encode(text: string): Uint8Array {
  return textEncoder.encode(text);
}

/**
 * A string from UTF-8 bytes; malformed sequences become U+FFFD, as `Buffer#toString` does.
 *
 * @internal
 */
export function utf8Decode(bytes: Uint8Array): string {
  return textDecoder.decode(bytes);
}

/**
 * Standard (padded) base64 of some bytes.
 *
 * @internal
 */
export function base64Encode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

/**
 * An environment variable, or `undefined` on a runtime with no `process.env` (most edge runtimes).
 *
 * @internal
 */
export function envVar(name: string): string | undefined {
  const proc = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
  return proc?.env?.[name];
}

/**
 * Load a Node builtin (`node:<name>`) on first use. Throws a {@link ClientAttestationError} naming the
 * feature when the runtime has no such module (an edge runtime without Node compatibility).
 *
 * The specifier is built at run time so bundlers for edge targets leave it alone instead of failing to
 * resolve it.
 *
 * @internal
 */
export async function importNodeBuiltin<T>(name: string, feature: string): Promise<T> {
  const specifier = "node:" + name;
  try {
    return (await import(/* @vite-ignore */ /* webpackIgnore: true */ specifier)) as T;
  } catch (err) {
    throw new ClientAttestationError(
      `${feature} needs the Node.js module '${specifier}', which this runtime does not provide`,
      { cause: err },
    );
  }
}
