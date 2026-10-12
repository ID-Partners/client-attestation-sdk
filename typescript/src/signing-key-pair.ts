/**
 * Signing keys for attestation-based client authentication.
 */
import {
  CompactSign,
  SignJWT,
  base64url,
  calculateJwkThumbprint,
  compactVerify,
  exportJWK,
  generateKeyPair,
  importJWK,
  type CryptoKey,
  type JWK,
} from "jose";

/**
 * A signing key pair (public + private) with its JWS `alg` and RFC 7638 thumbprint `kid`.
 *
 * Used both as the client instance key — which signs PoP / DPoP proofs and is bound into an
 * attestation's `cnf` — and as a Client Attester's issuing key.
 *
 * jose's crypto operations are async, so instances are created via the static async
 * factories {@link SigningKeyPair.generate} and {@link SigningKeyPair.fromJwk}.
 */
export class SigningKeyPair {
  /** The JWS algorithm (e.g. `ES256`). */
  readonly algorithm: string;
  /** The RFC 7638 JWK thumbprint (SHA-256, base64url) — this key's `kid`. */
  readonly keyId: string;

  readonly #privateKey: CryptoKey;
  readonly #publicJwk: JWK;

  private constructor(privateKey: CryptoKey, algorithm: string, publicJwk: JWK, keyId: string) {
    this.#privateKey = privateKey;
    this.algorithm = algorithm;
    // Store the public JWK with its kid stamped, so publicJwk() hands out a copy including kid.
    this.#publicJwk = { ...publicJwk, kid: keyId };
    this.keyId = keyId;
  }

  /**
   * Generate a fresh key pair for the given JWS algorithm: `ES256` / `ES384` / `ES512`
   * (EC P-256 / P-384 / P-521), or `RS256` / `RS384` / `RS512` / `PS256` / `PS384` / `PS512`
   * (RSA 2048).
   *
   * The private key is not extractable unless `options.extractable` is true: nothing in the SDK needs
   * to export it, so by default it can't leak through `exportJWK`. Pass `{ extractable: true }` only to
   * persist the key yourself (then restore it with {@link SigningKeyPair.fromJwk}).
   */
  static async generate(
    algorithm: string,
    options: { extractable?: boolean } = {},
  ): Promise<SigningKeyPair> {
    checkAlgorithm(algorithm);
    const { privateKey, publicKey } = await generateKeyPair(algorithm, {
      extractable: options.extractable ?? false,
      ...(algorithm.startsWith("ES") ? {} : { modulusLength: RSA_MODULUS_BITS }),
    });
    const publicJwk = publicMembers(await exportJWK(publicKey));
    const keyId = await calculateJwkThumbprint(publicJwk, "sha256");
    return new SigningKeyPair(privateKey, algorithm, publicJwk, keyId);
  }

  /**
   * Wrap an existing JWK (which must contain the private component `d`) for the given algorithm.
   *
   * The key must suit the algorithm: an EC key on its curve for `ES256` / `ES384` / `ES512`
   * (P-256 / P-384 / P-521), an RSA key of at least 2048 bits for `RS*` / `PS*`, and its public
   * members must belong to its private key. Only the key material is kept: the published JWK is
   * re-encoded canonically (full-width EC coordinates, minimal RSA integers) and its `kid` is the
   * RFC 7638 thumbprint, whatever `kid` or other members the input had.
   */
  static async fromJwk(jwk: JWK, algorithm: string): Promise<SigningKeyPair> {
    if (!jwk.d) {
      throw new Error("JWK does not contain a private key");
    }
    checkAlgorithm(algorithm);
    const canonical = canonicalPrivateJwk(jwk, algorithm);
    const privateKey = (await importJWK(canonical, algorithm)) as CryptoKey;
    const publicJwk = publicMembers(canonical);
    await checkKeyPair(privateKey, publicJwk, algorithm);
    const keyId = await calculateJwkThumbprint(publicJwk, "sha256");
    return new SigningKeyPair(privateKey, algorithm, publicJwk, keyId);
  }

  /** The private CryptoKey — package-internal; used by the JWS signer. */
  get privateKey(): CryptoKey {
    return this.#privateKey;
  }

  /**
   * The public-only JWK (including `kid`) as a fresh object — suitable as an attestation
   * `cnf.jwk` or a DPoP header value (from which callers strip `kid`).
   */
  publicJwk(): JWK {
    return { ...this.#publicJwk };
  }
}

/**
 * The JWS algorithms {@link SigningKeyPair} can generate and sign with.
 *
 * @internal
 */
export const SUPPORTED_ALGORITHMS: readonly string[] = [
  "ES256", "ES384", "ES512",
  "RS256", "RS384", "RS512",
  "PS256", "PS384", "PS512",
];

/** RSA modulus size for generated RS* / PS* keys, and the smallest one the SDK signs with. */
const RSA_MODULUS_BITS = 2048;

/** The curve, and its coordinate width in bytes, each ECDSA algorithm signs on. */
const EC_CURVES: Record<string, readonly [string, number]> = {
  ES256: ["P-256", 32],
  ES384: ["P-384", 48],
  ES512: ["P-521", 66],
};

/** Strict base64url decoding; the error names the member, never its value. */
function decodeMember(jwk: JWK, member: string): Uint8Array {
  const value = (jwk as Record<string, unknown>)[member];
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`JWK member '${member}' is missing or not base64url`);
  }
  return base64url.decode(value);
}

function stripLeadingZeros(bytes: Uint8Array): Uint8Array {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  return bytes.subarray(i);
}

/**
 * The key members of a private JWK, checked against `algorithm` and re-encoded canonically: EC
 * coordinates and `d` at the curve's full width, RSA `n` and `e` in their minimal octets (RFC 7518
 * section 6). Every other member (`kid`, `alg`, `use`, ...) is dropped.
 */
function canonicalPrivateJwk(jwk: JWK, algorithm: string): JWK {
  const ec = EC_CURVES[algorithm];
  if (ec) {
    const [crv, size] = ec;
    if (jwk.kty !== "EC") {
      throw new Error(`${algorithm} needs an EC key, not kty ${JSON.stringify(jwk.kty)}`);
    }
    if (jwk.crv !== crv) {
      throw new Error(`${algorithm} needs an EC key on ${crv}`);
    }
    const out: JWK = { kty: "EC", crv };
    for (const member of ["x", "y", "d"] as const) {
      const value = stripLeadingZeros(decodeMember(jwk, member));
      if (value.length > size) {
        throw new Error(`JWK member '${member}' is too long for ${crv}`);
      }
      const fixed = new Uint8Array(size);
      fixed.set(value, size - value.length);
      out[member] = base64url.encode(fixed);
    }
    return out;
  }
  if (jwk.kty !== "RSA") {
    throw new Error(`${algorithm} needs an RSA key, not kty ${JSON.stringify(jwk.kty)}`);
  }
  const out: JWK = {};
  for (const member of ["kty", "n", "e", "d", "p", "q", "dp", "dq", "qi", "oth"] as const) {
    if (jwk[member] !== undefined) {
      (out as Record<string, unknown>)[member] = jwk[member];
    }
  }
  const n = stripLeadingZeros(decodeMember(jwk, "n"));
  out.n = base64url.encode(n);
  out.e = base64url.encode(stripLeadingZeros(decodeMember(jwk, "e")));
  const bits = n[0] === 0 ? 0 : (n.length - 1) * 8 + (32 - Math.clz32(n[0]));
  if (bits < RSA_MODULUS_BITS) {
    throw new Error(`RSA keys must be at least ${RSA_MODULUS_BITS} bits`);
  }
  return out;
}

/**
 * Refuse a private key whose published public half is another key: signing with one key while
 * advertising another (as `kid`, `cnf.jwk` or the DPoP `jwk`) gives credentials no verifier accepts.
 */
async function checkKeyPair(privateKey: CryptoKey, publicJwk: JWK, algorithm: string): Promise<void> {
  try {
    const probe = new TextEncoder().encode("client-attestation-sdk key pair check");
    const jws = await new CompactSign(probe).setProtectedHeader({ alg: algorithm }).sign(privateKey);
    await compactVerify(jws, await importJWK(publicJwk, algorithm));
  } catch {
    throw new Error("the JWK's public key does not match its private key");
  }
}

function checkAlgorithm(algorithm: string): void {
  if (!SUPPORTED_ALGORITHMS.includes(algorithm)) {
    throw new Error(`unsupported signing algorithm: ${algorithm}`);
  }
}

/** The public members of an EC or RSA JWK (no private parameters, no metadata). */
function publicMembers(jwk: JWK): JWK {
  return jwk.kty === "RSA"
    ? { kty: jwk.kty, n: jwk.n, e: jwk.e }
    : { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
}

/**
 * RFC 7638 JWK thumbprint (SHA-256, base64url) over the required members only.
 *
 * @internal
 */
export async function thumbprint(publicJwk: JWK): Promise<string> {
  return calculateJwkThumbprint(publicJwk, "sha256");
}

/**
 * Sign claims into a compact JWS with an explicit `typ` header, keyed by `key`.
 *
 * When `embedJwk` is set the public key travels in a `jwk` header (as DPoP requires); otherwise
 * the key's thumbprint `kid` is set.
 *
 * @internal
 */
export async function signCompact(
  claims: Record<string, unknown>,
  key: SigningKeyPair,
  typ: string,
  embedJwk: boolean,
): Promise<string> {
  const header: Record<string, unknown> = { alg: key.algorithm, typ };
  if (embedJwk) {
    const publicJwk = key.publicJwk();
    delete publicJwk.kid;
    header.jwk = publicJwk;
  } else {
    header.kid = key.keyId;
  }
  return new SignJWT(claims).setProtectedHeader(header as never).sign(key.privateKey);
}

/** @internal */
export function requireText(value: string | null | undefined, field: string): string {
  if (value == null || String(value).trim() === "") {
    throw new Error(`${field} is required`);
  }
  return value;
}
