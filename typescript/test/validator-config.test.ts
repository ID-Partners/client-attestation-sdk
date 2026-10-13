import { exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { describe, expect, it } from "vitest";

import { AccessTokenValidator, errors, type ValidatorConfig } from "../src/validator/index.js";

const ISSUER = "https://issuer.example.com";
const AUDIENCE = "https://api.example.com";
const JWKS = { keys: [] };

function build(overrides: Record<string, unknown>): AccessTokenValidator {
  return new AccessTokenValidator({ issuer: ISSUER, audiences: [AUDIENCE], jwks: JWKS, ...overrides } as ValidatorConfig);
}

const INSECURE = [
  "http://issuer.example.com/jwks",
  "http://127.0.0.2/jwks",
  "http://localhost.attacker.example/jwks",
  "http://localhost@attacker.example/jwks",
  "issuer.example.com/jwks",
];

const SECURE = [
  "https://issuer.example.com/jwks",
  "HTTPS://issuer.example.com/jwks",
  "http://localhost:8080/jwks",
  "http://LOCALHOST/jwks",
  "http://127.0.0.1:9000/jwks",
  "http://[::1]:8080/jwks",
];

describe("validator endpoints must use https", () => {
  // over plain http anyone on the path serves their own keys (forging any token) or reads the client secret
  it.each(INSECURE)("refuses jwksUri %s", (url) => {
    expect(() => build({ jwks: undefined, jwksUri: url })).toThrow("jwksUri");
  });

  it.each(INSECURE)("refuses introspection endpoint %s", (url) => {
    expect(() => build({ introspection: { endpoint: url, clientId: "rs", clientSecret: "s3cret" } })).toThrow(
      "introspection endpoint",
    );
  });

  it.each(INSECURE)("allowInsecure permits %s", (url) => {
    const v = build({
      jwks: undefined,
      jwksUri: url,
      introspection: { endpoint: url, clientId: "rs", clientSecret: "s3cret" },
      allowInsecure: true,
    });
    expect(v.config.jwksUri).toBe(url);
  });

  it.each(SECURE)("accepts %s", (url) => {
    const v = build({ jwks: undefined, jwksUri: url, introspection: { endpoint: url, clientId: "rs", clientSecret: "s" } });
    expect(v.config.introspection?.endpoint).toBe(url);
  });
});

describe("validator config types", () => {
  // NaN makes every exp/nbf/iat comparison false, so an expired token would pass; "60" would concatenate
  it.each([Number.NaN, Number.POSITIVE_INFINITY, -1, 1.5, "60", true, 2 ** 53])(
    "refuses leewaySeconds %s",
    (leeway) => {
      expect(() => build({ leewaySeconds: leeway })).toThrow("leewaySeconds");
    },
  );

  it("accepts a zero and a default leeway", () => {
    expect(build({ leewaySeconds: 0 }).config.leewaySeconds).toBe(0);
    expect(build({}).config.leewaySeconds).toBe(60);
  });

  // a bare string would spread into its characters: acceptedTokenTypes "at+jwt" would accept typ "t"
  it.each(["acceptedTokenTypes", "acceptedAlgorithms", "requiredScopes"])("refuses a bare string for %s", (field) => {
    expect(() => build({ [field]: "at+jwt" })).toThrow(field);
    expect(() => build({ [field]: ["ok", 7] })).toThrow(field);
  });

  it("refuses a non-string audience entry and a non-boolean allowInsecure", () => {
    expect(() => build({ audiences: [AUDIENCE, 7] })).toThrow("audiences");
    expect(() => build({ allowInsecure: "yes" })).toThrow("allowInsecure");
  });
});

describe("the validator keeps its own copy of its config", () => {
  // reusing a config object for another validator, or changing it later, must not change a live validator
  it("ignores later changes to the introspection settings", async () => {
    const introspection = { endpoint: "https://issuer.example.com/introspect", clientId: "rs", clientSecret: "s3cret" };
    let posted = "";
    const v = new AccessTokenValidator(
      { issuer: ISSUER, audiences: [AUDIENCE], jwks: JWKS, introspection },
      {
        httpPost: async (url: string) => {
          posted = url;
          return { active: true };
        },
      },
    );
    introspection.endpoint = "http://attacker.example/introspect";
    await v.validateActive("opaque");
    expect(posted).toBe("https://issuer.example.com/introspect");
  });

  it("ignores later changes to the JWKS", async () => {
    // an RSA JWK without alg is imported again for each algorithm a token names
    const issuerKey = await generateKeyPair("RS256", { extractable: true });
    const attackerKey = await generateKeyPair("PS256", { extractable: true });
    const jwk = { ...(await exportJWK(issuerKey.publicKey)), kid: "k1" };
    const v = new AccessTokenValidator({
      issuer: ISSUER,
      audiences: [AUDIENCE],
      jwks: { keys: [jwk] },
      acceptedAlgorithms: ["RS256", "PS256"],
    });
    const sign = (alg: string, key: CryptoKey) =>
      new SignJWT({ iss: ISSUER, aud: AUDIENCE, exp: Math.floor(Date.now() / 1000) + 300 })
        .setProtectedHeader({ alg, kid: "k1", typ: "at+jwt" })
        .sign(key);
    expect((await v.validate(await sign("RS256", issuerKey.privateKey))).valid).toBe(true);
    jwk.n = (await exportJWK(attackerKey.publicKey)).n;
    const forged = await v.validate(await sign("PS256", attackerKey.privateKey));
    expect(forged.error).toBe(errors.INVALID_SIGNATURE);
  });
});

describe("introspection authMethod", () => {
  // F5: anything but the two methods used to be taken as client_secret_post, moving the secret into the form
  const introspection = (authMethod: unknown) => ({
    introspection: { endpoint: ISSUER + "/introspect", clientId: "rs", clientSecret: "s3cret", authMethod },
  });

  // unset (undefined, null or "", e.g. process.env.X with no variable) is the default, client_secret_basic
  it.each([
    [undefined, true],
    [null, true],
    ["", true],
    ["client_secret_basic", true],
    ["client_secret_post", false],
  ])("accepts %s", async (method, basic) => {
    let headers: Record<string, string> = {};
    const validator = new AccessTokenValidator(
      { issuer: ISSUER, audiences: [AUDIENCE], jwks: JWKS, ...introspection(method) } as ValidatorConfig,
      {
        httpPost: async (_url, _body, h) => {
          headers = h;
          return { active: true };
        },
      },
    );
    await validator.introspect("opaque");
    expect("Authorization" in headers).toBe(basic);
  });

  it.each(["client_secret_basci", "private_key_jwt", "client_secret_jwt", "CLIENT_SECRET_BASIC", " client_secret_basic",
    "none", " ", 0, false, 1, {}])("refuses %s", (method) => {
    expect(() => build(introspection(method))).toThrow("authMethod");
    expect(() => build(introspection(method))).not.toThrow("s3cret");
  });
});

describe("introspection credentials", () => {
  it.each([
    ["clientId", { clientId: "", clientSecret: "s3cret" }],
    ["clientId", { clientId: null, clientSecret: "s3cret" }],
    ["clientId", { clientSecret: "s3cret" }],
    ["clientSecret", { clientId: "rs", clientSecret: "" }],
    ["clientSecret", { clientId: "rs", clientSecret: null }],
    ["clientSecret", { clientId: "rs", clientSecret: 7 }],
  ])("refuses a missing, empty or non-string %s", (field, creds) => {
    const build_ = () => build({ introspection: { endpoint: ISSUER + "/introspect", ...creds } });
    expect(build_).toThrow(field);
    expect(build_).not.toThrow("s3cret");
  });

  it("describes a bad authMethod without echoing it", () => {
    const build_ = () =>
      build({ introspection: { endpoint: ISSUER + "/introspect", clientId: "rs", clientSecret: "s3cret", authMethod: "hunter2-secret" } });
    expect(build_).toThrow("14 characters");
    expect(build_).not.toThrow("hunter2");
  });
});
