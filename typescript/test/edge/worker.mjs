// Runs inside workerd (Cloudflare's Workers runtime) with no Node compatibility flag, via
// `workerd test`. run-workerd.mjs bundles this file with the SDK and the shared validation vectors and
// calls the `test` handler below; any thrown error fails the run.
import * as sdk from "../../src/index.ts";
import * as v from "../../src/validator/index.ts";
import vectors from "../../../validation/tokens.json";

function validatorFor(v, vectors, c) {
  // the shared config plus the case's overrides (present wins, even when empty) and clock
  const o = c.config ?? {};
  const cfg = {
    issuer: vectors.issuer,
    audiences: [vectors.audience],
    jwks: vectors.jwks,
    requiredScopes: vectors.required_scopes,
    acceptedAlgorithms: vectors.accepted_algorithms,
  };
  if ("accepted_algorithms" in o) cfg.acceptedAlgorithms = o.accepted_algorithms;
  if ("accepted_token_types" in o) cfg.acceptedTokenTypes = o.accepted_token_types;
  if ("leeway_seconds" in o) cfg.leewaySeconds = o.leeway_seconds;
  return new v.AccessTokenValidator(cfg, c.now === undefined ? {} : { clock: () => c.now * 1000 });
}

function check(cond, what) {
  if (!cond) throw new Error("edge check failed: " + what);
}

function claims(jwt) {
  return JSON.parse(atob(jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
}

export default {
  async test() {
    // prove this really is workerd without Node compatibility, not Node with a different name
    check(navigator.userAgent === "Cloudflare-Workers", "navigator.userAgent is " + navigator.userAgent);
    check(typeof process === "undefined" && typeof Buffer === "undefined", "Node globals are present");

    const attester = await sdk.SigningKeyPair.generate("ES256");
    const instance = await sdk.SigningKeyPair.generate("ES256");
    const attestation = await new sdk.ClientAttestationBuilder(attester, "https://attester.example.com")
      .clientId("https://rp.example.com")
      .confirmationKey(instance)
      .expiresIn(300)
      .build();
    const pop = await new sdk.PopBuilder(instance)
      .clientId("https://rp.example.com")
      .audience("https://as.example.com")
      .build();
    const dpop = await new sdk.DpopProofBuilder(instance)
      .method("GET")
      .uri("https://api.example.com/things?q=1")
      .accessToken("token-abc")
      .build();

    check(claims(attestation).sub === "https://rp.example.com", "attestation sub");
    for (const jwt of [attestation, pop, dpop]) check(jwt.split(".").length === 3, "compact JWS");
    const att = claims(attestation);
    check(att.iss === "https://attester.example.com", "attestation iss");
    check(att.cnf?.jwk?.kty === "EC" && !("d" in att.cnf.jwk), "attestation cnf.jwk is the public key");
    const popClaims = claims(pop);
    check(popClaims.iss === "https://rp.example.com" && popClaims.aud === "https://as.example.com", "PoP iss/aud");
    const dpopClaims = claims(dpop);
    // RFC 9449 ath: base64url(SHA-256("token-abc"))
    check(dpopClaims.ath === "CWFXsznPQZ28DI3vSfwr6STcEw-6zfp7h5vuCjB4zsQ", "DPoP ath");
    check(dpopClaims.htu === "https://api.example.com/things", "DPoP htu drops the query");
    check(dpopClaims.htm === "GET", "DPoP htm");

    check(vectors.cases.length > 0, "no validation vectors");
    for (const c of vectors.cases) {
      const r = await validatorFor(v, vectors, c).validate(c.token);
      const got = r.valid ? "valid" : r.error;
      check(got === c.expect, `vector ${c.name}: got ${got}, want ${c.expect}`);
    }

    // no filesystem, no process.env, and no route to the metadata server: detection reports nothing
    // found rather than crashing on a missing Node builtin (workerd logs the refused connect)
    let detect;
    try {
      await sdk.autoDetectEvidence({ gcpMetadataBase: "http://127.0.0.1:9" });
    } catch (e) {
      detect = e.name;
    }
    check(detect === "EvidenceNotFound", "autoDetectEvidence threw " + detect);

    // the shared HTTP transport (timeouts, capped streaming read) against workerd's own Response
    const realFetch = globalThis.fetch;
    globalThis.fetch = async () => new Response(JSON.stringify({ svid: "a.b.c" }), { status: 200 });
    try {
      const svid = await new sdk.HttpSvidSource("https://harness.example.com/dev/svid").fetch("aud");
      check(svid === "a.b.c", "HttpSvidSource returned " + svid);
    } finally {
      globalThis.fetch = realFetch;
    }

    console.log(
      `workerd edge check passed: attestation/PoP/DPoP built, ${vectors.cases.length} validation vectors agree`,
    );
  },
};
