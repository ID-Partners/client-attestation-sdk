/**
 * Get an access token with client attestation in one call.
 *
 * Point it at a PingFederate host. The SDK auto-detects the workload's platform identity (a projected
 * token file, a SPIRE socket, the GCP metadata server, or an env token), runs the whole attestation
 * flow, and returns an access token. No client_id, no client secret.
 *
 *   npx tsx examples/one-call-token.ts pf.example.com
 *   ALLOW_INSECURE=1 npx tsx examples/one-call-token.ts http://pingfederate.pf:9080   # in-cluster, plain HTTP
 *
 * Use it with an HTTP client:
 *
 *   const ca = new ClientAttestation("pf.example.com");
 *   await ca.fetch("https://api.example.com/things");  // Authorization (+ a DPoP proof for a DPoP-bound token)
 *   await ca.requestHeaders("GET", "https://api.example.com/things");  // the same headers, for any client
 *
 * Plain http is refused for anything but loopback unless you pass `allowInsecure: true`.
 */
import { ClientAttestation } from "../src/index.js";

const pfHost = process.argv[2] ?? "http://pingfederate.pf:9080";

// Optional: ask for a specific entitlement (RFC 9396). The attester grants at most what the workload
// is allowed. Omit to take the full attested ceiling.
const ca = new ClientAttestation(pfHost, {
  allowInsecure: process.env.ALLOW_INSECURE === "1",
  authorizationDetails: [{ type: "sales_agent", sales_regions: ["EMEA"] }],
});

const token = await ca.token();
console.log("access token (first 40 chars):", token.slice(0, 40), "...");
console.log("Authorization header:", (await ca.requestHeaders("GET", "https://api.example.com/")).Authorization.slice(0, 47), "...");

// A second call returns the cached token until it nears expiry — no new attestation is minted.
if ((await ca.token()) !== token) throw new Error("expected the cached token");
