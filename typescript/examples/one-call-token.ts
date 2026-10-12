/**
 * Get an access token with client attestation in one call.
 *
 * Point it at a PingFederate host. The SDK auto-detects the workload's platform identity (a projected
 * token file, a SPIRE socket, the GCP metadata server, or an env token), runs the whole attestation
 * flow, and returns an access token. No client_id, no client secret.
 *
 *   EVIDENCE_AUDIENCE=https://attester.example.com npx tsx examples/one-call-token.ts pf.example.com
 *   ALLOW_INSECURE=1 EVIDENCE_AUDIENCE=... npx tsx examples/one-call-token.ts http://pingfederate.pf.svc.cluster.local:9080   # in-cluster, plain HTTP
 *
 * EVIDENCE_AUDIENCE is the audience your attester expects the workload's identity token for; the
 * attester's discovery document must name the same one.
 *
 * Use it with an HTTP client:
 *
 *   const ca = new ClientAttestation("pf.example.com", { evidenceAudience: "https://attester.example.com" });
 *   await ca.fetch("https://api.example.com/things");  // Authorization (+ a DPoP proof for a DPoP-bound token)
 *   await ca.requestHeaders("GET", "https://api.example.com/things");  // the same headers, for any client
 *
 * Plain http is refused for anything but loopback unless you pass `allowInsecure: true`
 * (here: set ALLOW_INSECURE=1).
 */
import { createHash } from "node:crypto";

import { ClientAttestation } from "../src/index.js";

const attesterUrl = process.argv[2] ?? "https://pf.example.com";

// Optional: ask for a specific entitlement (RFC 9396). The attester grants at most what the workload
// is allowed. Omit to take the full attested ceiling.
const ca = new ClientAttestation(attesterUrl, {
  evidenceAudience: process.env.EVIDENCE_AUDIENCE ?? "https://attester.example.com",
  allowInsecure: process.env.ALLOW_INSECURE === "1",
  authorizationDetails: [{ type: "sales_agent", sales_regions: ["EMEA"] }],
});

const token = await ca.token();
// Never print the token itself: an opaque token is short enough that any prefix may be all of it.
console.log(`access token: ${token.length} chars, sha256 ${createHash("sha256").update(token).digest("hex").slice(0, 12)}`);
console.log("Authorization scheme:", (await ca.requestHeaders("GET", "https://api.example.com/")).Authorization.split(" ")[0]);

// A second call returns the cached token until it nears expiry — no new attestation is minted.
if ((await ca.token()) !== token) throw new Error("expected the cached token");
