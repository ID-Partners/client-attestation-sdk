/**
 * Bootstrap a Client Attestation from a workload's SPIFFE identity, then use it to get a token.
 *
 *   ISSUER=http://localhost:9031 USE_DEV_SVID=1 npx tsx examples/attestation-issuance-bootstrap.ts
 *
 * Plain http is refused for anything but loopback unless you also set ALLOW_INSECURE=1.
 * In production use `new SpireWorkloadApiSvidSource()` (the default) against a real agent.
 */
import { createHash } from "node:crypto";

import {
  AttestationIssuanceClient,
  HttpSvidSource,
  SpireWorkloadApiSvidSource,
  StaticSvidSource,
  type SvidSource,
} from "../src/index.js";

const ISSUER = (process.env.ISSUER ?? "https://pf.example.com").replace(/\/$/, "");
const CLIENT_ID = process.env.CLIENT_ID ?? "https://payment-agent.banking.demo";
const ATTESTER = process.env.ATTESTER_ISSUER ?? "https://attester.banking.demo";
const OP_ISSUER = process.env.OP_ISSUER ?? "https://as.banking.demo";
const MAX_RESPONSE_BYTES = 1024 * 1024;

// The SVID, attestation and PoP travel to ISSUER, so it must be https (loopback excepted).
const issuerUrl = new URL(ISSUER);
if (
  issuerUrl.protocol !== "https:" &&
  process.env.ALLOW_INSECURE !== "1" &&
  !(issuerUrl.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(issuerUrl.hostname))
) {
  console.error(`ISSUER must use https: ${ISSUER} (plain http is allowed for loopback, or set ALLOW_INSECURE=1)`);
  process.exit(1);
}

function svidSource(): SvidSource {
  if (process.env.SVID_JWT) return new StaticSvidSource(process.env.SVID_JWT);
  if (process.env.USE_DEV_SVID === "1") return new HttpSvidSource(`${ISSUER}/dev/svid`);
  return new SpireWorkloadApiSvidSource();
}

function fingerprint(token: string): string {
  return `${token.length} chars, sha256 ${createHash("sha256").update(token).digest("hex").slice(0, 12)}`;
}

const client = await AttestationIssuanceClient.create(
  `${ISSUER}/federation/attestation`, CLIENT_ID, ATTESTER, svidSource(),
  { allowInsecure: process.env.ALLOW_INSECURE === "1" }, // the check above has already vetted the URL
);
const issued = await client.bootstrap([{ type: "sales_agent", sales_regions: ["EMEA"] }]);
console.log(`minted attestation: ${issued.attestation.slice(0, 48)}…  expires_in=${issued.expiresIn}`);
console.log(`instance cnf kid  : ${client.instanceKey.keyId}`);

const pop = await issued.pop(OP_ISSUER, CLIENT_ID);
const res = await fetch(`${ISSUER}/as/token.oauth2`, {
  method: "POST",
  headers: {
    "Content-Type": "application/x-www-form-urlencoded",
    "OAuth-Client-Attestation": issued.attestation,
    "OAuth-Client-Attestation-PoP": pop,
  },
  body: "grant_type=client_credentials",
  redirect: "manual", // the request carries the attestation and PoP: never replay them to wherever a 3xx points
  signal: AbortSignal.timeout(20_000),
});
if (res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)) {
  console.error(`token endpoint    : HTTP ${res.status} redirect, not followed`);
  process.exit(1);
}
const chunks: Uint8Array[] = [];
let size = 0;
for (const reader = res.body?.getReader(); reader; ) {
  const { done, value } = await reader.read();
  if (done) break;
  size += value.byteLength;
  if (size > MAX_RESPONSE_BYTES) {
    await reader.cancel();
    console.error(`token endpoint    : response larger than ${MAX_RESPONSE_BYTES} bytes`);
    process.exit(1);
  }
  chunks.push(value);
}
let tok: { access_token?: string; error?: string } = {};
try {
  tok = JSON.parse(Buffer.concat(chunks).toString("utf8"));
} catch {
  // e.g. an HTML error page
}
const accessToken = res.status === 200 ? tok.access_token : undefined;
console.log(`token endpoint    : HTTP ${res.status}  access_token=${accessToken ? fingerprint(accessToken) : (tok.error ?? "no access_token")}`);
console.log(accessToken ? "BOOTSTRAP OK" : "no token");
process.exit(accessToken ? 0 : 1);
