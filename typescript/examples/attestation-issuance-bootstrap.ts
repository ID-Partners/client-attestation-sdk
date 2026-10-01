/**
 * Bootstrap a Client Attestation from a workload's SPIFFE identity, then use it to get a token.
 *
 *   ISSUER=http://localhost:9031 USE_DEV_SVID=1 npx tsx examples/attestation-issuance-bootstrap.ts
 *
 * In production use `new SpireWorkloadApiSvidSource()` (the default) against a real agent.
 */
import {
  AttestationIssuanceClient,
  HttpSvidSource,
  SpireWorkloadApiSvidSource,
  StaticSvidSource,
  type SvidSource,
} from "../src/index.js";

const ISSUER = (process.env.ISSUER ?? "http://localhost:9031").replace(/\/$/, "");
const CLIENT_ID = process.env.CLIENT_ID ?? "https://payment-agent.banking.demo";
const ATTESTER = process.env.ATTESTER_ISSUER ?? "https://attester.banking.demo";
const OP_ISSUER = process.env.OP_ISSUER ?? "https://as.banking.demo";

function svidSource(): SvidSource {
  if (process.env.SVID_JWT) return new StaticSvidSource(process.env.SVID_JWT);
  if (process.env.USE_DEV_SVID === "1") return new HttpSvidSource(`${ISSUER}/dev/svid`);
  return new SpireWorkloadApiSvidSource();
}

const client = await AttestationIssuanceClient.create(
  `${ISSUER}/federation/attestation`, CLIENT_ID, ATTESTER, svidSource(),
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
});
const tok = (await res.json()) as { access_token?: string };
console.log(`token endpoint    : HTTP ${res.status}  access_token=${(tok.access_token ?? "").slice(0, 32)}…`);
console.log(tok.access_token ? "BOOTSTRAP OK" : "no token");
process.exit(tok.access_token ? 0 : 1);
