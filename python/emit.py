"""Emit attestation artifacts from the shared vectors, for the cross-language interop check."""
import json
import os

from client_attestation_sdk import ClientAttestationBuilder, ClientAttestationCredential, SigningKeyPair

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.normpath(os.path.join(HERE, "..", "vectors"))

with open(os.path.join(VECTORS, "inputs.json")) as fh:
    inp = json.load(fh)

attester = SigningKeyPair.from_jwk(inp["attester"]["jwk"], inp["attester"]["alg"])
instance = SigningKeyPair.from_jwk(inp["instance"]["jwk"], inp["instance"]["alg"])

attestation = (
    ClientAttestationBuilder(attester, inp["attester"]["iss"])
    .client_id(inp["client_id"])
    .confirmation_key(instance)
    .expires_in(inp["attestation_ttl_seconds"])
    .build()
)

cred = ClientAttestationCredential(attestation, instance)
pop = cred.pop_headers(inp["client_id"], inp["audience"])
dpop = cred.dpop_headers("POST", inp["token_endpoint"])

out = {
    "language": "python",
    "attestation": attestation,
    "pop": pop["OAuth-Client-Attestation-PoP"],
    "dpop": dpop["DPoP"],
    "audience": inp["audience"],
    "tokenEndpoint": inp["token_endpoint"],
    "clientId": inp["client_id"],
}

os.makedirs(os.path.join(VECTORS, "out"), exist_ok=True)
with open(os.path.join(VECTORS, "out", "python.json"), "w") as fh:
    json.dump(out, fh, indent=2)
print("wrote vectors/out/python.json")
