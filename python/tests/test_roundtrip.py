import json

import jwt

from client_attestation_sdk import (
    ClientAttestationBuilder,
    ClientAttestationCredential,
    DpopProofBuilder,
    PopBuilder,
    SigningKeyPair,
)
from client_attestation_sdk.builders import ATTESTATION_TYP, DPOP_TYP, POP_TYP

ATTESTER_ISS = "https://attester.example.com"
CLIENT_ID = "https://rp.example.com"
AUDIENCE = "https://as.example.com"
TOKEN_ENDPOINT = "https://as.example.com/as/token.oauth2"


def _public(key: SigningKeyPair):
    return jwt.get_algorithm_by_name(key.algorithm).from_jwk(json.dumps(key.public_jwk()))


def test_attestation_binds_instance_key():
    attester = SigningKeyPair.generate("ES256")
    instance = SigningKeyPair.generate("ES256")
    attestation = (
        ClientAttestationBuilder(attester, ATTESTER_ISS)
        .client_id(CLIENT_ID)
        .confirmation_key(instance)
        .expires_in(300)
        .build()
    )
    assert jwt.get_unverified_header(attestation)["typ"] == ATTESTATION_TYP
    claims = jwt.decode(attestation, _public(attester), algorithms=["ES256"])
    assert claims["iss"] == ATTESTER_ISS
    assert claims["sub"] == CLIENT_ID
    assert claims["cnf"]["jwk"]["x"] == instance.public_jwk()["x"]


def test_pop_carries_aud_jti_iat_and_verifies_with_instance_key():
    instance = SigningKeyPair.generate("ES256")
    pop = PopBuilder(instance).client_id(CLIENT_ID).audience(AUDIENCE).build()
    assert jwt.get_unverified_header(pop)["typ"] == POP_TYP
    claims = jwt.decode(pop, _public(instance), algorithms=["ES256"], audience=AUDIENCE)
    assert claims["aud"] == AUDIENCE
    assert claims["iss"] == CLIENT_ID
    assert "jti" in claims and "iat" in claims


def test_dpop_embeds_public_jwk_header():
    instance = SigningKeyPair.generate("ES256")
    dpop = DpopProofBuilder(instance).method("POST").uri(TOKEN_ENDPOINT).build()
    header = jwt.get_unverified_header(dpop)
    assert header["typ"] == DPOP_TYP
    assert "jwk" in header and "d" not in header["jwk"]
    claims = jwt.decode(dpop, _public(instance), algorithms=["ES256"])
    assert claims["htm"] == "POST"
    assert claims["htu"] == TOKEN_ENDPOINT
    assert "jti" in claims and "iat" in claims


def test_credential_produces_both_header_sets():
    attester = SigningKeyPair.generate("ES256")
    instance = SigningKeyPair.generate("ES256")
    attestation = (
        ClientAttestationBuilder(attester, ATTESTER_ISS)
        .client_id(CLIENT_ID)
        .confirmation_key(instance)
        .expires_in(300)
        .build()
    )
    cred = ClientAttestationCredential(attestation, instance)
    pop_headers = cred.pop_headers(CLIENT_ID, AUDIENCE)
    dpop_headers = cred.dpop_headers("POST", TOKEN_ENDPOINT)
    assert pop_headers["OAuth-Client-Attestation"] == attestation
    assert "OAuth-Client-Attestation-PoP" in pop_headers
    assert dpop_headers["OAuth-Client-Attestation"] == attestation
    assert "DPoP" in dpop_headers
