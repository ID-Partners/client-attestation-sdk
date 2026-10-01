"""Generate the shared token-validation vectors: a fixed issuer key and pre-signed access tokens, each with
exactly one defect (or none), plus the expected verdict. Committed as validation/tokens.json so all three
ports validate identical bytes and must agree. Run: `python3 validation/generate.py`."""
import json
import os

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

HERE = os.path.dirname(os.path.abspath(__file__))

ISSUER = "https://issuer.example.com"
AUDIENCE = "https://api.example.com"
REQUIRED_SCOPES = ["read"]
KID = "issuer-2024"

IAT = 1704067200          # 2024-01-01
EXP_FUTURE = 4102444800   # 2100-01-01  (keeps "valid" valid indefinitely)
EXP_PAST = 1577836800     # 2020-01-01
NBF_FUTURE = 4102444800   # 2100-01-01
IAT_FUTURE = 4102444800   # 2100-01-01


def public_jwk(private_key, kid):
    jwk = json.loads(jwt.get_algorithm_by_name("ES256").to_jwk(private_key.public_key()))
    jwk.update({"kid": kid, "use": "sig", "alg": "ES256"})
    return jwk


issuer_key = ec.generate_private_key(ec.SECP256R1())
wrong_key = ec.generate_private_key(ec.SECP256R1())
jwks = {"keys": [public_jwk(issuer_key, KID)]}


def sign(claims, key=issuer_key, typ="at+jwt"):
    """RFC 9068 access tokens carry typ at+jwt. typ=None omits the header (PyJWT drops a None typ rather
    than adding its default JWT)."""
    return jwt.encode(claims, key, algorithm="ES256", headers={"kid": KID, "typ": typ})


def without(claims, name):
    return {k: v for k, v in claims.items() if k != name}


base = {
    "iss": ISSUER,
    "sub": "agent-1",
    "aud": [AUDIENCE],
    "iat": IAT,
    "exp": EXP_FUTURE,
    "scope": "read write",
    "client_id": "https://rp.example.com",
}

cases = [
    {"name": "valid", "token": sign(base), "expect": "valid"},
    {"name": "expired", "token": sign({**base, "exp": EXP_PAST}), "expect": "expired"},
    {"name": "not_yet_valid", "token": sign({**base, "nbf": NBF_FUTURE}), "expect": "not_yet_valid"},
    {"name": "wrong_issuer", "token": sign({**base, "iss": "https://evil.example.com"}), "expect": "invalid_issuer"},
    {"name": "wrong_audience", "token": sign({**base, "aud": ["https://other.example.com"]}), "expect": "invalid_audience"},
    {"name": "missing_scope", "token": sign({**base, "scope": "write"}), "expect": "insufficient_scope"},
    {"name": "bad_signature", "token": sign(base, key=wrong_key), "expect": "invalid_signature"},
    {"name": "missing_expiry", "token": sign(without(base, "exp")), "expect": "missing_expiry"},
    {"name": "issued_in_future", "token": sign({**base, "iat": IAT_FUTURE}), "expect": "issued_in_future"},
    # an ID token or other generic JWT presented as an access token (RFC 9068 section 4)
    {"name": "wrong_type", "token": sign(base, typ="JWT"), "expect": "invalid_token_type"},
    {"name": "no_type", "token": sign(base, typ=None), "expect": "valid"},
]

out = {
    "_comment": "TEST ONLY. The issuer key behind these tokens was thrown away after signing; the tokens and "
                "JWKS are published test vectors. Never trust them anywhere real.",
    "issuer": ISSUER,
    "audience": AUDIENCE,
    "required_scopes": REQUIRED_SCOPES,
    "accepted_algorithms": ["ES256"],
    "jwks": jwks,
    "cases": cases,
}
with open(os.path.join(HERE, "tokens.json"), "w") as fh:
    json.dump(out, fh, indent=2)
print(f"wrote validation/tokens.json with {len(cases)} cases")
