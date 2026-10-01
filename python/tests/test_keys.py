import json

import jwt
import pytest

from client_attestation_sdk import SigningKeyPair


def test_generate_rsa_key_signs_and_verifies():
    key = SigningKeyPair.generate("RS256")
    public_jwk = key.public_jwk()
    assert public_jwk["kty"] == "RSA"
    assert public_jwk["kid"] == key.key_id
    token = jwt.encode({"sub": "x"}, key.private_key, algorithm="RS256")
    public = jwt.get_algorithm_by_name("RS256").from_jwk(json.dumps(public_jwk))
    assert jwt.decode(token, public, algorithms=["RS256"])["sub"] == "x"


def test_generate_rejects_unsupported_algorithm():
    with pytest.raises(ValueError, match="unsupported signing algorithm"):
        SigningKeyPair.generate("HS256")


def test_thumbprint_rejects_unsupported_key_type():
    with pytest.raises(ValueError, match="unsupported key type"):
        SigningKeyPair(None, "HS256", {"kty": "oct", "k": "c2VjcmV0"})


def test_from_jwk_wraps_private_key_with_same_thumbprint():
    original = SigningKeyPair.generate("ES256")
    private_jwk = json.loads(jwt.get_algorithm_by_name("ES256").to_jwk(original.private_key))
    restored = SigningKeyPair.from_jwk(private_jwk, "ES256")
    assert restored.key_id == original.key_id
    assert restored.public_jwk()["x"] == original.public_jwk()["x"]


def test_from_jwk_requires_private_component():
    public_only = SigningKeyPair.generate("ES256").public_jwk()
    with pytest.raises(ValueError, match="private key"):
        SigningKeyPair.from_jwk(public_only, "ES256")
