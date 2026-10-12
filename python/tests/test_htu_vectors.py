"""DPoP htu and nonce-origin normalisation against the shared vectors (vectors/htu.json). Every port must
agree."""
import json
import os

import jwt
import pytest

from client_attestation_sdk import DpopProofBuilder, SigningKeyPair
from client_attestation_sdk.builders import _normalize_htu
from client_attestation_sdk.token_source import _origin

VECTORS = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "vectors"))
KEY = SigningKeyPair.generate("ES256")


def _cases():
    with open(os.path.join(VECTORS, "htu.json"), encoding="utf-8") as fh:
        return json.load(fh)["cases"]


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_vector(case):
    builder = DpopProofBuilder(KEY).uri(case["url"])
    if "error" in case:
        with pytest.raises(ValueError) as raised:
            builder.build()
        assert str(raised.value) == case["error"]
        assert _origin(case["url"]) == case["url"]   # a refused URL is its own nonce key
        return
    claims = jwt.decode(builder.build(), options={"verify_signature": False})
    assert claims["htu"] == case["htu"]
    assert _normalize_htu(case["url"]) == case["htu"]
    assert _origin(case["url"]) == case["origin"]


def test_a_lone_surrogate_in_the_path_is_refused():
    # Not in htu.json: JSON parsers disagree on a lone surrogate. Go's equivalent is invalid UTF-8.
    with pytest.raises(ValueError, match=r"^uri \(htu\) has an invalid path$"):
        _normalize_htu("https://as.example.com/a\ud800")
