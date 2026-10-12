"""What the builders, key import and signer seam refuse to put into a signed credential."""
import base64
import json

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from client_attestation_sdk import ClientAttestationBuilder, DpopProofBuilder, MintRequest, PopBuilder, SigningKeyPair
from client_attestation_sdk.builders import ATTESTATION_TYP, DPOP_TYP, POP_TYP

ISS = "https://attester.example.com"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _private_jwk(key) -> dict:
    alg = "ES256" if isinstance(key, ec.EllipticCurvePrivateKey) else "RS256"
    return json.loads(jwt.get_algorithm_by_name(alg).to_jwk(key))


def _segments(token: str):
    header, payload, _ = token.split(".")
    return json.loads(_unb64(header)), json.loads(_unb64(payload))


@pytest.mark.parametrize("cnf", [
    pytest.param(_private_jwk(ec.generate_private_key(ec.SECP256R1())), id="EC private"),
    pytest.param(_private_jwk(rsa.generate_private_key(public_exponent=65537, key_size=2048)), id="RSA private"),
    pytest.param({"kty": "oct", "k": "c2VjcmV0"}, id="oct"),
    pytest.param({"kty": "oct"}, id="oct without k"),
    pytest.param({"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}, id="OKP"),
    pytest.param({"kty": "EC", "crv": "P-256", "x": "AAAA"}, id="EC missing y"),
    pytest.param({"kty": "EC", "crv": "secp256k1", "x": "AAAA", "y": "AAAA"}, id="EC bad curve"),
])
def test_attestation_refuses_private_or_symmetric_confirmation_jwk(cnf):
    attester = SigningKeyPair.generate("ES256")
    with pytest.raises(ValueError, match="cnf.jwk"):
        ClientAttestationBuilder(attester, ISS).client_id("c").confirmation_jwk(cnf).expires_in(300).build()


def test_attestation_confirmation_jwk_keeps_only_public_members():
    attester, instance = SigningKeyPair.generate("ES256"), SigningKeyPair.generate("ES256")
    cnf = {**instance.public_jwk(), "use": "sig", "x5u": "https://example.com/x5u"}
    token = ClientAttestationBuilder(attester, ISS).client_id("c").confirmation_jwk(cnf).expires_in(300).build()
    assert _segments(token)[1]["cnf"]["jwk"] == instance.public_jwk()


@pytest.mark.parametrize("configure", [
    pytest.param(lambda b: b.expires_in(-100), id="negative ttl"),
    pytest.param(lambda b: b.expires_in(0), id="zero ttl"),
    pytest.param(lambda b: b.issued_at(1700000000).expires_at(1699999999), id="exp < iat"),
])
def test_attestation_refuses_expiry_not_after_issued_at(configure):
    attester, instance = SigningKeyPair.generate("ES256"), SigningKeyPair.generate("ES256")
    builder = ClientAttestationBuilder(attester, ISS).client_id("c").confirmation_key(instance)
    with pytest.raises(ValueError, match="after iat"):
        configure(builder).build()


def test_from_jwk_header_kid_is_always_the_thumbprint():
    jwk = {**_private_jwk(ec.generate_private_key(ec.SECP256R1())), "kid": "label"}
    key = SigningKeyPair.from_jwk(jwk, "ES256")
    assert _segments(PopBuilder(key).audience("https://as.example.com").build())[0]["kid"] == key.key_id


@pytest.mark.parametrize("raw, alg", [
    pytest.param(ec.generate_private_key(ec.SECP256R1()), "ES256", id="ES256"),
    pytest.param(ec.generate_private_key(ec.SECP384R1()), "ES384", id="ES384"),
    pytest.param(ec.generate_private_key(ec.SECP521R1()), "ES512", id="ES512"),
    pytest.param(rsa.generate_private_key(public_exponent=65537, key_size=2048), "RS256", id="RS256"),
    pytest.param(rsa.generate_private_key(public_exponent=65537, key_size=2048), "PS256", id="PS256"),
])
def test_dpop_jwk_is_the_confirmation_jwk_without_kid(raw, alg):
    instance = SigningKeyPair.from_jwk({**_private_jwk(raw), "kid": "caller-label", "use": "sig"}, alg)
    attestation = (ClientAttestationBuilder(SigningKeyPair.generate("ES256"), ISS)
                   .client_id("c").confirmation_key(instance).expires_in(300).build())
    cnf_jwk = _segments(attestation)[1]["cnf"]["jwk"]
    assert cnf_jwk["kid"] == instance.key_id
    header = _segments(DpopProofBuilder(instance).method("POST").uri("https://as.example.com/token").build())[0]
    assert "kid" not in header
    assert "kid" not in header["jwk"]
    assert header["jwk"] == {k: v for k, v in cnf_jwk.items() if k != "kid"}


def _swapped_ec():
    jwk = _private_jwk(ec.generate_private_key(ec.SECP256R1()))
    other = _private_jwk(ec.generate_private_key(ec.SECP256R1()))
    return {**jwk, "x": other["x"], "y": other["y"]}


def _swapped_rsa():
    jwk = _private_jwk(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    other = _private_jwk(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    return {k: v for k, v in {**jwk, "n": other["n"]}.items() if k in ("kty", "n", "e", "d")}


@pytest.mark.parametrize("jwk, alg", [
    pytest.param(_private_jwk(ec.generate_private_key(ec.SECP384R1())), "ES256", id="P-384 as ES256"),
    pytest.param(_private_jwk(ec.generate_private_key(ec.SECP256R1())), "ES384", id="P-256 as ES384"),
    pytest.param(_private_jwk(ec.generate_private_key(ec.SECP256R1())), "RS256", id="EC as RS256"),
    pytest.param(_private_jwk(rsa.generate_private_key(public_exponent=65537, key_size=2048)), "ES256",
                 id="RSA as ES256"),
    pytest.param(_private_jwk(rsa.generate_private_key(public_exponent=65537, key_size=1024)), "RS256",
                 id="RSA-1024 as RS256"),
    pytest.param(_private_jwk(rsa.generate_private_key(public_exponent=65537, key_size=1024)), "PS256",
                 id="RSA-1024 as PS256"),
    pytest.param(_swapped_ec(), "ES256", id="EC x/y of another key"),
    pytest.param(_swapped_rsa(), "RS256", id="RSA n of another key"),
    pytest.param(_private_jwk(ec.generate_private_key(ec.SECP256R1())), "none", id="alg none"),
    pytest.param(_private_jwk(ec.generate_private_key(ec.SECP256R1())), "HS256", id="alg HS256"),
])
def test_from_jwk_refuses_keys_the_algorithm_cannot_use(jwk, alg):
    with pytest.raises(ValueError):
        SigningKeyPair.from_jwk(jwk, alg)


def test_from_jwk_publishes_canonical_public_jwk():
    while True:
        key = ec.generate_private_key(ec.SECP256R1())
        if key.public_key().public_numbers().x < 1 << 248:
            break
    full = _private_jwk(key)
    numbers = key.private_numbers()
    x = numbers.public_numbers.x
    short = {**full, "x": _b64(x.to_bytes((x.bit_length() + 7) // 8, "big"))}
    from_short = SigningKeyPair.from_jwk(short, "ES256")
    assert len(_unb64(from_short.public_jwk()["x"])) == 32
    assert from_short.key_id == SigningKeyPair.from_jwk(full, "ES256").key_id

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    minimal = _private_jwk(rsa_key)
    padded = {**minimal, "n": _b64(b"\0" + _unb64(minimal["n"]))}
    from_padded = SigningKeyPair.from_jwk(padded, "RS256")
    assert from_padded.public_jwk() == {"kty": "RSA", "n": minimal["n"], "e": minimal["e"],
                                        "kid": from_padded.key_id}
    assert from_padded.key_id == SigningKeyPair.from_jwk(minimal, "RS256").key_id


class _FixedSigner:
    key_id = "fixed-kid"

    def __init__(self, algorithm, signature):
        self.algorithm = algorithm
        self._signature = signature

    def public_jwk(self):
        return {}

    def sign(self, signing_input):
        return self._signature


@pytest.mark.parametrize("alg, signature", [
    pytest.param("none", b"", id="alg none, empty signature"),
    pytest.param("HS256", bytes(32), id="alg HS256"),
    pytest.param("ES256", b"", id="empty ES256 signature"),
    pytest.param("ES256", b"\x30\x44\x02\x20" + bytes(66), id="DER ES256 signature"),
    pytest.param("ES384", bytes(64), id="truncated ES384 signature"),
    pytest.param("RS256", b"", id="empty RS256 signature"),
])
def test_external_signer_must_produce_a_real_signature(alg, signature):
    instance = SigningKeyPair.generate("ES256")
    with pytest.raises(ValueError):
        ClientAttestationBuilder(_FixedSigner(alg, signature), ISS).client_id("c") \
            .confirmation_key(instance).expires_in(60).build()


def test_external_signer_with_raw_signature_builds():
    instance = SigningKeyPair.generate("ES256")
    assert ClientAttestationBuilder(_FixedSigner("ES256", bytes(64)), ISS).client_id("c") \
        .confirmation_key(instance).expires_in(60).build()


@pytest.mark.parametrize("typ", [POP_TYP, DPOP_TYP, ATTESTATION_TYP, "application/" + POP_TYP,
                                 "OAuth-Client-Attestation-PoP+JWT"])
def test_mint_request_sign_refuses_reserved_typ(typ):
    request = MintRequest(instance_key=SigningKeyPair.generate("ES256"), evidence="svid")
    with pytest.raises(ValueError, match="reserved"):
        request.sign({"aud": "https://as.example.com", "jti": "j", "iat": 1}, typ)
    with pytest.raises(ValueError, match="reserved"):
        request.instance_proof(typ, "https://as.example.com")


def test_mint_request_sign_allows_a_profile_typ():
    request = MintRequest(instance_key=SigningKeyPair.generate("ES256"), evidence="svid")
    assert request.sign({"aud": "a"}, "oauth-attestation-instance-proof+jwt")
