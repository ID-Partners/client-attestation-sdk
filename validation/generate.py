"""Generate the shared validation vectors. Committed so all four ports validate identical bytes and must agree:

- validation/tokens.json: a fixed issuer key and pre-signed access tokens, each with exactly one defect (or
  none), plus the expected verdict. A case may carry `config` (overrides of the shared validator config:
  `accepted_algorithms`, `accepted_token_types` (null turns the typ check off), `leeway_seconds`) and `now`
  (the validator's clock, in epoch seconds). Without them the emitter uses the shared config and the real
  clock. A case may also carry `jwks` (a key set that replaces the shared one, for the key-selection cases)
  or `jwks_fetch_error` (no static key set: the validator is given a `jwks_uri` whose fetch fails with that
  message), and `expect_description` (the result's error description must be exactly this).
- validation/introspection.json: canned RFC 7662 introspection responses and the expected verdict of
  `validate_active` / `validateActive` / `ValidateActive` for each (`expect`), and of the
  `ProtectedResource.authenticate_active` guard (`expect_guard`) for the `guard` resource, whose validator
  accepts every audience in `guard.audiences`. `"raises"` means the call must fail with the port's error (an
  exception, or Go's returned error) rather than return a verdict.
- validation/config.json: validator configurations (a `jwks_uri`, an introspection `endpoint`,
  `allow_insecure`, `leeway_seconds`, each on top of the shared config) and whether building a validator from
  each must be `"accepted"` or `"refused"` with the port's config error.

validation/SEMANTICS.md says what every verdict means. Run: `python3 validation/generate.py`."""
import base64
import json
import os

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

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
EXP_SOON = IAT + 3600     # with an injected clock, for the leeway cases
MAX_SAFE = 2**53 - 1      # the largest NumericDate every port holds exactly


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jcs(value):
    """Compact JSON text, keys in insertion order."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def public_jwk(private_key, kid):
    numbers = private_key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256",
            "x": b64u(numbers.x.to_bytes(32, "big")), "y": b64u(numbers.y.to_bytes(32, "big")),
            "kid": kid, "use": "sig", "alg": "ES256"}


issuer_key = ec.generate_private_key(ec.SECP256R1())
wrong_key = ec.generate_private_key(ec.SECP256R1())
jwks = {"keys": [public_jwk(issuer_key, KID)]}
# what a key-confusion attacker uses as the HMAC secret: the issuer's public key, as published
public_pem = issuer_key.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)


def es256(signing_input, key):
    r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


HASHES = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}


def jws_sign(signing_input, key, alg):
    """Sign as `alg` says with whatever key is given, even one the algorithm shouldn't accept (an ES384
    signature made with a P-256 key: the hash is SHA-384, the signature is sized by the key's curve)."""
    digest = HASHES[alg[2:]]()
    if alg.startswith("ES"):
        size = (key.curve.key_size + 7) // 8
        r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(digest)))
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")
    if alg.startswith("PS"):
        return key.sign(signing_input, padding.PSS(padding.MGF1(digest), padding.PSS.DIGEST_LENGTH), digest)
    return key.sign(signing_input, padding.PKCS1v15(), digest)


def hs256(signing_input, secret):
    mac = hmac.HMAC(secret, hashes.SHA256())
    mac.update(signing_input)
    return mac.finalize()


def compact(header, payload, sign=None):
    """A compact JWS over raw header and payload bytes (each may be anything, including invalid JSON).
    `sign` maps the signing input to the signature bytes; it defaults to ES256 with the issuer key."""
    signing_input = (b64u(header) + "." + b64u(payload)).encode("ascii")
    signature = (sign or (lambda m: es256(m, issuer_key)))(signing_input)
    return signing_input.decode("ascii") + "." + b64u(signature)


def header(typ="at+jwt", **extra):
    h = {"alg": "ES256", "kid": KID}
    if typ is not None:
        h["typ"] = typ
    h.update(extra)
    return jcs(h)


def sign(claims, key=issuer_key, typ="at+jwt"):
    """RFC 9068 access tokens carry typ at+jwt. typ=None omits the header."""
    return compact(header(typ), jcs(claims), lambda m: es256(m, key))


def raw(payload_text, hdr=None):
    """Sign payload bytes exactly as given (str is UTF-8 encoded), for the payloads json.dumps can't make."""
    data = payload_text.encode("utf-8") if isinstance(payload_text, str) else payload_text
    return compact(hdr or header(), data)


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
base_text = jcs(base).decode("utf-8")
base_body = base_text[1:-1]   # the members, to splice raw ones in front of


def with_raw_member(member):
    """The base claims with one raw JSON member text appended (overriding nothing: names are fresh)."""
    return "{" + base_body + "," + member + "}"


def nested(depth):
    """The base claims plus a member nested so the whole payload is `depth` levels deep (the object is 1)."""
    return "{" + base_body + ',"n":' + "[" * (depth - 1) + "]" * (depth - 1) + "}"


B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def non_canonical(token):
    """The token with a padding bit set in its last character: the same bytes to a lenient decoder."""
    last = B64URL.index(token[-1])
    assert last & 0xF == 0, "an 86-character segment's last character carries 4 zero padding bits"
    return token[:-1] + B64URL[last | 1]


def case(name, token, expect, **extra):
    return {"name": name, "token": token, "expect": expect, **extra}


cases = [
    # --- the original eleven: one defect each ---
    case("valid", sign(base), "valid"),
    case("expired", sign({**base, "exp": EXP_PAST}), "expired"),
    case("not_yet_valid", sign({**base, "nbf": NBF_FUTURE}), "not_yet_valid"),
    case("wrong_issuer", sign({**base, "iss": "https://evil.example.com"}), "invalid_issuer"),
    case("wrong_audience", sign({**base, "aud": ["https://other.example.com"]}), "invalid_audience"),
    case("missing_scope", sign({**base, "scope": "write"}), "insufficient_scope"),
    case("bad_signature", sign(base, key=wrong_key), "invalid_signature"),
    case("missing_expiry", sign(without(base, "exp")), "missing_expiry"),
    case("issued_in_future", sign({**base, "iat": IAT_FUTURE}), "issued_in_future"),
    # an ID token or other generic JWT presented as an access token (RFC 9068 section 4)
    case("wrong_type", sign(base, typ="JWT"), "invalid_token_type"),
    case("no_type", sign(base, typ=None), "valid"),

    # --- compact serialisation ---
    case("not_three_segments", sign(base) + ".x", "invalid_token"),
    case("padded_segment", sign(base).replace(".", "=.", 1), "invalid_token"),
    # an 86-character signature segment ends in a character carrying 4 padding bits, which must be zero
    case("non_canonical_base64", non_canonical(sign(base)), "invalid_token"),
    # an 86-character signature segment made 89: no base64url text has a length of 1 mod 4
    case("bad_base64_length", sign(base) + "AAA", "invalid_token"),

    # --- algorithm: none and HMAC are refused whatever the config says ---
    case("alg_none_configured",
         b64u(jcs({"alg": "none", "kid": KID, "typ": "at+jwt"})) + "." + b64u(jcs(base)) + ".",
         "unsupported_algorithm", config={"accepted_algorithms": ["ES256", "none"]}),
    case("alg_none_uppercase_configured",
         b64u(jcs({"alg": "NONE", "kid": KID, "typ": "at+jwt"})) + "." + b64u(jcs(base)) + ".",
         "unsupported_algorithm", config={"accepted_algorithms": ["ES256", "NONE"]}),
    case("alg_hs256_public_key_configured",
         compact(jcs({"alg": "HS256", "kid": KID, "typ": "at+jwt"}), jcs(base), lambda m: hs256(m, public_pem)),
         "unsupported_algorithm", config={"accepted_algorithms": ["ES256", "HS256"]}),
    case("alg_hs256_public_key",
         compact(jcs({"alg": "HS256", "kid": KID, "typ": "at+jwt"}), jcs(base), lambda m: hs256(m, public_pem)),
         "unsupported_algorithm"),
    case("alg_missing", compact(jcs({"kid": KID, "typ": "at+jwt"}), jcs(base)), "unsupported_algorithm"),
    case("alg_not_string", compact(jcs({"alg": 7, "kid": KID, "typ": "at+jwt"}), jcs(base)), "unsupported_algorithm"),

    # --- configuration: an explicitly empty list accepts nothing; leeway 0 is zero ---
    case("algorithms_empty", sign(base), "unsupported_algorithm", config={"accepted_algorithms": []}),
    case("token_types_empty", sign(base), "invalid_token_type", config={"accepted_token_types": []}),
    case("token_types_empty_no_typ", sign(base, typ=None), "valid", config={"accepted_token_types": []}),
    case("token_type_check_off", sign(base, typ="JWT"), "valid", config={"accepted_token_types": None}),
    case("leeway_default_tolerates_skew", sign({**base, "exp": EXP_SOON}), "valid", now=EXP_SOON + 30),
    case("leeway_zero_expired", sign({**base, "exp": EXP_SOON}), "expired",
         config={"leeway_seconds": 0}, now=EXP_SOON + 1),
    case("leeway_zero_at_exp", sign({**base, "exp": EXP_SOON}), "valid",
         config={"leeway_seconds": 0}, now=EXP_SOON),
    case("leeway_zero_nbf", sign({**base, "exp": EXP_SOON, "nbf": EXP_SOON - 10}), "not_yet_valid",
         config={"leeway_seconds": 0}, now=EXP_SOON - 11),

    # --- header: a strict JSON object, no duplicate names, no crit ---
    case("header_not_json", compact(b"not json", jcs(base)), "invalid_token"),
    case("header_not_object", compact(b'["ES256"]', jcs(base)), "invalid_token"),
    case("header_duplicate_alg",
         compact(b'{"alg":"none","alg":"ES256","kid":"' + KID.encode() + b'","typ":"at+jwt"}', jcs(base)),
         "invalid_token"),
    case("header_crit", compact(header(crit=["exp"], exp=EXP_FUTURE), jcs(base)), "invalid_token"),
    case("header_kid_not_string", compact(jcs({"alg": "ES256", "kid": 2024, "typ": "at+jwt"}), jcs(base)),
         "key_not_found"),
    case("header_kid_empty", compact(jcs({"alg": "ES256", "kid": "", "typ": "at+jwt"}), jcs(base)), "key_not_found"),
    case("header_kid_absent", compact(jcs({"alg": "ES256", "typ": "at+jwt"}), jcs(base)), "valid"),
    case("header_typ_not_string", compact(jcs({"alg": "ES256", "kid": KID, "typ": 1}), jcs(base)),
         "invalid_token_type"),
    case("header_typ_boolean_listed", compact(jcs({"alg": "ES256", "kid": KID, "typ": True}), jcs(base)),
         "invalid_token_type", config={"accepted_token_types": ["true", "at+jwt"]}),
    case("header_typ_not_string_check_off", compact(jcs({"alg": "ES256", "kid": KID, "typ": 1}), jcs(base)),
         "valid", config={"accepted_token_types": None}),
    case("header_typ_null", compact(jcs({"alg": "ES256", "kid": KID, "typ": None}), jcs(base)), "valid"),
    case("header_typ_application_prefix", sign(base, typ="application/AT+JWT"), "valid"),

    # --- payload: valid signature, but not a strict JSON object -> invalid_token ---
    case("payload_not_json", raw("this is not JSON"), "invalid_token"),
    case("payload_array", raw('["iss","sub"]'), "invalid_token"),
    case("payload_string", raw('"' + ISSUER + '"'), "invalid_token"),
    case("payload_null", raw("null"), "invalid_token"),
    case("payload_empty", raw(""), "invalid_token"),
    case("payload_invalid_utf8", raw(base_text.encode("utf-8").replace(b"agent-1", b"agent-\xff")),
         "invalid_token"),
    case("payload_bom", raw("\ufeff" + base_text), "invalid_token"),
    case("payload_trailing_comma", raw("{" + base_body + ",}"), "invalid_token"),
    case("payload_leading_zero", raw(with_raw_member('"n":01')), "invalid_token"),
    case("payload_raw_control_char", raw(with_raw_member('"n":"a\u0001b"')), "invalid_token"),
    case("payload_nan", raw(with_raw_member('"n":NaN')), "invalid_token"),
    case("payload_trailing_data", raw(base_text + " {}"), "invalid_token"),
    case("payload_depth_64", raw(nested(64)), "valid"),
    case("payload_depth_65", raw(nested(65)), "invalid_token"),
    case("payload_depth_5000", raw(nested(5000)), "invalid_token"),

    # --- duplicate member names: rejected at any depth (RFC 7519 section 4 lets a recipient reject) ---
    case("duplicate_claim", raw('{"iss":"https://evil.example.com",' + base_body + "}"), "invalid_token"),
    case("duplicate_claim_escaped", raw('{"\\u0069ss":"https://evil.example.com",' + base_body + "}"),
         "invalid_token"),
    case("duplicate_nested_member", raw(with_raw_member('"cnf":{"jkt":"a","jkt":"b"}')), "invalid_token"),
    case("same_name_different_objects", raw(with_raw_member('"a":{"x":1},"b":{"x":1}')), "valid"),

    # --- NumericDate: a finite JSON number within +/-(2^53 - 1); fractions truncate toward zero ---
    case("exp_infinite", raw(base_text.replace(f'"exp":{EXP_FUTURE}', '"exp":1e400')), "invalid_token"),
    case("nbf_negative_infinite", raw(with_raw_member('"nbf":-1e400')), "invalid_token"),
    case("iat_infinite", raw(base_text.replace(f'"iat":{IAT}', '"iat":1e400')), "invalid_token"),
    case("exp_beyond_safe_integer", sign({**base, "exp": MAX_SAFE + 1}), "invalid_token"),
    case("exp_huge_integer", raw(base_text.replace(f'"exp":{EXP_FUTURE}', '"exp":100000000000000000000')),
         "invalid_token"),
    case("exp_max_safe_integer", sign({**base, "exp": MAX_SAFE}), "valid"),
    case("exp_fraction", sign({**base, "exp": EXP_FUTURE + 0.5}), "valid"),
    case("exp_exponent_form", raw(base_text.replace(f'"exp":{EXP_FUTURE}', '"exp":4.1024448e9')), "valid"),
    case("exp_string", sign({**base, "exp": str(EXP_FUTURE)}), "invalid_token"),
    case("exp_boolean", sign({**base, "exp": True}), "invalid_token"),
    case("exp_null", sign({**base, "exp": None}), "missing_expiry"),

    # --- claim types: fail closed rather than drop what doesn't fit ---
    case("aud_string", sign({**base, "aud": AUDIENCE}), "valid"),
    case("aud_non_string_entry", sign({**base, "aud": [AUDIENCE, 7]}), "invalid_token"),
    case("aud_number", sign({**base, "aud": 7}), "invalid_token"),
    case("aud_object", sign({**base, "aud": {"aud": AUDIENCE}}), "invalid_token"),
    case("aud_empty_array", sign({**base, "aud": []}), "invalid_audience"),
    case("aud_missing", sign(without(base, "aud")), "invalid_audience"),
    case("scope_not_string", sign({**base, "scope": ["read"]}), "invalid_token"),
    case("scp_array", sign({**without(base, "scope"), "scp": ["read", "write"]}), "valid"),
    case("scp_non_string_entry", sign({**without(base, "scope"), "scp": ["read", 7]}), "invalid_token"),
    # Microsoft Entra ID issues scp as a space-delimited string: read like scope
    case("scp_string", sign({**without(base, "scope"), "scp": "write  read"}), "valid"),
    case("scp_string_missing_scope", sign({**without(base, "scope"), "scp": "write profile"}),
         "insufficient_scope"),
    case("scp_string_tab_delimited", sign({**without(base, "scope"), "scp": "write\tread"}), "insufficient_scope"),
    case("scp_number", sign({**without(base, "scope"), "scp": 7}), "invalid_token"),
    # scope wins over scp when both are present (scp is still type-checked)
    case("scope_wins_over_scp", sign({**base, "scope": "write", "scp": "read"}), "insufficient_scope"),
    case("scp_bad_beside_scope", sign({**base, "scp": [7]}), "invalid_token"),
    case("scope_extra_spaces", sign({**base, "scope": "  write   read "}), "valid"),
    case("scope_tab_delimited", sign({**base, "scope": "write\tread"}), "insufficient_scope"),
    case("scope_nbsp_delimited", sign({**base, "scope": "write\u00a0read"}), "insufficient_scope"),
    case("huge_number_claim", raw(with_raw_member('"n":' + "9" * 5000)), "valid"),
    case("sub_number", sign({**base, "sub": 7}), "invalid_token"),
    case("sub_missing", sign(without(base, "sub")), "valid"),
    case("sub_null", sign({**base, "sub": None}), "valid"),
]


# --- key selection (step 3) and key use (step 4), each against its own key set ---
ALL_ALGORITHMS = ["ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]
p384_key = ec.generate_private_key(ec.SECP384R1())
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa_weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
leaked_key = ec.generate_private_key(ec.SECP256R1())   # published with its private part
ed25519_key = ed25519.Ed25519PrivateKey.generate()      # a key type a port may not read


def int_b64u(n):
    return b64u(n.to_bytes((n.bit_length() + 7) // 8, "big"))


def jwk_of(key, kid=None, alg=None, private=False, **extra):
    """A JWK for key; kid, alg and use are left out unless given, extra members are added as they are."""
    if isinstance(key, rsa.RSAPrivateKey):
        numbers = key.public_key().public_numbers()
        jwk = {"kty": "RSA", "n": int_b64u(numbers.n), "e": int_b64u(numbers.e)}
        if private:
            jwk["d"] = int_b64u(key.private_numbers().d)
    else:
        size = (key.curve.key_size + 7) // 8
        numbers = key.public_key().public_numbers()
        jwk = {"kty": "EC", "crv": {256: "P-256", 384: "P-384", 521: "P-521"}[key.curve.key_size],
               "x": b64u(numbers.x.to_bytes(size, "big")), "y": b64u(numbers.y.to_bytes(size, "big"))}
        if private:
            jwk["d"] = b64u(key.private_numbers().private_value.to_bytes(size, "big"))
    if kid is not None:
        jwk["kid"] = kid
    if alg is not None:
        jwk["alg"] = alg
    jwk.update(extra)
    return jwk


def keyset(*jwks):
    return {"keys": list(jwks)}


ABSENT = object()


def signed(key=issuer_key, alg="ES256", kid=KID, claims=None):
    """The base claims signed with key as alg, with kid in the header (ABSENT leaves it out)."""
    h = {"alg": alg}
    if kid is not ABSENT:
        h["kid"] = kid
    h["typ"] = "at+jwt"
    return compact(jcs(h), jcs(claims or base), lambda m: jws_sign(m, key, alg))


every_alg = {"accepted_algorithms": ALL_ALGORITHMS}
cases += [
    # kid absent matches only a set holding exactly one key; kid-less JWKs are distinct keys, not one
    case("kid_absent_two_kidless_keys", signed(kid=ABSENT), "key_not_found",
         jwks=keyset(jwk_of(wrong_key), jwk_of(issuer_key))),
    case("kid_absent_one_kidless_key", signed(kid=ABSENT), "valid", jwks=keyset(jwk_of(issuer_key))),
    # an empty kid names no key, not even a JWK whose kid is the empty string
    case("kid_empty_jwk_kid_empty", signed(kid=""), "key_not_found", jwks=keyset(jwk_of(issuer_key, kid=""))),
    case("kid_absent_sole_jwk_kid_empty", signed(kid=ABSENT), "valid", jwks=keyset(jwk_of(issuer_key, kid=""))),
    # duplicate kids: the first JWK with that kid that may be used for the alg, in document order
    case("kid_duplicate_first_wins", signed(), "valid",
         jwks=keyset(jwk_of(issuer_key, KID), jwk_of(wrong_key, KID))),
    case("kid_duplicate_later_ignored", signed(), "invalid_signature",
         jwks=keyset(jwk_of(wrong_key, KID), jwk_of(issuer_key, KID))),
    case("kid_duplicate_other_alg_skipped", signed(), "valid",
         jwks=keyset(jwk_of(wrong_key, KID, alg="ES384"), jwk_of(issuer_key, KID, alg="ES256"))),

    # an EC key only verifies the algorithm of its curve: P-256 ES256, P-384 ES384, P-521 ES512
    case("ec_p256_key_es384_token", signed(alg="ES384"), "invalid_signature",
         config=every_alg, jwks=keyset(jwk_of(issuer_key, KID))),
    case("ec_p256_key_declared_es384", signed(alg="ES384"), "invalid_signature",
         config=every_alg, jwks=keyset(jwk_of(issuer_key, KID, alg="ES384"))),
    case("ec_p384_key_es256_token", signed(p384_key, "ES256"), "invalid_signature",
         config=every_alg, jwks=keyset(jwk_of(p384_key, KID))),
    case("ec_p384_key_es384_token", signed(p384_key, "ES384"), "valid",
         config=every_alg, jwks=keyset(jwk_of(p384_key, KID))),
    case("ec_key_rs256_token", signed(rsa_key, "RS256"), "invalid_signature",
         config=every_alg, jwks=keyset(jwk_of(issuer_key, KID))),

    # an RSA JWK without alg verifies any RS* or PS* algorithm that is accepted; one with alg only that one
    case("rsa_algless_rs256", signed(rsa_key, "RS256"), "valid", config=every_alg, jwks=keyset(jwk_of(rsa_key, KID))),
    case("rsa_algless_rs512", signed(rsa_key, "RS512"), "valid", config=every_alg, jwks=keyset(jwk_of(rsa_key, KID))),
    case("rsa_algless_ps256", signed(rsa_key, "PS256"), "valid", config=every_alg, jwks=keyset(jwk_of(rsa_key, KID))),
    case("rsa_algless_ps384", signed(rsa_key, "PS384"), "valid", config=every_alg, jwks=keyset(jwk_of(rsa_key, KID))),
    case("rsa_declared_rs256_ps256_token", signed(rsa_key, "PS256"), "key_not_found",
         config=every_alg, jwks=keyset(jwk_of(rsa_key, KID, alg="RS256"))),
    case("rsa_key_es256_token", signed(), "invalid_signature", config=every_alg, jwks=keyset(jwk_of(rsa_key, KID))),
    # an RSA key under 2048 bits verifies nothing
    case("rsa_1024_rs256", signed(rsa_weak_key, "RS256"), "invalid_signature",
         config=every_alg, jwks=keyset(jwk_of(rsa_weak_key, KID))),
    case("rsa_1024_declared_ps256", signed(rsa_weak_key, "PS256"), "invalid_signature",
         config=every_alg, jwks=keyset(jwk_of(rsa_weak_key, KID, alg="PS256"))),

    # a JWK not meant for verifying signatures is skipped, as if it weren't in the set
    case("jwk_use_enc_skipped", signed(), "key_not_found", jwks=keyset(jwk_of(issuer_key, KID, use="enc"))),
    case("jwk_use_enc_not_counted", signed(kid=ABSENT), "valid",
         jwks=keyset(jwk_of(issuer_key, use="sig"), jwk_of(wrong_key, use="enc"))),
    case("jwk_key_ops_without_verify", signed(), "key_not_found",
         jwks=keyset(jwk_of(issuer_key, KID, key_ops=["encrypt"]))),
    case("jwk_key_ops_verify", signed(), "valid", jwks=keyset(jwk_of(issuer_key, KID, key_ops=["verify"]))),
    # key_ops holding "verify" among other operations (a JWK exported from a key pair) still verifies
    case("jwk_key_ops_sign_verify", signed(), "valid",
         jwks=keyset(jwk_of(issuer_key, KID, key_ops=["sign", "verify"]))),
    case("jwk_key_ops_verify_encrypt", signed(), "valid",
         jwks=keyset(jwk_of(issuer_key, KID, key_ops=["verify", "encrypt"]))),
    case("rsa_key_ops_sign_verify_ps256", signed(rsa_key, "PS256"), "valid",
         config=every_alg, jwks=keyset(jwk_of(rsa_key, KID, key_ops=["sign", "verify"]))),
    case("jwk_private_ec_skipped", signed(leaked_key), "key_not_found",
         jwks=keyset(jwk_of(leaked_key, KID, private=True))),
    case("jwk_private_not_counted", signed(kid=ABSENT), "valid",
         jwks=keyset(jwk_of(leaked_key, private=True), jwk_of(issuer_key))),
    case("jwk_private_rsa_skipped", signed(rsa_key, "RS256"), "key_not_found",
         config=every_alg, jwks=keyset(jwk_of(rsa_key, KID, private=True))),

    # a JWK the port can't read is left out, and the rest of the set still counts
    case("jwk_unknown_kty_skipped", signed(), "valid",
         jwks=keyset({"kty": "foo", "kid": KID}, jwk_of(issuer_key, KID))),
    # (its own kid: a port that reads Ed25519 has a key it simply doesn't use for an ES256 token)
    case("jwk_ed25519_skipped", signed(), "valid",
         jwks=keyset({"kty": "OKP", "crv": "Ed25519", "kid": "ed25519",
                      "x": b64u(ed25519_key.public_key().public_bytes(serialization.Encoding.Raw,
                                                                      serialization.PublicFormat.Raw))},
                     jwk_of(issuer_key, KID))),
    case("jwk_ec_without_y_skipped", signed(), "valid",
         jwks=keyset({k: v for k, v in jwk_of(wrong_key, KID).items() if k != "y"}, jwk_of(issuer_key, KID))),
    case("jwk_rsa_without_e_skipped", signed(), "valid",
         jwks=keyset({"kty": "RSA", "kid": KID, "n": int_b64u(rsa_key.public_key().public_numbers().n)},
                     jwk_of(issuer_key, KID))),
    case("jwk_non_object_skipped", signed(), "valid",
         jwks=keyset("not a jwk", 42, None, ["kty"], jwk_of(issuer_key, KID))),
    case("jwk_unreadable_not_counted", signed(kid=ABSENT), "valid",
         jwks=keyset({"kty": "foo"}, "not a jwk", None, jwk_of(issuer_key))),

    # a failed jwks_uri fetch never reaches the caller: the description is fixed, the detail goes to the log
    case("jwks_fetch_failed", sign(base), "key_not_found",
         jwks_fetch_error="GET https://keys.internal.example:8443/jwks failed: 503 <html>backend \ufffd</html>",
         expect_description="signing keys unavailable"),

    # a \u escape takes exactly four ASCII hex digits: not Arabic-Indic digits, not fullwidth letters
    case("header_escape_arabic_indic_digits",
         compact(b'{"alg":"ES256","kid":"' + KID.encode() + b'","typ":"at+jwt","x":"\\u' +
                 "\u0660\u0660".encode("utf-8") + b'41"}', jcs(base)), "invalid_token"),
    case("payload_escape_fullwidth_hex", raw(with_raw_member('"n":"\\u00\uff21\uff21"')), "invalid_token"),
]

names = [c["name"] for c in cases]
assert len(names) == len(set(names)), "duplicate case names"

out = {
    "_comment": "TEST ONLY. The issuer key behind these tokens was thrown away after signing; the tokens and "
                "JWKS are published test vectors. Some cases' JWKS deliberately include private JWKs (with \"d\"), "
                "throwaway keys that check a private key in a JWKS is skipped. Never trust any of them anywhere "
                "real. Semantics: SEMANTICS.md.",
    "issuer": ISSUER,
    "audience": AUDIENCE,
    "required_scopes": REQUIRED_SCOPES,
    "accepted_algorithms": ["ES256"],
    "jwks": jwks,
    "cases": cases,
}
with open(os.path.join(HERE, "tokens.json"), "w") as fh:
    json.dump(out, fh, indent=2, ensure_ascii=True)
    fh.write("\n")


def icase(name, expect, response=None, guard=None, **extra):
    """`guard` is the authenticate_active verdict, when it differs from the validate_active one."""
    c = {"name": name, "expect": expect, "expect_guard": guard or expect}
    if response is not None:
        c["response"] = response
    c.update(extra)
    return c


OTHER_RESOURCE = "https://other.example.com"
active = {"active": True, "sub": "agent-1", "scope": "read write", "aud": AUDIENCE, "client_id": "rp"}
introspection_cases = [
    icase("active", "valid", active),
    # the AS needn't return aud, but then nothing says the token is for this resource: the guard refuses it
    icase("active_no_aud", "valid", without(active, "aud"), guard="invalid_audience"),
    icase("active_aud_array", "valid", {**active, "aud": ["https://other.example.com", AUDIENCE]}),
    icase("inactive", "inactive", {"active": False}),
    # RFC 7662 section 2.2: active is a boolean; only JSON true counts
    icase("active_missing", "inactive", without(active, "active")),
    icase("active_string_true", "inactive", {**active, "active": "true"}),
    icase("active_number_one", "inactive", {**active, "active": 1}),
    icase("active_null", "inactive", {**active, "active": None}),
    icase("active_object", "inactive", {**active, "active": {"value": True}}),
    icase("missing_scope", "insufficient_scope", {**active, "scope": "write"}),
    icase("scope_not_string", "invalid_token", {**active, "scope": ["read"]}),
    icase("scp_array", "valid", {**without(active, "scope"), "scp": ["read"]}),
    icase("scp_string", "valid", {**without(active, "scope"), "scp": "read write"}),
    icase("scp_non_string_entry", "invalid_token", {**without(active, "scope"), "scp": ["read", 7]}),
    # the guard's validator accepts the other resource too, so only the guard's binding catches this
    icase("wrong_audience", "invalid_audience", {**active, "aud": OTHER_RESOURCE}),
    # a sender-constrained token needs its proof checked, which a Bearer guard can't do
    icase("cnf_jkt", "valid", {**active, "cnf": {"jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}},
          guard="invalid_token"),
    icase("cnf_x5t", "valid", {**active, "cnf": {"x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"}},
          guard="invalid_token"),
    icase("cnf_null", "valid", {**active, "cnf": None}),
    icase("aud_non_string_entry", "invalid_token", {**active, "aud": [AUDIENCE, 7]}),
    icase("sub_number", "invalid_token", {**active, "sub": 7}),
    # transport and configuration failures are errors, never a verdict
    icase("transport_error", "raises", transport_error=True),
    icase("no_endpoint", "raises", no_endpoint=True),
]
with open(os.path.join(HERE, "introspection.json"), "w") as fh:
    json.dump({
        "_comment": "Canned RFC 7662 responses fed to each port's validate_active through an injected transport, "
                    "with required_scopes and audience from tokens.json. `raises`: the call must fail with the "
                    "port's error. expect_guard: the verdict of ProtectedResource.authenticate_active for the "
                    "guard resource, whose validator accepts guard.audiences. Semantics: SEMANTICS.md.",
        "guard": {"resource": AUDIENCE, "audiences": [AUDIENCE, OTHER_RESOURCE]},
        "cases": introspection_cases,
    }, fh, indent=2, ensure_ascii=True)
    fh.write("\n")



def ccase(name, expect, **config):
    return {"name": name, "expect": expect, "config": config}


config_cases = [
    # https everywhere except the client's loopback hosts, unless allow_insecure (SEMANTICS.md, Configuration)
    ccase("jwks_uri_https", "accepted", jwks_uri=ISSUER + "/jwks"),
    ccase("jwks_uri_https_upper_case_scheme", "accepted", jwks_uri="HTTPS://issuer.example.com/jwks"),
    ccase("jwks_uri_http", "refused", jwks_uri="http://issuer.example.com/jwks"),
    ccase("jwks_uri_http_allow_insecure", "accepted", jwks_uri="http://issuer.example.com/jwks",
          allow_insecure=True),
    ccase("jwks_uri_http_localhost", "accepted", jwks_uri="http://localhost:8080/jwks"),
    ccase("jwks_uri_http_localhost_upper_case", "accepted", jwks_uri="http://LOCALHOST/jwks"),
    ccase("jwks_uri_http_127_0_0_1", "accepted", jwks_uri="http://127.0.0.1:9000/jwks"),
    ccase("jwks_uri_http_ipv6_loopback", "accepted", jwks_uri="http://[::1]:8080/jwks"),
    # only the three names are exempt, not the rest of 127/8 or a name that starts with localhost
    ccase("jwks_uri_http_127_0_0_2", "refused", jwks_uri="http://127.0.0.2/jwks"),
    ccase("jwks_uri_http_localhost_subdomain", "refused", jwks_uri="http://localhost.attacker.example/jwks"),
    ccase("jwks_uri_http_localhost_userinfo", "refused", jwks_uri="http://localhost@attacker.example/jwks"),
    ccase("jwks_uri_no_scheme", "refused", jwks_uri="issuer.example.com/jwks"),
    ccase("introspection_https", "accepted", introspection_endpoint=ISSUER + "/introspect"),
    ccase("introspection_http", "refused", introspection_endpoint="http://issuer.example.com/introspect"),
    ccase("introspection_http_allow_insecure", "accepted",
          introspection_endpoint="http://issuer.example.com/introspect", allow_insecure=True),
    ccase("introspection_http_loopback", "accepted", introspection_endpoint="http://127.0.0.1:9000/introspect"),
    ccase("leeway_zero", "accepted", leeway_seconds=0),
    ccase("leeway_negative", "refused", leeway_seconds=-1),
]
with open(os.path.join(HERE, "config.json"), "w") as fh:
    json.dump({
        "_comment": "Validator configurations on top of the shared config in tokens.json (a jwks_uri replaces the "
                    "static jwks). `accepted`: building the validator succeeds; `refused`: it fails with the "
                    "port's config error. Semantics: SEMANTICS.md, Configuration.",
        "cases": config_cases,
    }, fh, indent=2, ensure_ascii=True)
    fh.write("\n")

print(f"wrote validation/tokens.json ({len(cases)} cases), validation/introspection.json "
      f"({len(introspection_cases)} cases) and validation/config.json ({len(config_cases)} cases)")
