"""Credential redaction, shared by the curl trace (`ClientAttestation(trace=...)`) and the loggers."""
from __future__ import annotations

import json
import re

# Header names and JSON/form members whose values are credentials.
SECRET_HEADERS = frozenset(h.lower() for h in ("Authorization", "DPoP", "OAuth-Client-Attestation",
                                               "OAuth-Client-Attestation-PoP"))
SECRET_FIELDS = frozenset({"svid", "proof", "assertion", "client_assertion", "subject_token", "actor_token",
                           "client_secret", "attestation", "access_token", "refresh_token", "id_token"})
PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "k", "oth"})

# The logging backstop (docs/logging.md, the same rule in every port). A log attribute is redacted when
# its key names a credential, or its value carries one this SDK handles. Keys are matched in lower case.
LOG_SECRET_KEYS = SECRET_FIELDS | SECRET_HEADERS | frozenset({
    "auth_req_id", "code", "handle", "token", "secret", "password", "private_key", "vault_token",
    "x-vault-token"})
LOG_SECRET_KEY_SUFFIXES = ("_token", "-token", "_secret", "-secret", "_password")
# Vault/OpenBao tokens: hvs./hvb./hvr. and the older s./b./r. forms, standing alone (not inside a longer
# word or dotted name).
_VAULT_TOKEN = re.compile(r"(?:^|[^A-Za-z0-9._-])"
                          r"(?:hv[sbr]\.[A-Za-z0-9_-]{20,}|[sbr]\.[A-Za-z0-9_-]{24,}(?:$|[^A-Za-z0-9._-]))")
# An Authorization header value anywhere in the string: a scheme this SDK sends, standing alone, then
# whitespace and the first character of a credential ("Bearer x", " Bearer x", "Authorization: Bearer x").
# A bare scheme name ("Bearer", "token_type=Bearer", "dpop_combined") is not one.
_AUTH_SCHEME = re.compile(r"(?:^|[^A-Za-z0-9_-])(?:bearer|dpop|basic)[ \t]+[A-Za-z0-9._~+/-]", re.IGNORECASE)


def redacted(value) -> str:
    raw = value if isinstance(value, str) else json.dumps(value, default=str)
    return f"<redacted:{len(raw.encode('utf-8'))} bytes>"


def redact_json(value):
    """A copy of a request body with credential members (and private JWK members) redacted, and any other
    string that looks like a JWT: a custom attester profile may send evidence or a proof under a member
    name not listed here."""
    if isinstance(value, list):
        return [redact_json(item) for item in value]
    if not isinstance(value, dict):
        return redacted(value) if looks_like_jwt(value) else value
    is_jwk = "kty" in value
    return {key: redacted(item) if key in SECRET_FIELDS or (is_jwk and key in PRIVATE_JWK_MEMBERS)
            else redact_json(item) for key, item in value.items()}


def looks_like_jwt(value) -> bool:
    """A string that is, or embeds, a compact JWS/JWT (its header is base64url JSON, so it starts ``eyJ``)."""
    return isinstance(value, str) and "eyJ" in value


def is_secret_key(key) -> bool:
    """A log attribute key whose value is a credential, whatever it looks like (opaque tokens too)."""
    k = str(key).lower()
    return k in LOG_SECRET_KEYS or k.endswith(LOG_SECRET_KEY_SUFFIXES)


def looks_like_secret(value) -> bool:
    """A log attribute value that carries a credential: a JWT, a Vault/OpenBao token, or an
    ``Authorization`` header value."""
    return isinstance(value, str) and (looks_like_jwt(value) or _VAULT_TOKEN.search(value) is not None
                                       or _AUTH_SCHEME.search(value) is not None)
