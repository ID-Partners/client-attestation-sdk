"""Credential redaction, shared by the curl trace (`ClientAttestation(trace=...)`) and the loggers."""
from __future__ import annotations

import json

# Header names and JSON/form members whose values are credentials.
SECRET_HEADERS = frozenset(h.lower() for h in ("Authorization", "DPoP", "OAuth-Client-Attestation",
                                               "OAuth-Client-Attestation-PoP"))
SECRET_FIELDS = frozenset({"svid", "proof", "assertion", "client_assertion", "subject_token", "actor_token",
                           "client_secret", "attestation", "access_token", "refresh_token", "id_token"})
PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "k", "oth"})


def redacted(value) -> str:
    raw = value if isinstance(value, str) else json.dumps(value)
    return f"<redacted:{len(raw.encode('utf-8'))} bytes>"


def redact_json(value):
    """A copy of a request body with credential members (and private JWK members) redacted."""
    if isinstance(value, list):
        return [redact_json(item) for item in value]
    if not isinstance(value, dict):
        return value
    is_jwk = "kty" in value
    return {key: redacted(item) if key in SECRET_FIELDS or (is_jwk and key in PRIVATE_JWK_MEMBERS)
            else redact_json(item) for key, item in value.items()}


def looks_like_jwt(value) -> bool:
    """A string that is, or embeds, a compact JWS/JWT (its header is base64url JSON, so it starts ``eyJ``)."""
    return isinstance(value, str) and "eyJ" in value
