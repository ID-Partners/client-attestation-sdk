"""Validator configuration."""
from __future__ import annotations

DEFAULT_ALGORITHMS = ("ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512")
# RFC 9068 section 2.1: a JWT access token's typ is at+jwt (the application/ prefix is optional)
DEFAULT_TOKEN_TYPES = ("at+jwt",)


class IntrospectionConfig:
    """RFC 7662 introspection endpoint + client credentials (the resource server authenticating to the AS)."""

    def __init__(self, endpoint, client_id, client_secret, auth_method="client_secret_basic"):
        self.endpoint = endpoint
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_method = auth_method  # "client_secret_basic" | "client_secret_post"


class ValidatorConfig:
    """What this resource server accepts: the trusted issuer, its own audience identifier(s), the signing
    keys (static ``jwks`` or a ``jwks_uri`` to fetch), required scopes, accepted algorithms, clock leeway,
    and optional introspection.

    ``issuer`` and ``audiences`` are required: a validator that skips either accepts tokens minted for
    someone else. ``accepted_token_types`` is checked against the JWT ``typ`` header when the token carries
    one, so an ID token can't stand in for an access token. Pass ``None`` to turn that check off for an
    issuer that stamps something other than ``at+jwt``.

    An explicitly empty ``accepted_algorithms`` or ``accepted_token_types`` accepts nothing, and
    ``leeway_seconds=0`` allows no clock skew: only an omitted argument takes the default. ``none`` and the
    ``HS*`` algorithms are refused even when listed (see validation/SEMANTICS.md)."""

    def __init__(self, issuer, audiences, *, jwks=None, jwks_uri=None, required_scopes=None,
                 accepted_algorithms=DEFAULT_ALGORITHMS, leeway_seconds=60, introspection=None,
                 accepted_token_types=DEFAULT_TOKEN_TYPES):
        if not issuer:
            raise ValueError("issuer is required")
        self.issuer = issuer
        self.audiences = [audiences] if isinstance(audiences, str) else list(audiences or [])
        if not self.audiences:
            raise ValueError("at least one audience is required")
        self.accepted_token_types = (
            None if accepted_token_types is None else tuple(_normalise_type(t) for t in accepted_token_types))
        self.jwks = jwks
        self.jwks_uri = jwks_uri
        self.required_scopes = list(required_scopes or [])
        self.accepted_algorithms = tuple(accepted_algorithms)
        self.leeway_seconds = leeway_seconds
        self.introspection = introspection


def _is_forbidden_algorithm(alg):
    """``none`` (in any case) and the HMAC algorithms are refused whatever ``accepted_algorithms`` says: an
    unsigned token proves nothing, and an HMAC "signature" checked against an issuer's public key is forgeable
    by anyone who has that key."""
    lowered = alg.lower()
    return lowered == "none" or lowered.startswith("hs")


def _normalise_type(value):
    """Compare JOSE typ values the way RFC 7515 section 4.1.9 says to: case-insensitively, with an optional
    ``application/`` prefix."""
    value = str(value).lower()
    return value[len("application/"):] if value.startswith("application/") else value
