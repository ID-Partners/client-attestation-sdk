"""Validator configuration."""
from __future__ import annotations

import copy
import urllib.parse

DEFAULT_ALGORITHMS = ("ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512")
# RFC 9068 section 2.1: a JWT access token's typ is at+jwt (the application/ prefix is optional)
DEFAULT_TOKEN_TYPES = ("at+jwt",)
# the hosts the client exempts from its https rule (token_source._LOOPBACK_HOSTS)
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


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
    ``HS*`` algorithms are refused even when listed (see validation/SEMANTICS.md).

    ``jwks_uri`` and the introspection endpoint must use https unless their host is loopback (``localhost``,
    ``127.0.0.1``, ``::1``) or ``allow_insecure=True``: over plain http anyone on the path could serve their
    own keys, or read the resource server's client secret. ``leeway_seconds`` must be a non-negative
    ``int``, and the list options must be lists (or tuples) of strings, not a bare string."""

    def __init__(self, issuer, audiences, *, jwks=None, jwks_uri=None, required_scopes=None,
                 accepted_algorithms=DEFAULT_ALGORITHMS, leeway_seconds=60, introspection=None,
                 accepted_token_types=DEFAULT_TOKEN_TYPES, allow_insecure=False):
        if not issuer:
            raise ValueError("issuer is required")
        self.issuer = issuer
        self.audiences = [audiences] if isinstance(audiences, str) else _string_list(audiences or [], "audiences")
        if not self.audiences:
            raise ValueError("at least one audience is required")
        # NaN would make every exp/nbf/iat comparison false, i.e. no time check at all
        if isinstance(leeway_seconds, bool) or not isinstance(leeway_seconds, int) or leeway_seconds < 0:
            raise ValueError("leeway_seconds must be a non-negative int")
        if not isinstance(allow_insecure, bool):
            raise ValueError("allow_insecure must be a bool")
        if jwks_uri:
            _require_https(jwks_uri, "jwks_uri", allow_insecure)
        if introspection is not None and introspection.endpoint:
            _require_https(introspection.endpoint, "introspection endpoint", allow_insecure)
        self.accepted_token_types = (
            None if accepted_token_types is None
            else tuple(_normalise_type(t) for t in _string_list(accepted_token_types, "accepted_token_types")))
        self.jwks = jwks
        self.jwks_uri = jwks_uri
        self.required_scopes = _string_list(required_scopes or [], "required_scopes")
        self.accepted_algorithms = tuple(_string_list(accepted_algorithms, "accepted_algorithms"))
        self.leeway_seconds = leeway_seconds
        self.introspection = introspection
        self.allow_insecure = allow_insecure

    def _checked_copy(self):
        """A copy that shares nothing mutable with this config, built through the constructor so every check
        runs again on the current values (a config changed after construction is refused, not trusted).
        ``accepted_token_types`` is already normalised, so it is checked but not normalised a second time
        (``application/application/x`` must stay ``application/x``)."""
        introspection = self.introspection
        if introspection is not None:
            introspection = IntrospectionConfig(introspection.endpoint, introspection.client_id,
                                                introspection.client_secret, introspection.auth_method)
        own = ValidatorConfig(
            self.issuer, self.audiences, jwks=copy.deepcopy(self.jwks), jwks_uri=self.jwks_uri,
            required_scopes=self.required_scopes, accepted_algorithms=self.accepted_algorithms,
            leeway_seconds=self.leeway_seconds, introspection=introspection, accepted_token_types=None,
            allow_insecure=self.allow_insecure)
        if self.accepted_token_types is not None:
            own.accepted_token_types = tuple(_string_list(self.accepted_token_types, "accepted_token_types"))
        return own


def _string_list(value, what):
    """``value`` as a list of strings. A bare string is refused: it would iterate as its characters, so
    ``accepted_token_types="at+jwt"`` would accept a ``typ`` of ``"t"``."""
    if isinstance(value, (str, bytes)):
        raise ValueError(f"{what} must be a list of strings, not a single string")
    try:
        items = list(value)
    except TypeError:
        raise ValueError(f"{what} must be a list of strings") from None
    if not all(isinstance(item, str) for item in items):
        raise ValueError(f"{what} must be a list of strings")
    return items


def _require_https(url, what, allow_insecure):
    """Refuse a non-https URL unless it is plain http to a loopback host or ``allow_insecure`` is set: the
    rule the client applies to its own endpoints."""
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme == "https" or allow_insecure:
        return
    if scheme == "http" and (parts.hostname or "").lower() in _LOOPBACK_HOSTS:
        return
    raise ValueError(f"{what} must use https: {url} (plain http is allowed only for loopback hosts, "
                     "or pass allow_insecure=True)")


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
