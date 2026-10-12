"""Minimal AS-metadata discovery (RFC 8414 / OpenID Connect Discovery)."""
from __future__ import annotations

import urllib.parse

from client_attestation_sdk import _http
from client_attestation_sdk.errors import TransportError

from . import _strict
from .config import _require_https

_WELL_KNOWN = ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration")


def _default_get(url):
    return _http.text_ok(_http.request("GET", url, timeout=10), "metadata endpoint")


def discover(metadata_url, http_get=None, *, issuer=None, allow_insecure=False):
    """Fetch an authorization-server metadata document, e.g.
    ``https://issuer.example.com/.well-known/oauth-authorization-server``. The returned dict carries
    ``issuer``, ``jwks_uri`` and ``introspection_endpoint`` to feed into a
    :class:`~client_attestation_sdk.token_validator.config.ValidatorConfig`.

    The document is only returned when its ``issuer`` is the one asked for (RFC 8414 section 3.3):
    ``issuer`` exactly, or else the issuer ``metadata_url`` was built from, with
    ``/.well-known/oauth-authorization-server`` or ``/.well-known/openid-configuration`` inserted after the
    host (RFC 8414 section 3.1) or appended to the issuer (OpenID Connect Discovery section 4). For any other
    URL, pass ``issuer``. ``metadata_url`` and the returned ``jwks_uri`` and ``introspection_endpoint`` must
    use https unless their host is loopback or ``allow_insecure=True``.

    Raises :class:`ValueError` for an insecure ``metadata_url`` or one that names no issuer (before any
    request), and :class:`~client_attestation_sdk.errors.TransportError` when the fetch fails or the
    document is not a strict JSON object, names another issuer or lists a plain-http endpoint."""
    _require_https(metadata_url, "metadata URL", allow_insecure)
    derived = _expected_issuer(metadata_url) if issuer is None else None
    if issuer is None and derived is None:
        raise ValueError(f"cannot tell which issuer {metadata_url} belongs to: it is not a "
                         ".well-known/oauth-authorization-server or .well-known/openid-configuration URL, "
                         "so pass issuer=")
    get = http_get or _default_get
    text = get(metadata_url)
    try:
        metadata = _strict.parse_object(text.encode("utf-8") if isinstance(text, str) else text, "metadata")
    except _strict.Malformed as exc:
        raise TransportError(f"metadata endpoint returned {exc}") from None
    got = metadata.get("issuer")
    # the issuer a URL was built from may have lost a terminating "/" (RFC 8414 section 3.1)
    expected = (issuer,) if issuer is not None else (derived, derived + "/")
    if not isinstance(got, str) or got not in expected:
        shown = got[:512] if isinstance(got, str) else "(missing)"
        raise TransportError(f"metadata issuer {shown} is not the expected issuer {expected[0]}")
    for name in ("jwks_uri", "introspection_endpoint"):
        value = metadata.get(name)
        if value is None:
            continue
        if not isinstance(value, str):
            raise TransportError(f"metadata {name} is not a string")
        try:
            _require_https(value, f"metadata {name}", allow_insecure)
        except ValueError as exc:
            raise TransportError(str(exc)) from None
    return metadata


def _expected_issuer(metadata_url):
    """The issuer a standard metadata URL was built from, or ``None`` when it isn't one: the well-known path
    inserted after the host (RFC 8414 section 3.1, also used for ``openid-configuration``) or appended to the
    issuer's path (OpenID Connect Discovery section 4, also seen for ``oauth-authorization-server``). An
    issuer has no query or fragment."""
    try:
        parts = urllib.parse.urlsplit(metadata_url)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc or parts.query or parts.fragment:
        return None
    origin = f"{parts.scheme}://{parts.netloc}"   # urlsplit lower-cases the scheme
    path = parts.path
    for wk in _WELL_KNOWN:
        if path == wk or path.startswith(wk + "/"):
            return origin + path[len(wk):]
    for wk in _WELL_KNOWN:
        if path.endswith(wk):
            return origin + path[:-len(wk)]
    return None
