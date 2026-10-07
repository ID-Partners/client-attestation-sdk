"""Minimal AS-metadata discovery (RFC 8414 / OpenID Connect Discovery)."""
from __future__ import annotations

import json

from client_attestation_sdk import _http


def _default_get(url):
    return _http.text_ok(_http.request("GET", url, timeout=10), "metadata endpoint")


def discover(metadata_url, http_get=None):
    """Fetch an authorization-server metadata document, e.g.
    ``https://issuer.example.com/.well-known/oauth-authorization-server``. The returned dict carries
    ``issuer``, ``jwks_uri`` and ``introspection_endpoint`` to feed into a
    :class:`~client_attestation_sdk.token_validator.config.ValidatorConfig`."""
    get = http_get or _default_get
    return json.loads(get(metadata_url))
