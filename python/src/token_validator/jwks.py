"""Resolves issuer signing keys — from a static JWKS or a ``jwks_uri`` (fetched and cached, refreshed on an
unknown ``kid`` and when the cached set grows old).

A ``jwks_uri`` provider never fetches more than once per ``min_refresh_seconds``, however many unknown
``kid`` values it is shown, and concurrent misses share one fetch. Without that, a stream of tokens with
made-up ``kid`` values turns every request into a request to the issuer."""
from __future__ import annotations

import json
import threading
import time

import jwt

from client_attestation_sdk import _http

MAX_JWKS_BYTES = 512 * 1024
DEFAULT_MIN_REFRESH_SECONDS = 30
DEFAULT_MAX_AGE_SECONDS = 3600


class JwksFetchError(Exception):
    """The JWKS could not be fetched or parsed."""


def _default_get(url):
    # The shared transport refuses redirects and bodies over the cap ("... larger than N bytes").
    response = _http.request("GET", url, timeout=10, max_bytes=MAX_JWKS_BYTES)
    return _http.text_ok(response, "JWKS endpoint")


def _algorithm_for(jwk):
    kty = jwk.get("kty")
    if kty == "EC":
        return {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}.get(jwk.get("crv"), "ES256")
    if kty == "RSA":
        return "RS256"
    if kty == "OKP":
        return "EdDSA"
    return "RS256"


class JwksProvider:
    def __init__(self, jwks=None, jwks_uri=None, http_get=None, *,
                 min_refresh_seconds=DEFAULT_MIN_REFRESH_SECONDS, max_age_seconds=DEFAULT_MAX_AGE_SECONDS,
                 clock=time.monotonic):
        self._static = jwks is not None
        self._jwks_uri = jwks_uri
        self._http_get = http_get or _default_get
        self._min_refresh = min_refresh_seconds
        self._max_age = max_age_seconds
        self._clock = clock
        self._lock = threading.Lock()          # guards _keys and the timestamps
        self._refresh_lock = threading.Lock()  # one fetch at a time
        self._keys = {}
        self._loaded_at = None
        self._last_attempt = None
        self.last_error = None
        if jwks is not None:
            self._keys = self._parse(jwks)

    @staticmethod
    def _parse(jwks):
        # kid -> (key, the JWK's declared alg or None). A JWK that declares an alg is only used for that alg.
        keys = {}
        for jwk in jwks.get("keys", []):
            alg = jwk.get("alg") or _algorithm_for(jwk)
            try:
                keys[jwk.get("kid")] = (jwt.get_algorithm_by_name(alg).from_jwk(json.dumps(jwk)), jwk.get("alg"))
            except Exception:
                continue
        return keys

    def resolve(self, kid, alg=None):
        """The verification key for ``kid`` (and ``alg``), or ``None``. Never raises: a failed fetch leaves
        the reason in ``last_error``."""
        if not self._static and self._jwks_uri:
            entry = self._lookup(kid)
            if entry is None or self._stale():
                self._refresh(kid)
        entry = self._lookup(kid)
        if entry is None:
            return None
        key, declared = entry
        if alg is not None and declared is not None and declared != alg:
            return None
        return key

    def _lookup(self, kid):
        with self._lock:
            if kid in self._keys:
                return self._keys[kid]
            if kid is None and len(self._keys) == 1:
                return next(iter(self._keys.values()))
            return None

    def _stale(self):
        with self._lock:
            return self._loaded_at is None or self._clock() - self._loaded_at >= self._max_age

    def _refresh(self, kid):
        with self._refresh_lock:
            # another thread may have refreshed while this one waited
            if self._lookup(kid) is not None and not self._stale():
                return
            with self._lock:
                now = self._clock()
                if self._last_attempt is not None and now - self._last_attempt < self._min_refresh:
                    return
                self._last_attempt = now
            try:
                body = self._http_get(self._jwks_uri)
                if len(body) > MAX_JWKS_BYTES:
                    raise JwksFetchError(f"JWKS is larger than {MAX_JWKS_BYTES} bytes")
                keys = self._parse(json.loads(body))
            except Exception as exc:  # keep serving the keys already held
                self.last_error = f"JWKS fetch failed: {exc}"
                return
            with self._lock:
                self._keys = keys
                self._loaded_at = self._clock()
                self.last_error = None
