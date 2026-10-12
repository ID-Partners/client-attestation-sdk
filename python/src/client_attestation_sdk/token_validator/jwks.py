"""Resolves issuer signing keys — from a static JWKS or a ``jwks_uri`` (fetched and cached, refreshed on an
unknown ``kid`` and when the cached set grows old).

A ``jwks_uri`` provider never fetches more than once per ``min_refresh_seconds``, however many unknown
``kid`` values it is shown, and concurrent misses share one fetch. Without that, a stream of tokens with
made-up ``kid`` values turns every request into a request to the issuer."""
from __future__ import annotations

import json
import logging
import threading
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from client_attestation_sdk import _http, _log

MAX_JWKS_BYTES = 512 * 1024
DEFAULT_MIN_REFRESH_SECONDS = 30
DEFAULT_MAX_AGE_SECONDS = 3600
MIN_RSA_KEY_BITS = 2048   # RFC 7518 section 3.3

# the JWK members only a private or symmetric key carries (RFC 7518 section 6)
_PRIVATE_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "k")
# the one curve each ES* algorithm verifies with
_CURVES = {"ES256": "secp256r1", "ES384": "secp384r1", "ES512": "secp521r1"}

_logger = _log.get("validator")


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


def _verifies_signatures(jwk):
    """Whether a JWK may verify a signature: not when its ``use`` is present and not ``sig``, its ``key_ops``
    is present and lacks ``verify``, or it carries private members. An entry that isn't a JSON object isn't a
    JWK at all, and is skipped like any key that can't be read."""
    if not isinstance(jwk, dict):
        return False
    if "use" in jwk and jwk["use"] != "sig":
        return False
    if "key_ops" in jwk and not (isinstance(jwk["key_ops"], list) and "verify" in jwk["key_ops"]):
        return False
    return not any(member in jwk for member in _PRIVATE_MEMBERS)


def key_fits(alg, key):
    """Whether ``alg`` may use ``key`` at all. PyJWT sizes an ECDSA signature by the key's curve but hashes by
    the header alg, so without this a P-256 key would verify an ES384 signature; and it takes an RSA key of
    any size."""
    if isinstance(key, ec.EllipticCurvePublicKey):
        return key.curve.name == _CURVES.get(alg)
    if isinstance(key, rsa.RSAPublicKey):
        return key.key_size >= MIN_RSA_KEY_BITS
    return True


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
        self._keys = []
        self._loaded_at = None
        self._last_attempt = None
        self.last_error = None
        if jwks is not None:
            self._keys = self._parse(jwks)

    @staticmethod
    def _parse(jwks):
        # (kid, key, the JWK's declared alg or None) in document order: kid-less JWKs are distinct keys, and
        # a JWK that may not verify signatures is left out. A JWK that declares an alg is only used for it.
        keys = []
        for jwk in jwks.get("keys", []):
            if not _verifies_signatures(jwk):
                continue
            alg = jwk.get("alg") or _algorithm_for(jwk)
            try:
                keys.append((jwk.get("kid"), jwt.get_algorithm_by_name(alg).from_jwk(json.dumps(jwk)),
                             jwk.get("alg")))
            except Exception:
                continue
        return keys

    def resolve(self, kid, alg=None):
        """The verification key for ``kid`` (and ``alg``), or ``None``. Never raises: a failed fetch leaves
        the reason in ``last_error``."""
        if not self._static and self._jwks_uri:
            key = self._lookup(kid, alg)
            if key is None or self._stale():
                self._refresh(kid, alg, have_key=key is not None)
        return self._lookup(kid, alg)

    def _lookup(self, kid, alg):
        def allowed(declared):
            return alg is None or declared is None or declared == alg

        with self._lock:
            if kid is None:
                # a token without a kid is only matched to a set holding exactly one key
                if len(self._keys) != 1:
                    return None
                _, key, declared = self._keys[0]
                return key if allowed(declared) else None
            if kid == "":
                return None   # an empty kid names no key, not even a JWK whose kid is ""
            # duplicate kids: the first JWK with this kid that may be used for alg
            return next((key for jwk_kid, key, declared in self._keys if jwk_kid == kid and allowed(declared)),
                        None)

    def _stale(self):
        with self._lock:
            return self._loaded_at is None or self._clock() - self._loaded_at >= self._max_age

    def _refresh(self, kid, alg, have_key):
        # A caller that already holds a usable (if stale) key never waits for another thread's fetch: it goes on
        # with the key it has. One without a key waits for a fetch in flight, which may bring its key.
        if not self._refresh_lock.acquire(blocking=not have_key):
            return
        try:
            # another thread may have refreshed while this one waited
            if self._lookup(kid, alg) is not None and not self._stale():
                return
            with self._lock:
                now = self._clock()
                if self._last_attempt is not None and now - self._last_attempt < self._min_refresh:
                    _log.emit(_logger, logging.DEBUG, "jwks.refetch_throttled", host=_log.host(self._jwks_uri))
                    return
                self._last_attempt = now
            try:
                body = self._http_get(self._jwks_uri)
                if len(body) > MAX_JWKS_BYTES:
                    raise JwksFetchError(f"JWKS is larger than {MAX_JWKS_BYTES} bytes")
                keys = self._parse(json.loads(body))
            except Exception as exc:  # keep serving the keys already held
                self.last_error = f"JWKS fetch failed: {exc}"
                reason = "malformed" if isinstance(exc, (ValueError, AttributeError)) and \
                    "larger than" not in str(exc) else _log.failure_reason(exc)
                _log.emit(_logger, logging.WARNING, "jwks.fetch_failed", host=_log.host(self._jwks_uri),
                          reason=reason, status=getattr(exc, "status", None))
                return
            with self._lock:
                self._keys = keys
                self._loaded_at = self._clock()
                self.last_error = None
            _log.emit(_logger, logging.DEBUG, "jwks.fetched", host=_log.host(self._jwks_uri), keys=len(keys))
        finally:
            self._refresh_lock.release()
