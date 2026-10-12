"""Access-token validation: JWT signature + claim checks, and optional RFC 7662 introspection."""
from __future__ import annotations

import base64
import logging
import time
import urllib.parse

import jwt

from client_attestation_sdk import _http, _log
from client_attestation_sdk.errors import TransportError

from . import _strict, errors
from .config import _is_forbidden_algorithm, _normalise_type
from .jwks import JwksProvider, key_fits
from .result import ValidationResult


_logger = _log.get("validator")


MAX_INTROSPECTION_BYTES = 1024 * 1024


def _default_post(url, body, headers):
    # the shared transport refuses redirects (they would carry the credentials) and bodies over the cap
    response = _http.request("POST", url, headers=headers, body=body.encode("utf-8"), timeout=10,
                             max_bytes=MAX_INTROSPECTION_BYTES)
    # like every port's shared transport, invalid UTF-8 becomes U+FFFD; the JSON itself is parsed strictly
    text = _http.text_ok(response, "introspection endpoint")
    try:
        return _strict.parse_object(text.encode("utf-8"), "introspection response")
    except _strict.Malformed as exc:
        raise TransportError(f"introspection endpoint returned {exc}", status=response.status) from None


class AccessTokenValidator:
    """Validates access tokens for a resource server.

    ``validate`` does local JWT validation in a fixed order — algorithm accepted, key resolvable, signature,
    ``typ`` (when present), ``iss``, ``exp`` present, ``exp``, ``nbf``, ``iat`` not in the future, audience,
    then scope — returning the first failure's stable error code. That
    order is part of the cross-language contract so every port reports the same verdict. ``validate_active``
    instead uses RFC 7662 introspection.
    """

    def __init__(self, config, http_post=None, http_get=None, *, clock=None):
        """``clock`` returns the current time in epoch seconds (default :func:`time.time`); inject one to
        validate as of a fixed instant.

        The validator keeps its own copy of ``config``: changing that object (or its lists, or its
        introspection settings) afterwards doesn't change what the validator accepts."""
        self.config = config._checked_copy()
        self._clock = clock or time.time
        self._jwks = JwksProvider(jwks=self.config.jwks, jwks_uri=self.config.jwks_uri, http_get=http_get)
        self._http_post = http_post or _default_post

    def validate(self, token, required_scopes=None):
        return _verdict(self._validate(token, required_scopes), "jwt")

    def _validate(self, token, required_scopes):
        required = self.config.required_scopes if required_scopes is None else list(required_scopes)

        try:
            header, signing_input, payload, signature = _strict.split_compact(token)
        except _strict.Malformed:
            # never echo token data to the caller: the description lands in WWW-Authenticate
            return ValidationResult._failure(errors.INVALID_TOKEN, "malformed token")

        alg = header.get("alg")
        if not isinstance(alg, str) or _is_forbidden_algorithm(alg) or alg not in self.config.accepted_algorithms:
            return ValidationResult._failure(errors.UNSUPPORTED_ALGORITHM, "algorithm not accepted")

        kid = header.get("kid")
        key = self._jwks.resolve(kid, alg) if kid is None or isinstance(kid, str) else None
        if key is None:
            # a fetch failure's detail (internal host, dial error, IdP body) went to the log as jwks.fetch_failed;
            # the description lands in WWW-Authenticate, in front of anyone
            return ValidationResult._failure(
                errors.KEY_NOT_FOUND,
                "signing keys unavailable" if self._jwks.last_error else "no signing key for this kid")

        try:
            verified = key_fits(alg, key) and jwt.get_algorithm_by_name(alg).verify(signing_input, key, signature)
        except Exception:
            verified = False
        if not verified:
            return ValidationResult._failure(errors.INVALID_SIGNATURE, "signature verification failed")

        try:
            claims = _strict.parse_object(payload)
        except _strict.Malformed as exc:
            return ValidationResult._failure(errors.INVALID_TOKEN, str(exc))

        typ = header.get("typ")
        accepted_types = self.config.accepted_token_types
        if typ is not None and accepted_types is not None and (
                not isinstance(typ, str) or _normalise_type(typ) not in accepted_types):
            return ValidationResult._failure(errors.INVALID_TOKEN_TYPE, "token is not a JWT access token")

        if claims.get("iss") != self.config.issuer:
            return ValidationResult._failure(errors.INVALID_ISSUER, "unexpected issuer")

        now = int(self._clock())
        leeway = self.config.leeway_seconds
        try:
            exp = _strict.numeric_date(claims, "exp")
            nbf = _strict.numeric_date(claims, "nbf")
            iat = _strict.numeric_date(claims, "iat")
        except _strict.Malformed as exc:
            return ValidationResult._failure(errors.INVALID_TOKEN, str(exc))
        if exp is None:
            return ValidationResult._failure(errors.MISSING_EXPIRY, "token has no exp claim")
        if now > exp + leeway:
            return ValidationResult._failure(errors.EXPIRED, "token has expired")
        if nbf is not None and now + leeway < nbf:
            return ValidationResult._failure(errors.NOT_YET_VALID, "token is not yet valid")
        if iat is not None and now + leeway < iat:
            return ValidationResult._failure(errors.ISSUED_IN_FUTURE, "token was issued in the future")

        try:
            audience = _strict.audience(claims)
            if not any(a in audience for a in self.config.audiences):
                return ValidationResult._failure(errors.INVALID_AUDIENCE, "token audience is not accepted")
            granted = _strict.scopes(claims)
            missing = [s for s in required if s not in granted]
            if missing:
                return ValidationResult._failure(errors.INSUFFICIENT_SCOPE, "missing scopes: " + " ".join(missing))
            _strict.subject(claims)
        except _strict.Malformed as exc:
            return ValidationResult._failure(errors.INVALID_TOKEN, str(exc))

        return ValidationResult._success(claims, granted, audience)

    def introspect(self, token, token_type_hint="access_token"):
        """RFC 7662: POST the token to the AS introspection endpoint and return the parsed response."""
        cfg = self.config.introspection
        if cfg is None:
            raise ValueError("no introspection endpoint configured")
        form = {"token": token, "token_type_hint": token_type_hint}
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        if cfg.auth_method == "client_secret_basic":
            raw = f"{cfg.client_id}:{cfg.client_secret}".encode("utf-8")
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        else:
            form["client_id"] = cfg.client_id
            form["client_secret"] = cfg.client_secret
        try:
            data = self._http_post(cfg.endpoint, urllib.parse.urlencode(form), headers)
            if not isinstance(data, dict):
                raise TransportError("introspection endpoint returned JSON that is not an object")
            return data
        except TransportError as error:
            _log.emit(_logger, logging.WARNING, "http.failed", step="introspection", method="POST",
                      host=_log.host(cfg.endpoint), path=_log.path(cfg.endpoint), status=error.status,
                      reason=_log.failure_reason(error))
            raise

    def validate_active(self, token, required_scopes=None):
        """Introspect the token and enforce ``active`` plus scope/audience from the response."""
        return _verdict(self._validate_active(token, required_scopes), "introspection")

    def _validate_active(self, token, required_scopes):
        data = self.introspect(token)
        # RFC 7662 section 2.2: active is a boolean, so only JSON true counts
        if data.get("active") is not True:
            return ValidationResult._failure(errors.INACTIVE, "token is not active")
        required = self.config.required_scopes if required_scopes is None else list(required_scopes)
        try:
            granted = _strict.scopes(data)
            missing = [s for s in required if s not in granted]
            if missing:
                return ValidationResult._failure(errors.INSUFFICIENT_SCOPE, "missing scopes: " + " ".join(missing))
            audience = _strict.audience(data)
            if audience and not any(a in audience for a in self.config.audiences):
                return ValidationResult._failure(errors.INVALID_AUDIENCE, "token audience is not accepted")
            _strict.subject(data)
        except _strict.Malformed as exc:
            return ValidationResult._failure(errors.INVALID_TOKEN, str(exc))
        return ValidationResult._success(data, granted, audience)


def _verdict(result, mode):
    """Log a verdict (its stable code, never the token or its claims) and return it."""
    code = errors.VALID if result.valid else result.error
    _log.emit(_logger, logging.DEBUG if result.valid else logging.INFO, "token.validated", result=code, mode=mode)
    return result
