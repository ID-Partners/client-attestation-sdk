"""The one place the SDK makes outbound HTTP calls.

Every call:

- has a timeout (the caller's, always passed explicitly);
- never follows a redirect. Requests carry credentials (``Authorization``, ``DPoP``,
  ``OAuth-Client-Attestation``, ``X-Vault-Token``, client secrets and assertions in bodies) and urllib
  re-sends headers to the redirect target, so a 3xx is a :class:`TransportError`;
- reads at most ``max_bytes`` of body (default 1 MiB); a larger body is a :class:`TransportError`;
- speaks only ``http`` / ``https`` (no ``file:``, ``ftp:`` or ``data:`` URLs);
- turns network failures (``URLError``, timeouts, resets, TLS errors) into :class:`TransportError`.

A non-2xx, non-3xx answer is NOT an error at this layer: :func:`request` returns it, because some callers
parse error bodies (an OAuth 400/401 JSON error, a CIBA ``authorization_pending``). :func:`json_ok` and
:func:`text_ok` are the strict readers: non-2xx or malformed JSON raises :class:`TransportError`.
"""
from __future__ import annotations

import http.client
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from .errors import TransportError

DEFAULT_MAX_BYTES = 1024 * 1024
ERROR_BODY_LIMIT = 512

__all__ = ["DEFAULT_MAX_BYTES", "HttpResponse", "TransportError", "json_ok", "parse_json_object",
           "request", "require", "text_ok"]


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Returning ``None`` stops urllib following the redirect; the 3xx then surfaces as an HTTPError."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401, ARG002
        return None


_DEFAULT_OPENER = urllib.request.build_opener(_RefuseRedirects)


def _opener(context: Optional[ssl.SSLContext]):
    if context is None:
        return _DEFAULT_OPENER
    return urllib.request.build_opener(_RefuseRedirects, urllib.request.HTTPSHandler(context=context))


def _display(url: str) -> str:
    """The URL without its query or fragment, for error messages."""
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def request(method: str, url: str, *, headers: Optional[Mapping[str, str]] = None,
            body: Optional[bytes] = None, timeout: float, max_bytes: int = DEFAULT_MAX_BYTES,
            context: Optional[ssl.SSLContext] = None) -> HttpResponse:
    """Make one HTTP request. Returns the response for any 1xx/2xx/4xx/5xx status; raises
    :class:`TransportError` for a redirect, an oversized body, an unsupported scheme, or a network
    failure (including the timeout)."""
    method = method.upper()
    where = f"{method} {_display(url)}"
    if urllib.parse.urlsplit(url).scheme.lower() not in ("http", "https"):
        raise TransportError(f"{where}: only http and https URLs are supported")
    req = urllib.request.Request(url, data=body, method=method, headers=dict(headers or {}))
    try:
        try:
            resp = _opener(context).open(req, timeout=timeout)
        except urllib.error.HTTPError as error:
            resp = error  # a non-2xx answer: still a response, with a status and a body
        with resp:
            status = resp.getcode()
            if 300 <= status < 400:
                raise TransportError(f"{where} returned HTTP {status} (redirects are not followed)",
                                     status=status)
            data = resp.read(max_bytes + 1)
            response_headers = resp.headers
    except TransportError:
        raise
    except (OSError, http.client.HTTPException) as error:
        reason = getattr(error, "reason", None) or error
        raise TransportError(f"{where} failed: {reason}") from error
    if len(data) > max_bytes:
        raise TransportError(f"{where}: response body is larger than {max_bytes} bytes", status=status)
    return HttpResponse(status, response_headers, data)


def _check_ok(response: HttpResponse, what: str) -> None:
    if not response.ok:
        text = response.text()
        snippet = response.body[:ERROR_BODY_LIMIT].decode("utf-8", "replace")
        raise TransportError(f"{what} returned HTTP {response.status}: {snippet}",
                             status=response.status, body=text)


def text_ok(response: HttpResponse, what: str) -> str:
    """The body as text, or :class:`TransportError` for a non-2xx status."""
    _check_ok(response, what)
    return response.text()


def parse_json_object(raw, what: str, *, status: Optional[int] = None, allow_empty: bool = False) -> dict:
    """Parse ``raw`` (bytes or str) as a JSON object, or raise :class:`TransportError`."""
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
    if allow_empty and not text.strip():
        return {}
    try:
        parsed = json.loads(text)
    except ValueError as error:
        raise TransportError(f"{what} returned malformed JSON: {error}", status=status,
                             body=text[:ERROR_BODY_LIMIT]) from error
    if not isinstance(parsed, dict):
        raise TransportError(f"{what} returned JSON that is not an object", status=status,
                             body=text[:ERROR_BODY_LIMIT])
    return parsed


def json_ok(response: HttpResponse, what: str, *, allow_empty: bool = False) -> dict:
    """The body as a JSON object, or :class:`TransportError` for a non-2xx status or a body that is not a
    JSON object. ``allow_empty`` maps an empty body to ``{}``."""
    _check_ok(response, what)
    return parse_json_object(response.body, what, status=response.status, allow_empty=allow_empty)


def require(obj: Mapping[str, Any], key: str, what: str) -> Any:
    """``obj[key]``, or :class:`TransportError` naming the missing member."""
    try:
        return obj[key]
    except (KeyError, TypeError, IndexError):
        raise TransportError(f"{what} has no {key}") from None
