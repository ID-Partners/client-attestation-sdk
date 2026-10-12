"""The one place the SDK makes outbound HTTP calls.

Every call:

- has a timeout (the caller's, always passed explicitly) that bounds the whole call - connect, TLS, headers
  and body - not each socket operation, so a server that trickles bytes can't hold a call (and the locks
  around it) open past it;
- never follows a redirect. Requests carry credentials (``Authorization``, ``DPoP``,
  ``OAuth-Client-Attestation``, ``X-Vault-Token``, client secrets and assertions in bodies) and urllib
  re-sends headers to the redirect target, so a 3xx is a :class:`TransportError`;
- reads at most ``max_bytes`` of body (default 1 MiB); a larger body is a :class:`TransportError`;
- speaks only ``http`` / ``https`` (no ``file:``, ``ftp:`` or ``data:`` URLs);
- uses an environment proxy (``HTTPS_PROXY``) only for https to a remote host, where CONNECT keeps TLS end
  to end; plain http, loopback, link-local and cloud metadata hosts, and ``direct=True`` calls always go
  direct (see :class:`_ProxyHandler`);
- refuses a URL with userinfo (``user:password@``), and never names userinfo or a query in an error;
- turns network failures (``URLError``, timeouts, resets, TLS errors) into :class:`TransportError`.

A non-2xx, non-3xx answer is NOT an error at this layer: :func:`request` returns it, because some callers
parse error bodies (an OAuth 400/401 JSON error, a CIBA ``authorization_pending``). :func:`json_ok` and
:func:`text_ok` are the strict readers: non-2xx or malformed JSON raises :class:`TransportError`.
"""
from __future__ import annotations

import functools
import http.client
import io
import ipaddress
import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from .errors import ClientAttestationError, TransportError

DEFAULT_MAX_BYTES = 1024 * 1024
ERROR_BODY_LIMIT = 512
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

__all__ = ["DEFAULT_MAX_BYTES", "HttpResponse", "TransportError", "json_ok", "parse_json_object",
           "request", "require", "require_https", "text_ok"]


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


def _remaining(deadline: float) -> float:
    """Seconds left before ``deadline``, or the same ``TimeoutError`` a socket timeout raises."""
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("timed out")
    return left


class _DeadlineSocket:
    """A connected socket that re-arms its timeout to what is left of the call's deadline before every send
    and receive. urllib's ``timeout`` is per operation, so without this a server sending one byte just
    inside it keeps the call open indefinitely. ``close`` waits for the response's file to be closed, as a
    real socket's does."""

    def __init__(self, sock, deadline: float):
        self._sock = sock
        self._deadline = deadline
        self._io_refs = 0
        self._closed = False

    def __getattr__(self, name):
        return getattr(self._sock, name)

    def recv_into(self, *args):
        self._sock.settimeout(_remaining(self._deadline))
        return self._sock.recv_into(*args)

    def recv(self, *args):
        self._sock.settimeout(_remaining(self._deadline))
        return self._sock.recv(*args)

    def sendall(self, *args):
        self._sock.settimeout(_remaining(self._deadline))
        return self._sock.sendall(*args)

    def makefile(self, mode="rb", buffering=None, **_):  # http.client only reads ("rb")
        self._io_refs += 1
        return io.BufferedReader(socket.SocketIO(self, "rb"), buffering or io.DEFAULT_BUFFER_SIZE)

    def _decref_socketios(self):
        self._io_refs -= 1
        if self._closed and self._io_refs <= 0:
            self._sock.close()

    def close(self):
        self._closed = True
        if self._io_refs <= 0:
            self._sock.close()


_new_socket = socket.socket  # tests swap this to stand in an address that never answers


class _DeadlineConnection:
    """Mixin for ``http.client`` connections: the connect attempts, a proxy's CONNECT reply and the TLS
    handshake all get what is left of the deadline, and the connected socket is a :class:`_DeadlineSocket`."""

    def __init__(self, *args, deadline: float, **kwargs):
        super().__init__(*args, **kwargs)
        self._deadline = deadline
        self._create_connection = self._connect_within_deadline

    def _connect_within_deadline(self, address, timeout, source_address=None):  # noqa: ARG002
        host, port = address
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        error: OSError = OSError(f"no address for {host}")
        for index, (family, socktype, proto, _, addr) in enumerate(infos):
            # Each address gets an equal share of what is left, so one that never answers (a blackholed
            # IPv6 address in front of a working IPv4 one) can't use up the deadline before the next is
            # tried. The last address gets everything that remains.
            share = _remaining(self._deadline) / (len(infos) - index)
            sock = _new_socket(family, socktype, proto)
            try:
                sock.settimeout(share)
                if source_address:
                    sock.bind(source_address)
                sock.connect(addr)
                sock.settimeout(_remaining(self._deadline))  # what the TLS handshake gets
                return sock
            except OSError as exc:
                sock.close()
                error = exc
        raise error

    def _tunnel(self):
        # The proxy's answer to CONNECT is read through the deadline socket too, so a proxy that trickles
        # its reply can't hold the call open. TLS is then set up on the plain socket underneath.
        raw = self.sock
        self.sock = _DeadlineSocket(raw, self._deadline)
        try:
            super()._tunnel()
        finally:
            if self.sock is not None:
                self.sock = raw

    def connect(self):
        super().connect()
        self.sock = _DeadlineSocket(self.sock, self._deadline)


class _HTTPConnection(_DeadlineConnection, http.client.HTTPConnection):
    pass


class _HTTPSConnection(_DeadlineConnection, http.client.HTTPSConnection):
    pass


class _Request(urllib.request.Request):
    def __init__(self, *args, deadline: float, direct: bool, **kwargs):
        super().__init__(*args, **kwargs)
        self.deadline = deadline
        self.direct = direct


class _HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(functools.partial(_HTTPConnection, deadline=req.deadline), req)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(functools.partial(_HTTPSConnection, deadline=req.deadline), req,
                            context=self._context)


# Cloud metadata servers that aren't link-local addresses (169.254.169.254 is caught as link-local).
_METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata", "fd00:ec2::254"})


def _never_proxied(host: Optional[str]) -> bool:
    """Loopback, link-local and cloud metadata hosts: the SDK sends them tokens it must not route elsewhere.
    An IPv4 address in a short, octal, hex or integer form (``127.1``, ``0x7f000001``) counts, as the
    resolver reads it the same way."""
    host = (host or "").rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost") or host in _METADATA_HOSTS:
        return True
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        try:
            address = ipaddress.IPv4Address(socket.inet_aton(host))
        except (OSError, ValueError):
            return False
    address = getattr(address, "ipv4_mapped", None) or address
    return address.is_loopback or address.is_link_local or address.is_unspecified


@functools.lru_cache(maxsize=1)
def _environment_proxies() -> Mapping[str, str]:
    """The proxy environment variables (``HTTPS_PROXY`` and friends), read once, as urllib's own default
    opener does. Only the environment: not the macOS or Windows system proxy settings."""
    return urllib.request.getproxies_environment()


class _ProxyHandler(urllib.request.ProxyHandler):
    """The SDK's one proxy policy. A request goes through a proxy only when it is https, the environment
    names an https proxy (``HTTPS_PROXY``), the host is not loopback, link-local or a cloud metadata
    server, ``NO_PROXY`` doesn't exclude it, and the caller didn't ask for ``direct``. It then goes through
    a CONNECT tunnel, so TLS stays end to end and the proxy sees only the host and port. Everything else -
    plain http in particular (an OpenBao ``X-Vault-Token``, a metadata identity token) - goes direct;
    urllib's default handler would send it to ``HTTP_PROXY`` in cleartext."""

    def __init__(self):
        super().__init__({})  # no per-scheme handlers from a mapping; https_open below decides

    def https_open(self, req):
        proxy = _environment_proxies().get("https")
        if (not proxy or getattr(req, "direct", False)
                or _never_proxied(urllib.parse.urlsplit(req.full_url).hostname)):
            return None
        return self.proxy_open(req, proxy, "https")


def _build_opener(context: Optional[ssl.SSLContext]):
    return urllib.request.build_opener(_RefuseRedirects, _ProxyHandler, _HTTPHandler,
                                       _HTTPSHandler(context=context))


_DEFAULT_OPENER = _build_opener(None)


def _opener(context: Optional[ssl.SSLContext]):
    return _DEFAULT_OPENER if context is None else _build_opener(context)


def _display(url: str) -> str:
    """The URL without its userinfo, query or fragment, for error messages."""
    parts = urllib.parse.urlsplit(url)
    host = parts.netloc.rpartition("@")[2]
    return urllib.parse.urlunsplit((parts.scheme, host, parts.path, "", ""))


def request(method: str, url: str, *, headers: Optional[Mapping[str, str]] = None,
            body: Optional[bytes] = None, timeout: float, max_bytes: int = DEFAULT_MAX_BYTES,
            context: Optional[ssl.SSLContext] = None, direct: bool = False) -> HttpResponse:
    """Make one HTTP request. Returns the response for any 1xx/2xx/4xx/5xx status; raises
    :class:`TransportError` for a redirect, an oversized body, an unsupported scheme, or a network
    failure (including the timeout, which covers the whole call). A URL with userinfo (``user:pass@``) is
    refused. With ``direct=True`` the request never goes through a proxy, whatever the URL (metadata
    servers); without it the proxy policy of :class:`_ProxyHandler` applies."""
    deadline = time.monotonic() + timeout
    method = method.upper()
    where = f"{method} {_display(url)}"
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() not in ("http", "https"):
        raise TransportError(f"{where}: only http and https URLs are supported")
    if "@" in parts.netloc:
        # urllib would put user:pass@ in the Host header and a proxy's CONNECT line, and http.client quotes
        # it in "nonnumeric port" errors. Credentials belong in a header.
        raise TransportError(f"{where}: URLs with userinfo (user:password@) are not supported")
    req = _Request(url, data=body, method=method, headers=dict(headers or {}), deadline=deadline,
                   direct=direct)
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
        snippet = response.body[:ERROR_BODY_LIMIT].decode("utf-8", "replace")
        raise TransportError(f"{what} returned HTTP {response.status}: {snippet}",
                             status=response.status, body=snippet)


def text_ok(response: HttpResponse, what: str) -> str:
    """The body as text, or :class:`TransportError` for a non-2xx status."""
    _check_ok(response, what)
    return response.text()


def parse_json_object(raw, what: str, *, status: Optional[int] = None, allow_empty: bool = False) -> dict:
    """Parse ``raw`` (bytes or str) as a JSON object, or raise :class:`TransportError`. The error never
    carries or quotes the body: this parses 2xx bodies, which is where tokens, attestations and SVIDs
    travel."""
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
    if allow_empty and not text.strip():
        return {}
    try:
        parsed, problem = json.loads(text), None
    except ValueError as error:
        parsed, problem = None, str(error)  # the position only; the error itself holds the text (.doc)
    if problem is not None:
        # Raised outside the except block, so the decode error is neither the cause nor the context.
        raise TransportError(f"{what} returned malformed JSON: {problem}", status=status)
    if not isinstance(parsed, dict):
        raise TransportError(f"{what} returned JSON that is not an object", status=status)
    return parsed


def json_ok(response: HttpResponse, what: str, *, allow_empty: bool = False) -> dict:
    """The body as a JSON object, or :class:`TransportError` for a non-2xx status or a body that is not a
    JSON object. ``allow_empty`` maps an empty body to ``{}``."""
    _check_ok(response, what)
    return parse_json_object(response.body, what, status=response.status, allow_empty=allow_empty)


def require_https(url: str, what: str, allow_insecure: bool) -> None:
    """Credentials travel on every call, so endpoints must be https — except loopback (local fakes and
    sidecars) or when the caller explicitly passed `allow_insecure=True`."""
    if allow_insecure:
        return
    try:
        parts = urllib.parse.urlsplit(url)
        hostname = parts.hostname
    except ValueError:  # e.g. an unclosed IPv6 bracket
        raise ClientAttestationError(f"{what} is not a valid URL: {url}") from None
    scheme = parts.scheme.lower()
    if scheme == "https":
        return
    if scheme == "http" and (hostname or "").lower() in LOOPBACK_HOSTS:
        return
    raise ClientAttestationError(
        f"{what} must use https: {url} (plain http is allowed only for loopback hosts, "
        "or pass allow_insecure=True)")


def require(obj: Mapping[str, Any], key: str, what: str) -> Any:
    """``obj[key]``, or :class:`TransportError` naming the missing member."""
    try:
        return obj[key]
    except (KeyError, TypeError, IndexError):
        raise TransportError(f"{what} has no {key}") from None
