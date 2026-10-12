"""OpenID Connect CIBA (Client Initiated Backchannel Authentication) — the CLIENT side.

An agent that hits an authorization challenge and holds a paired-device channel for the human it
acts for can raise the ceremony itself: ``POST /as/bc-auth.ciba`` (a push to the human's
authenticator, decoupled from wherever the agent runs) then poll ``/as/token.oauth2`` with
``grant_type=urn:openid:params:grant-type:ciba`` until the human approves, declines, or the request
expires. This module is that client, and nothing more: it knows the wire protocol and the AS's
pacing rules; it does not know what the approval *means* (see :mod:`.resolver`).

Two lessons are encoded here that were expensive to learn against PingFederate and must survive
every port:

1. **The poll cadence is the AS's, not yours.** ``bc-auth`` returns ``interval``. Poll faster and
   PF escalates ``authorization_pending`` → ``slow_down`` → ``invalid_request`` ("please respect the
   polling interval") → **it invalidates the ``auth_req_id``** (``invalid_grant``), which a naive
   client reports as "expired on device" — every ceremony dying ~10s in, before any human could
   possibly have tapped. :meth:`CibaClient.poll` is therefore *throttled*: at most one token-endpoint
   call per interval (calls in between return the cached outcome), +5s on ``slow_down`` (CIBA Core
   §11), and a hard back-off on PF's interval-violation warning.

2. **``private_key_jwt`` audience.** The client assertion's ``aud`` is the AS's issuer identifier, as
   ONE string (CIBA Core §7.1, and the OpenID Foundation's 2025 guidance after the private_key_jwt
   audience-confusion disclosure): an assertion that names only this AS can't be replayed to another.
   PF validates the ``aud`` against its own issuer / token endpoint, which in a proxied deployment is
   the INTERNAL address, not the public host you posted to; that is why :class:`CibaClient` uses the
   ``issuer`` it is given, not the URL it calls. Two explicit opt-outs exist for an AS that accepts
   nothing else: ``audience_mode=AUDIENCE_ENDPOINT`` (the endpoint called, one string, what this client
   sent before it used the issuer) and ``extra_audiences`` (an array; see
   :func:`private_key_jwt_assertion`).

Client authentication is pluggable (:class:`ClientAuth`). ``private_key_jwt`` ships here because that
is what the deployed CIBA clients use today; an attestation-based authenticator (this SDK's core
capability) slots in behind the same interface once the AS accepts it on the backchannel endpoint.
"""
from __future__ import annotations

import inspect
import json
import logging
import re
import ssl
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol

import jwt

from client_attestation_sdk import _http, _log
from client_attestation_sdk.errors import TransportError

# ---- outcomes -----------------------------------------------------------------------------------
PENDING = "pending"     # authorization_pending / slow_down — keep waiting
APPROVED = "approved"   # 200 token response from the token endpoint — the human approved
DENIED = "denied"       # access_denied
EXPIRED = "expired"     # expired_token, or PF's invalid_grant after it killed the request

# ---- client-assertion audience (``audience_mode``) ----------------------------------------------
AUDIENCE_ISSUER = "issuer"       # the AS's issuer identifier, one string (the default)
AUDIENCE_ENDPOINT = "endpoint"   # the endpoint called, one string: what was sent before the issuer was used
_AUDIENCE_MODES = (AUDIENCE_ISSUER, AUDIENCE_ENDPOINT)

CIBA_GRANT = "urn:openid:params:grant-type:ciba"
_logger = _log.get("authz")
_OAUTH_ERROR_CODE = re.compile(r"^[a-z_]{1,64}$")
_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
# What :meth:`CibaClient.request` sets itself: the signed request object's registered claims and the
# parameters it takes by name. ``extra`` may not carry any of them (it would override them).
_RESERVED_REQUEST_CLAIMS = frozenset({"iss", "aud", "exp", "iat", "nbf", "jti",
                                      "scope", "login_hint", "binding_message"})
# bc-auth timing as the client will honour it. ``expires_in`` is REQUIRED (CIBA Core §7.3): a missing,
# zero or unreadable one gets the short default rather than "never expires", and an absurd one is capped,
# so a ceremony always ends on the client's clock.
_DEFAULT_INTERVAL = 3
_MAX_INTERVAL = 600
_DEFAULT_EXPIRES_IN = 120
_MAX_EXPIRES_IN = 3600
# Guards every CibaRequest's poll state (pacing, outcome) and _IN_FLIGHT. Held only to read and update
# that state, never across a network call, and shared by every client so that two clients polling the
# same request still agree on whether a call is in flight.
_POLL_STATE_LOCK = threading.Lock()
# id() of each CibaRequest with a token-endpoint call under way. The poll holds a reference to the request
# for as long as its id is here, so the id can't be reused meanwhile.
_IN_FLIGHT: "set[int]" = set()


class CibaError(Exception):
    """A backchannel request could not be raised (transport failure or a non-200 from bc-auth). The
    default transport (:func:`urllib_http`) also raises it for a network failure, a timeout, a redirect
    (never followed) or an oversized response. ``body`` is at most the first 512 characters of a non-200
    answer, and None for a 200 that could not be used."""

    def __init__(self, message: str, *, status: Optional[int] = None, body: Optional[str] = None):
        super().__init__(message)
        self.status = status
        self.body = body


def _bounded_int(value, default: int, hi: int) -> int:
    """``value`` as an int in ``[1, hi]``; ``default`` when it is missing, not a number, below 1 or not
    finite (``1e400`` parses as infinity, and ``int()`` of it raises ``OverflowError``)."""
    try:
        n = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return default if n < 1 else min(n, hi)


def _loads(text: str):
    """``json.loads`` for an AS response, with every way it can fail a ``ValueError``: a custom transport
    may not cap the body, and deep nesting raises ``RecursionError``."""
    if len(text) > _http.DEFAULT_MAX_BYTES:
        raise ValueError("response too large")
    try:
        return json.loads(text)
    except RecursionError:
        raise ValueError("response nested too deeply") from None


# ---- transport ----------------------------------------------------------------------------------
# (method, url, form-fields, headers) -> (status, body-text). Injectable so a caller can supply
# its own HTTP stack (httpx, a test double, a recorder). The default is stdlib urllib, matching
# the rest of this SDK.
HttpFn = Callable[[str, str, dict, dict], "tuple[int, str]"]


def urllib_http(*, timeout: float = 30.0, dangerously_disable_tls_verification: bool = False) -> HttpFn:
    """Default transport.

    ``dangerously_disable_tls_verification`` skips certificate AND hostname verification, so anyone
    on the path can impersonate the AS and read every client assertion and token. Only for an AS
    reached on an internal self-signed address in development, never for a public one.
    """
    ctx = None
    if dangerously_disable_tls_verification:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    def _do(method: str, url: str, form: dict, headers: dict) -> "tuple[int, str]":
        data = urllib.parse.urlencode(form).encode("utf-8") if form is not None else None
        all_headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        all_headers.update(headers or {})
        try:
            resp = _http.request(method, url, headers=all_headers, body=data, timeout=timeout, context=ctx)
        except TransportError as exc:
            raise CibaError(str(exc), status=exc.status, body=exc.body) from exc
        # Non-2xx is returned, not raised: the poll reads the OAuth error body (authorization_pending etc).
        return resp.status, resp.text()
    return _do


# ---- client authentication -------------------------------------------------------------------
class ClientAuth(Protocol):
    """Adds the client's credential to a form POST bound for ``endpoint``.

    An implementation may also take a keyword-only ``issuer`` argument
    (``apply(endpoint, form, *, issuer=None)``): :class:`CibaClient` then passes its own ``issuer`` on every
    call, as :class:`PrivateKeyJwtAuth` does. One whose ``apply`` takes only ``endpoint`` and ``form`` is
    called exactly that way, as before."""

    def apply(self, endpoint: str, form: dict) -> None: ...  # noqa: E704


def _check_audience(issuer: Optional[str], audience_mode: str) -> None:
    if audience_mode not in _AUDIENCE_MODES:
        raise ValueError(f"audience_mode must be AUDIENCE_ISSUER or AUDIENCE_ENDPOINT, not {audience_mode!r}")
    if issuer is not None and (not isinstance(issuer, str) or not issuer):
        # An empty issuer would quietly fall back to the endpoint: ask for that by name instead.
        raise ValueError("issuer must be a non-empty string or None (for the endpoint audience, "
                         "use audience_mode=AUDIENCE_ENDPOINT)")


def _accepts_issuer(apply) -> bool:
    """Whether a ``ClientAuth.apply`` takes the ``issuer`` keyword (or any keyword)."""
    try:
        params = inspect.signature(apply).parameters
    except (TypeError, ValueError):
        return False
    p = params.get("issuer")
    if p is not None:
        return p.kind in (inspect.Parameter.KEYWORD_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    return any(q.kind is inspect.Parameter.VAR_KEYWORD for q in params.values())


def private_key_jwt_assertion(*, client_id: str, endpoint: str, private_key_pem: str, kid: str,
                              extra_audiences: "tuple[str, ...]" = (), ttl: int = 120,
                              algorithm: str = "ES256", issuer: Optional[str] = None,
                              audience_mode: str = AUDIENCE_ISSUER) -> str:
    """Mint an RFC 7523 client-assertion JWT.

    ``aud`` is ONE string, chosen by ``audience_mode``:

    - :data:`AUDIENCE_ISSUER` (the default): ``issuer``, the AS's issuer identifier, or ``endpoint`` when
      no issuer is given. A single audience naming the AS is what CIBA Core §7.1 and the OpenID
      Foundation's 2025 guidance (after the private_key_jwt audience-confusion disclosure) ask for.
    - :data:`AUDIENCE_ENDPOINT`: ``endpoint``, the URL the assertion is posted to, whatever ``issuer`` is.
      This is what :class:`CibaClient` sent before it used the issuer; choose it for an AS that accepts
      only its endpoint URL (it answers ``invalid_client`` to the issuer).

    ``issuer`` must be None or a non-empty string.

    ``extra_audiences`` is an explicit opt-in for an AS that validates the audience against something
    else, such as PingFederate behind a proxy checking its INTERNAL issuer and token endpoint. Empty
    entries are ignored; with at least one left, ``aud`` is an array: the audience above, ``endpoint``,
    then the extras, without repeats. The risk: the assertion is good at any server that accepts any one
    of those values, so a party that receives it (or that a tampered discovery document points
    ``endpoint`` at) can replay it there until it expires (``ttl``). List only this AS's own identifiers,
    from configuration, never from discovery metadata.
    """
    _check_audience(issuer, audience_mode)
    now = int(time.time())
    aud = [endpoint if audience_mode == AUDIENCE_ENDPOINT else (issuer or endpoint)]
    extras = [a for a in extra_audiences if a]
    if extras:                  # the opt-in: an array
        for a in (endpoint, *extras):
            if a not in aud:
                aud.append(a)
    return jwt.encode({"iss": client_id, "sub": client_id, "aud": aud if len(aud) > 1 else aud[0],
                       "jti": uuid.uuid4().hex, "iat": now, "exp": now + ttl},
                      private_key_pem, algorithm=algorithm, headers={"kid": kid})


@dataclass
class PrivateKeyJwtAuth:
    """``private_key_jwt`` client authentication (RFC 7523 §2.2).

    The assertion's ``aud`` is the AS's issuer, one string: ``issuer`` when set, else the ``issuer``
    :class:`CibaClient` passes to :meth:`apply` on each call (its own), else the endpoint called. The
    object is read at each call, so a later change to its key, ``kid`` or other fields applies to the
    next assertion.

    Opt-outs, for an AS that rejects its issuer as the audience (see :func:`private_key_jwt_assertion`):
    ``audience_mode=AUDIENCE_ENDPOINT`` sends the endpoint called, one string, as this client did before
    it used the issuer; ``extra_audiences`` makes ``aud`` an array, with the risk described there."""
    client_id: str
    private_key_pem: str = field(repr=False)    # never in repr/logs
    kid: str
    # Opt-in: further audiences (the AS's internal issuer + token endpoint behind a proxy).
    extra_audiences: "tuple[str, ...]" = ()
    algorithm: str = "ES256"
    issuer: Optional[str] = None
    audience_mode: str = AUDIENCE_ISSUER

    def __post_init__(self) -> None:
        _check_audience(self.issuer, self.audience_mode)

    def apply(self, endpoint: str, form: dict, *, issuer: Optional[str] = None) -> None:
        form["client_assertion_type"] = _JWT_BEARER
        form["client_assertion"] = private_key_jwt_assertion(
            client_id=self.client_id, endpoint=endpoint, private_key_pem=self.private_key_pem,
            kid=self.kid, extra_audiences=self.extra_audiences, algorithm=self.algorithm,
            issuer=self.issuer or issuer or None, audience_mode=self.audience_mode)


# ---- request / poll state -----------------------------------------------------------------------
@dataclass
class CibaRequest:
    """One backchannel authentication request as the AS accepted it, plus the poll throttle state.

    This object IS the poll state — pass the same instance to every :meth:`CibaClient.poll`. It is
    persisted with :meth:`to_dict` (including ``last_poll_at`` and the ``interval`` as ``slow_down`` left
    it) and rebuilt with :meth:`rehydrate`, which starts the throttle again from the later of the stored
    ``last_poll_at`` and now: one wasted interval is cheaper than a killed grant.

    Pacing is per instance. Two replicas that each hold a copy poll the AS once per interval EACH, so
    route every poll of one ceremony to one replica (or one copy) when more than one serves it.
    """
    auth_req_id: str = field(repr=False)        # bearer for the token poll: keep out of repr/logs
    interval: int                # seconds; PF's answer, honoured and mutated by poll()
    expires_in: int              # seconds from ``requested_at``
    requested_at: float = field(default_factory=time.time)
    last_poll_at: float = 0.0
    last_outcome: str = PENDING
    last_error: str = ""
    access_token: Optional[str] = field(default=None, repr=False)   # set on APPROVED, if the caller wants it
    token_response: Optional[dict] = field(default=None, repr=False)

    @property
    def deadline(self) -> float:
        return self.requested_at + max(0, self.expires_in)

    def expired_by_clock(self, now: Optional[float] = None) -> bool:
        return self.expires_in > 0 and (now or time.time()) >= self.deadline

    def to_dict(self) -> dict:
        return {"auth_req_id": self.auth_req_id, "interval": self.interval,
                "expires_in": self.expires_in, "requested_at": self.requested_at,
                "last_outcome": self.last_outcome, "last_poll_at": self.last_poll_at}

    @classmethod
    def rehydrate(cls, d: dict) -> "CibaRequest":
        """Rebuild from :meth:`to_dict` output. Seeds the throttle so the first poll waits a full
        interval from the later of the stored ``last_poll_at`` and now. A stored ``last_poll_at`` more
        than ``interval`` seconds ahead of now is ignored."""
        r = cls(auth_req_id=str(d.get("auth_req_id") or ""),
                interval=_bounded_int(d.get("interval"), _DEFAULT_INTERVAL, _MAX_INTERVAL),
                expires_in=_bounded_int(d.get("expires_in"), _DEFAULT_EXPIRES_IN, _MAX_EXPIRES_IN),
                requested_at=float(d.get("requested_at") or time.time()))
        r.last_outcome = str(d.get("last_outcome") or PENDING)
        now = time.time()
        try:
            stored = float(d.get("last_poll_at") or 0.0)
        except (TypeError, ValueError):
            stored = 0.0
        # The later of the two. A stored time more than one interval ahead (a skewed clock, junk) is
        # ignored rather than allowed to stall the ceremony: no real poll is stamped later than that.
        r.last_poll_at = stored if now < stored <= now + r.interval else now
        return r


class CibaClient:
    """Raise and poll CIBA requests against one authorization server.

    :param bc_auth_endpoint: e.g. ``https://as.example/as/bc-auth.ciba``
    :param token_endpoint: e.g. ``https://as.example/as/token.oauth2``
    :param client_id: the CIBA client's id (also the ``iss`` of a signed request object)
    :param client_auth: how this client authenticates to the AS
    :param request_signing_key_pem: when set, ``bc-auth`` carries a SIGNED request object (JWS,
        ``request=`` parameter) — what a FAPI-CIBA client sends. When ``None`` the parameters go flat.
    :param request_signing_kid: the JWS ``kid`` for the signed request
    :param issuer: the AS issuer — the ``aud`` of the signed request object. It is also passed to
        ``client_auth.apply`` as ``issuer=`` on every call when that method takes the keyword (see
        :class:`ClientAuth`), so a :class:`PrivateKeyJwtAuth` with no ``issuer`` of its own uses it as the
        client assertion's audience. ``client_auth`` is used as given, never copied.
    :param http: transport (see :func:`urllib_http`)
    :param allow_insecure: allow plain-http endpoints for non-loopback hosts. Without it both endpoints
        must be https (loopback is exempt): the client assertion, ``login_hint``, ``auth_req_id`` and the
        tokens travel on them.

    ``interval`` and ``expires_in`` from ``bc-auth`` are read as whole seconds: ``interval`` at most 600,
    ``expires_in`` at most 3600 and 120 when the AS leaves it out (it is REQUIRED), so a ceremony never
    outlives the client's clock.
    """

    def __init__(self, *, bc_auth_endpoint: str, token_endpoint: str, client_id: str,
                 client_auth: ClientAuth, issuer: str,
                 request_signing_key_pem: Optional[str] = None,
                 request_signing_kid: Optional[str] = None,
                 request_signing_alg: str = "ES256",
                 http: Optional[HttpFn] = None,
                 clock: Callable[[], float] = time.time,
                 allow_insecure: bool = False):
        _http.require_https(bc_auth_endpoint, "bc_auth_endpoint", allow_insecure)
        _http.require_https(token_endpoint, "token_endpoint", allow_insecure)
        self.bc_auth_endpoint = bc_auth_endpoint
        self.token_endpoint = token_endpoint
        self.client_id = client_id
        self.client_auth = client_auth
        self.issuer = issuer
        self.request_signing_key_pem = request_signing_key_pem
        self.request_signing_kid = request_signing_kid
        self.request_signing_alg = request_signing_alg
        self.http = http or urllib_http()
        self.clock = clock

    # ---- bc-auth --------------------------------------------------------------------------------
    def request(self, *, login_hint: str, binding_message: Optional[str] = None,
                scope: str = "openid", authorization_details: Optional[list] = None,
                extra: Optional[dict] = None, request_ttl: int = 300) -> CibaRequest:
        """``POST bc-auth``. Returns the accepted request (with the AS's ``interval`` and
        ``expires_in``) or raises :class:`CibaError`.

        ``binding_message`` is what the human sees on the device — keep it SHORT (PingOne MFA renders
        ≤20 chars) and charset-safe; carry the full instruction out of band, keyed by it.
        ``authorization_details`` (RFC 9396) is sent FLAT, never inside the signed request object —
        on PingFederate the RAR pipeline runs on flat delivery but drops the details when they ride
        in the signed ``request`` JWT (a confirmed product defect).
        ``extra`` adds further request parameters. It may not set ``iss``, ``aud``, ``exp``, ``iat``,
        ``nbf``, ``jti``, ``scope``, ``login_hint`` or ``binding_message``: those come from this client
        and the named arguments, and a key that collides with one raises ``ValueError`` before anything
        is sent.
        """
        clash = sorted(_RESERVED_REQUEST_CLAIMS.intersection(extra or {}))
        if clash:
            raise ValueError(f"extra must not set reserved request parameters: {', '.join(clash)}")
        now = int(self.clock())
        claims = {"scope": scope, "login_hint": login_hint}
        if binding_message:
            claims["binding_message"] = binding_message
        if extra:
            claims.update(extra)
        form: dict = {}
        if self.request_signing_key_pem:
            req_obj = {"iss": self.client_id, "aud": self.issuer, "jti": uuid.uuid4().hex,
                       "iat": now, "exp": now + request_ttl, "nbf": now, **claims}
            form["request"] = jwt.encode(req_obj, self.request_signing_key_pem,
                                         algorithm=self.request_signing_alg,
                                         headers={"kid": self.request_signing_kid} if self.request_signing_kid else None)
        else:
            form.update(claims)
        if authorization_details is not None:
            form["authorization_details"] = json.dumps(authorization_details, separators=(",", ":"))
        self._apply_client_auth(self.bc_auth_endpoint, form)

        try:
            status, text = self.http("POST", self.bc_auth_endpoint, form, {})
        except Exception as exc:
            self._log_failed("ciba_request", self.bc_auth_endpoint, getattr(exc, "status", None),
                             _log.failure_reason(exc))
            raise
        if status != 200:
            self._log_failed("ciba_request", self.bc_auth_endpoint, status, "status")
            raise CibaError(f"bc-auth {status}: {text[:300]}", status=status,
                            body=text[:_http.ERROR_BODY_LIMIT])
        # From here the answer is a 200, whose body carries the auth_req_id: errors neither keep nor quote it
        # (the decode error holds the text, so it is not chained either).
        try:
            body, malformed = (_loads(text) if text else {}), False
        except ValueError:
            body, malformed = None, True
        if malformed:
            raise CibaError("bc-auth returned non-JSON", status=status)
        if not isinstance(body, dict):
            raise CibaError("bc-auth returned JSON that is not an object", status=status)
        interval = _bounded_int(body.get("interval"), _DEFAULT_INTERVAL, _MAX_INTERVAL)
        expires_in = _bounded_int(body.get("expires_in"), _DEFAULT_EXPIRES_IN, _MAX_EXPIRES_IN)
        auth_req_id = str(body.get("auth_req_id") or "")
        if not auth_req_id:
            raise CibaError("bc-auth returned no auth_req_id", status=status)
        _log.emit(_logger, logging.INFO, "authz.ciba_requested", host=_log.host(self.bc_auth_endpoint),
                  interval=interval, expires_in=expires_in)
        return CibaRequest(auth_req_id=auth_req_id, interval=interval, expires_in=expires_in,
                           requested_at=float(self.clock()))

    def _apply_client_auth(self, endpoint: str, form: dict) -> None:
        """``client_auth.apply``, with this client's issuer when the implementation takes it."""
        apply = self.client_auth.apply
        if _accepts_issuer(apply):
            apply(endpoint, form, issuer=self.issuer or None)
        else:
            apply(endpoint, form)

    @staticmethod
    def _log_failed(step: str, url: str, status, reason: str) -> None:
        _log.emit(_logger, logging.WARNING, "http.failed", step=step, method="POST", host=_log.host(url),
                  path=_log.path(url), status=status, reason=reason)

    # ---- token poll -----------------------------------------------------------------------------
    def poll(self, req: CibaRequest) -> str:
        """Ask the AS whether the human has answered. Returns one of :data:`PENDING`,
        :data:`APPROVED`, :data:`DENIED`, :data:`EXPIRED`.

        THROTTLED: if fewer than ``req.interval`` seconds have passed since the last real call, the
        cached outcome is returned and the AS is NOT contacted. Callers may therefore poll as often as
        they like (a browser every 2s, a concierge every 3s, a bridge every second) — the AS sees at
        most one request per interval.

        The poll state is locked only while it is read and updated, not during the call to the AS, so a
        slow AS holds up only the request being polled. While a call for ``req`` is in flight, another
        poll of ``req`` returns the cached outcome without contacting the AS, and does not end the request
        on the client clock even past its deadline: the AS's answer to that call is honoured whenever it
        arrives (the AS is the authority on expiry), so an approval given just before the deadline is not
        lost. Only when no call is in flight does the client clock expire the request.
        """
        with _POLL_STATE_LOCK:
            now = self.clock()
            if req.last_outcome in (APPROVED, DENIED, EXPIRED):
                return req.last_outcome
            if not req.auth_req_id:
                return PENDING
            if id(req) in _IN_FLIGHT:
                return req.last_outcome
            if req.expired_by_clock(now):
                req.last_outcome = EXPIRED
                req.last_error = "expires_in elapsed (client clock)"
                return EXPIRED
            if now - req.last_poll_at < req.interval + 0.5:
                return req.last_outcome
            req.last_poll_at = now
            _IN_FLIGHT.add(id(req))
        try:
            return self._poll_once(req)
        finally:
            with _POLL_STATE_LOCK:
                _IN_FLIGHT.discard(id(req))

    def _poll_once(self, req: CibaRequest) -> str:
        """One token-endpoint call for ``req``, its answer folded into ``req`` under the state lock. The
        caller has marked ``req`` in flight."""
        form = {"grant_type": CIBA_GRANT, "auth_req_id": req.auth_req_id}
        self._apply_client_auth(self.token_endpoint, form)
        try:
            status, text = self.http("POST", self.token_endpoint, form, {})
        except Exception as exc:  # noqa: BLE001 — a transport blip is not a verdict
            with _POLL_STATE_LOCK:
                outcome = req.last_outcome
                if outcome not in (APPROVED, DENIED, EXPIRED):     # a final verdict's state stays as it is
                    req.last_error = f"transport: {exc}"
            self._log_failed("ciba_poll", self.token_endpoint, getattr(exc, "status", None),
                             _log.failure_reason(exc))
            return outcome
        outcome = PENDING
        err = ""
        last_error = None
        token_response = token = None
        backoff = 0
        if status == 200:
            # Only a token response is an approval: a JSON object with a non-empty access_token.
            # Anything else on a 200 (an HTML page from a proxy, an empty body) is not a verdict.
            try:
                tr = _loads(text) if text else None
            except ValueError:
                tr = None
            token = tr.get("access_token") if isinstance(tr, dict) else None
            if isinstance(token, str) and token:
                outcome = APPROVED
                token_response = tr
            else:
                # stay pending, like any other answer we cannot read; last_error says why
                token = None
                last_error = "200 response is not a token response"
        else:
            err, desc = "", ""
            try:
                j = _loads(text) if text else {}
            except ValueError:
                j = None
            if isinstance(j, dict):
                err, desc = str(j.get("error") or ""), str(j.get("error_description") or "")
            else:
                # not JSON, or JSON that is not an object: read it as unparseable
                err = text[:80]
            last_error = f"{status} {err} {desc}".strip()
            if err == "slow_down":
                # CIBA Core §11: the client MUST add 5s to its interval.
                backoff = 5
            elif err == "access_denied":
                outcome = DENIED
            elif err in ("expired_token", "invalid_grant"):
                # invalid_grant is what PF says AFTER it has killed the request for interval
                # violations — indistinguishable from expiry to the client, so report it as one.
                outcome = EXPIRED
            elif err == "invalid_request" and "polling interval" in desc:
                # PF's last warning before it invalidates the grant. Back off hard.
                backoff = 5
            elif err == "authorization_pending":
                pass
            # anything else: stay pending; last_error carries the detail for logs
        with _POLL_STATE_LOCK:
            # Defensive: the first final verdict stands, so no two callers are told different ends. (A
            # concurrent poll of ``req`` does not end it while this call is in flight.)
            if req.last_outcome not in (APPROVED, DENIED, EXPIRED):
                if last_error is not None:
                    req.last_error = last_error
                if token is not None:
                    req.token_response = token_response
                    req.access_token = token
                req.interval += backoff
                req.last_outcome = outcome
            final = req.last_outcome
        _log.emit(_logger, logging.DEBUG, "authz.ciba_polled", outcome=final, status=status,
                  error=err if _OAUTH_ERROR_CODE.match(err) else None)
        return final
