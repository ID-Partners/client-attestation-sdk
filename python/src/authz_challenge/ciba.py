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

2. **``private_key_jwt`` audience.** PF validates the client assertion's ``aud`` against its own
   issuer / token endpoint, which in a proxied deployment is the INTERNAL address, not the public
   host you posted to. :func:`private_key_jwt_assertion` sends an ``aud`` array carrying the endpoint
   you called *and* the AS's internal issuer + token endpoint, or PF answers 400 ``invalid_client``.

Client authentication is pluggable (:class:`ClientAuth`). ``private_key_jwt`` ships here because that
is what the deployed CIBA clients use today; an attestation-based authenticator (this SDK's core
capability) slots in behind the same interface once the AS accepts it on the backchannel endpoint.
"""
from __future__ import annotations

import json
import ssl
import threading
import time
import urllib.parse
import uuid
import warnings
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol

import jwt

from client_attestation_sdk import _http
from client_attestation_sdk.errors import TransportError

# ---- outcomes -----------------------------------------------------------------------------------
PENDING = "pending"     # authorization_pending / slow_down — keep waiting
APPROVED = "approved"   # 200 from the token endpoint — the human approved
DENIED = "denied"       # access_denied
EXPIRED = "expired"     # expired_token, or PF's invalid_grant after it killed the request

CIBA_GRANT = "urn:openid:params:grant-type:ciba"
_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


class CibaError(Exception):
    """A backchannel request could not be raised (transport failure or a non-200 from bc-auth). The
    default transport (:func:`urllib_http`) also raises it for a network failure, a timeout, a redirect
    (never followed) or an oversized response."""

    def __init__(self, message: str, *, status: Optional[int] = None, body: Optional[str] = None):
        super().__init__(message)
        self.status = status
        self.body = body


# ---- transport ----------------------------------------------------------------------------------
# (method, url, form-fields, headers) -> (status, body-text). Injectable so a caller can supply
# its own HTTP stack (httpx, a test double, a recorder). The default is stdlib urllib, matching
# the rest of this SDK.
HttpFn = Callable[[str, str, dict, dict], "tuple[int, str]"]


def urllib_http(*, timeout: float = 30.0, dangerously_disable_tls_verification: bool = False,
                insecure_tls: Optional[bool] = None) -> HttpFn:
    """Default transport.

    ``dangerously_disable_tls_verification`` skips certificate AND hostname verification, so anyone
    on the path can impersonate the AS and read every client assertion and token. Only for an AS
    reached on an internal self-signed address in development, never for a public one.

    ``insecure_tls`` is the old name for the same switch. It still works for one release and emits
    a :class:`DeprecationWarning`; it will be removed.
    """
    if insecure_tls is not None:
        warnings.warn("urllib_http(insecure_tls=...) is deprecated; use "
                      "dangerously_disable_tls_verification=... instead", DeprecationWarning, stacklevel=2)
        dangerously_disable_tls_verification = dangerously_disable_tls_verification or bool(insecure_tls)
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
    """Adds the client's credential to a form POST bound for ``endpoint``."""

    def apply(self, endpoint: str, form: dict) -> None: ...  # noqa: E704


def private_key_jwt_assertion(*, client_id: str, endpoint: str, private_key_pem: str, kid: str,
                              extra_audiences: "tuple[str, ...]" = (), ttl: int = 120,
                              algorithm: str = "ES256") -> str:
    """Mint an RFC 7523 client-assertion JWT.

    ``aud`` is an ARRAY: the endpoint being called plus ``extra_audiences`` — the AS's internal issuer
    and token endpoint when the AS validates the audience against an address other than the one you
    reached it on (PingFederate behind a proxy does exactly this; omit them and PF 400s
    ``invalid_client``).
    """
    now = int(time.time())
    aud = [endpoint, *[a for a in extra_audiences if a and a != endpoint]]
    return jwt.encode({"iss": client_id, "sub": client_id, "aud": aud if len(aud) > 1 else aud[0],
                       "jti": uuid.uuid4().hex, "iat": now, "exp": now + ttl},
                      private_key_pem, algorithm=algorithm, headers={"kid": kid})


@dataclass
class PrivateKeyJwtAuth:
    """``private_key_jwt`` client authentication (RFC 7523 §2.2)."""
    client_id: str
    private_key_pem: str = field(repr=False)    # never in repr/logs
    kid: str
    # The AS's internal issuer + token endpoint, when they differ from the public URL you call.
    extra_audiences: "tuple[str, ...]" = ()
    algorithm: str = "ES256"

    def apply(self, endpoint: str, form: dict) -> None:
        form["client_assertion_type"] = _JWT_BEARER
        form["client_assertion"] = private_key_jwt_assertion(
            client_id=self.client_id, endpoint=endpoint, private_key_pem=self.private_key_pem,
            kid=self.kid, extra_audiences=self.extra_audiences, algorithm=self.algorithm)


# ---- request / poll state -----------------------------------------------------------------------
@dataclass
class CibaRequest:
    """One backchannel authentication request as the AS accepted it, plus the poll throttle state.

    This object IS the poll state — pass the same instance to every :meth:`CibaClient.poll`. If it is
    persisted and rebuilt (a restart mid-ceremony), seed ``last_poll_at`` with the current time on
    rebuild: the throttle state was lost, and one wasted interval is cheaper than a killed grant.
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
                "last_outcome": self.last_outcome}

    @classmethod
    def rehydrate(cls, d: dict) -> "CibaRequest":
        """Rebuild from :meth:`to_dict` output. Seeds the throttle so the first poll waits."""
        r = cls(auth_req_id=str(d.get("auth_req_id") or ""),
                interval=max(1, int(d.get("interval") or 3)),
                expires_in=int(d.get("expires_in") or 0),
                requested_at=float(d.get("requested_at") or time.time()))
        r.last_outcome = str(d.get("last_outcome") or PENDING)
        r.last_poll_at = time.time()
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
    :param issuer: the AS issuer — the ``aud`` of the signed request object
    :param http: transport (see :func:`urllib_http`)
    """

    def __init__(self, *, bc_auth_endpoint: str, token_endpoint: str, client_id: str,
                 client_auth: ClientAuth, issuer: str,
                 request_signing_key_pem: Optional[str] = None,
                 request_signing_kid: Optional[str] = None,
                 request_signing_alg: str = "ES256",
                 http: Optional[HttpFn] = None,
                 clock: Callable[[], float] = time.time):
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
        self._lock = threading.Lock()

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
        """
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
        self.client_auth.apply(self.bc_auth_endpoint, form)

        status, text = self.http("POST", self.bc_auth_endpoint, form, {})
        if status != 200:
            raise CibaError(f"bc-auth {status}: {text[:300]}", status=status, body=text)
        try:
            body = json.loads(text) if text else {}
        except ValueError:
            raise CibaError(f"bc-auth returned non-JSON: {text[:200]}", status=status, body=text)
        if not isinstance(body, dict):
            raise CibaError(f"bc-auth returned JSON that is not an object: {text[:200]}",
                            status=status, body=text)
        try:
            interval = max(1, int(body.get("interval") or 3))
        except (TypeError, ValueError):
            interval = 3
        try:
            expires_in = max(0, int(body.get("expires_in") or 0))
        except (TypeError, ValueError):
            expires_in = 0
        auth_req_id = str(body.get("auth_req_id") or "")
        if not auth_req_id:
            raise CibaError("bc-auth returned no auth_req_id", status=status, body=text)
        return CibaRequest(auth_req_id=auth_req_id, interval=interval, expires_in=expires_in,
                           requested_at=float(self.clock()))

    # ---- token poll -----------------------------------------------------------------------------
    def poll(self, req: CibaRequest) -> str:
        """Ask the AS whether the human has answered. Returns one of :data:`PENDING`,
        :data:`APPROVED`, :data:`DENIED`, :data:`EXPIRED`.

        THROTTLED: if fewer than ``req.interval`` seconds have passed since the last real call, the
        cached outcome is returned and the AS is NOT contacted. Callers may therefore poll as often as
        they like (a browser every 2s, a concierge every 3s, a bridge every second) — the AS sees at
        most one request per interval.
        """
        with self._lock:
            now = self.clock()
            if req.last_outcome in (APPROVED, DENIED, EXPIRED):
                return req.last_outcome
            if not req.auth_req_id:
                return PENDING
            if req.expired_by_clock(now):
                req.last_outcome = EXPIRED
                req.last_error = "expires_in elapsed (client clock)"
                return EXPIRED
            if now - req.last_poll_at < req.interval + 0.5:
                return req.last_outcome
            req.last_poll_at = now

            form = {"grant_type": CIBA_GRANT, "auth_req_id": req.auth_req_id}
            self.client_auth.apply(self.token_endpoint, form)
            try:
                status, text = self.http("POST", self.token_endpoint, form, {})
            except Exception as exc:  # noqa: BLE001 — a transport blip is not a verdict
                req.last_error = f"transport: {exc}"
                return req.last_outcome
            outcome = PENDING
            if status == 200:
                outcome = APPROVED
                try:
                    tr = json.loads(text) if text else {}
                except ValueError:
                    tr = {}
                req.token_response = tr
                req.access_token = tr.get("access_token") if isinstance(tr, dict) else None
            else:
                err, desc = "", ""
                try:
                    j = json.loads(text) if text else {}
                    err, desc = str(j.get("error") or ""), str(j.get("error_description") or "")
                except ValueError:
                    err = text[:80]
                req.last_error = f"{status} {err} {desc}".strip()
                if err == "slow_down":
                    # CIBA Core §11: the client MUST add 5s to its interval.
                    req.interval += 5
                elif err == "access_denied":
                    outcome = DENIED
                elif err in ("expired_token", "invalid_grant"):
                    # invalid_grant is what PF says AFTER it has killed the request for interval
                    # violations — indistinguishable from expiry to the client, so report it as one.
                    outcome = EXPIRED
                elif err == "invalid_request" and "polling interval" in desc:
                    # PF's last warning before it invalidates the grant. Back off hard.
                    req.interval += 5
                elif err == "authorization_pending":
                    pass
                # anything else: stay pending; last_error carries the detail for logs
            req.last_outcome = outcome
            return outcome
