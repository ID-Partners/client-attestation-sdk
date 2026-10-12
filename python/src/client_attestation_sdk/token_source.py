"""One call to get an access token with client attestation.

Point it at an attester (PingFederate by default) and call `.token()`. It runs the whole flow:

    discover -> get platform identity (evidence) -> get a challenge -> mint the attestation ->
    call the token endpoint with the attestation headers -> cache the access token

The workload sends no client secret and no client_id. Its only credential is the attestation, built
from the identity its runtime already gives it (auto-detected; see `evidence.py`).

    from client_attestation_sdk import ClientAttestation

    ca = ClientAttestation("pf.example.com", evidence_audience="https://attester.example.com/evidence")
    token = ca.token()                                   # access token, cached until it nears expiry

    import requests
    requests.get(api, auth=ca.requests_auth())           # attaches Authorization (and DPoP, if bound)

    # or hand the headers to anything (httpx, fetch, an ADK header_provider):
    headers = ca.request_headers("GET", api)
"""
from __future__ import annotations

import base64
import json
import logging
import math
import re
import shlex
import threading
import time
import urllib.parse
import zlib

from . import _http, _log
from .attester import AttesterMetadata, AttesterProfile, MintRequest, PingFederateProfile
from ._redact import PRIVATE_JWK_MEMBERS as _PRIVATE_JWK_MEMBERS  # noqa: F401 - kept importable
from ._redact import SECRET_FIELDS as _SECRET_FIELDS  # noqa: F401 - kept importable
from ._redact import redact_json as _redact_json, redacted as _redacted
from .builders import DpopProofBuilder, PopBuilder, _check_htu, _normalize_htu, _url_origin as _origin
from .errors import ClientAttestationError, TransportError  # noqa: F401 - re-exported
from .evidence import auto_detect_evidence
from .keys import SigningKeyPair
from .svid_source import SvidSource

ATTESTATION_HEADER = "OAuth-Client-Attestation"
POP_HEADER = "OAuth-Client-Attestation-PoP"
DPOP_HEADER = "DPoP"
# The PingFederate profile's conventions, kept importable from here (see attester.PingFederateProfile).
INSTANCE_PROOF_TYP = PingFederateProfile.INSTANCE_PROOF_TYP
WELL_KNOWN_PATH = PingFederateProfile.WELL_KNOWN_PATH
# Refresh this many seconds before the token actually expires, so a token is never used at the edge.
DEFAULT_EXPIRY_SKEW_SECONDS = 30
DPOP_NONCE_HEADER = "DPoP-Nonce"
# A token is cached for at most this long (seconds), whatever `expires_in` the token endpoint gives.
_MAX_TOKEN_LIFETIME = 24 * 60 * 60
# At most this much of a 400 body is read to look for `use_dpop_nonce`; a longer body is not a challenge.
_MAX_NONCE_CHALLENGE_BODY = 64 * 1024
# RFC 9449 nonces are short opaque strings: a longer `DPoP-Nonce` is ignored, as if there were none.
_MAX_DPOP_NONCE_LENGTH = 1024
# At most this many origins' nonces are remembered; a new origin over the cap replaces the one stored
# longest ago (it costs that origin one challenge).
_MAX_DPOP_NONCE_ORIGINS = 256
# What the https check calls the URL a profile's call goes to, by step.
_STEP_LABELS = {"discover": "attester_url", "mint": "attestation_endpoint", "challenge": "challenge_endpoint"}

# Trace redaction (see `trace_redact`): header names whose values are credentials. The JSON/form members
# and private JWK members live in `_redact`, shared with the loggers.
_SECRET_HEADERS = frozenset(h.lower() for h in ("Authorization", DPOP_HEADER, ATTESTATION_HEADER, POP_HEADER))
_PIN_REQUIRED = ("evidence_audience is required: set it to the audience your attester expects the workload's "
                 "identity token for, so the attester's discovery document can't choose it")

# Logs the flow's lifecycle (docs/logging.md). Silent unless the application configures logging.
_logger = _log.get("token_source")


class ClientAttestation:
    """Gets and caches an access token using client attestation.

    Args:
        attester_url: the attester's host — `"pf.example.com"`, or a full base URL
            `"https://pf.example.com"`. Plain hostnames default to https. Optional when `metadata` is
            given (no discovery is needed) or a custom `profile` does not need it.
        profile: the :class:`~client_attestation_sdk.attester.AttesterProfile` that discovers the
            attester and mints the attestation. Default :class:`PingFederateProfile`, the behaviour of
            every earlier release. See docs/attester-profiles.md.
        metadata: static :class:`~client_attestation_sdk.attester.AttesterMetadata` (evidence audience,
            attestation and token endpoints, optionally challenge endpoint and PoP audience). When set,
            no discovery request is made; the profile still mints.
        evidence: how to get the workload's platform identity. Leave as None to auto-detect the
            runtime (env token, projected token file, SPIRE socket, or GCP metadata). Pass an
            `SvidSource` to override.
        authorization_details: optional RFC 9396 access request sent at mint time; the attester grants
            at most what the workload is entitled to.
        algorithm: instance-key signature algorithm (default ES256).
        expiry_skew_seconds: refresh this long before the token expires (finite, not negative).
        timeout: per-request HTTP timeout in seconds.
        pop_method: how the instance key proves possession at the token endpoint.
            `"attestation_pop_jwt"` (default) sends a Client Attestation PoP JWT under the
            `OAuth-Client-Attestation-PoP` header. `"dpop_combined"` instead sends an RFC 9449
            DPoP proof (bound to the same instance key) under the `DPoP` header, with the
            attester-issued challenge carried as the DPoP `nonce`.
        challenge_at_token: whether the attester-issued challenge also rides in the token-endpoint
            proof (the PoP's `challenge` claim, or the DPoP `nonce`), on top of the mint-time
            instance proof it always protects. Default `True` binds token issuance to the same
            challenge as the mint, so a captured attestation cannot be redeemed for a token without
            it — but it requires an attester whose challenge store tolerates being checked at both
            points. Some attesters treat a challenge as consumed the moment the mint's instance
            proof uses it, and then reject a token request that presents the same value as
            "unknown or expired" — set this `False` against one of those (the challenge still
            protects the mint; only the token-endpoint copy is dropped).
        trace: optional list to append a `{"step", "curl"}` record to for each wire call the flow
            makes (`discover`, `challenge`, `mint`, `token`) — the same shape demo consoles already
            render as "show the exact request". The `challenge` record also gets a `value` key (the
            issued challenge string); `mint` and `token` also get a `jwt` key (the attestation and
            the access token, respectively). `None` (default) costs nothing and changes no behaviour.
            Every curl argument is shell-quoted, so the string can be pasted into a POSIX shell.
        trace_redact: with a `trace`, replace every credential in a record with `<redacted:N bytes>`
            (default `True`): the Authorization, DPoP, OAuth-Client-Attestation and
            OAuth-Client-Attestation-PoP header values, the svid/proof/assertion members (and any
            private JWK members) of a request body, any other body value that looks like a JWT (so a
            custom profile's own member names are covered), and the `value` and `jwt` keys. `False` records
            them verbatim — for local debugging only; a trace kept that way holds live credentials.
        require_challenge: when the discovery document advertises a `challenge_endpoint` and the
            challenge cannot be fetched (network, HTTP status, bad JSON, no `attestation_challenge`),
            fail with `ClientAttestationError` (default `True`). `False` keeps the old behaviour of
            minting without a challenge. No advertised endpoint means no challenge and no error.
        allow_insecure: allow plain-http `attester_url` and discovery endpoints for non-loopback hosts
            (default `False`). Loopback (`localhost`, `127.0.0.1`, `::1`) is always allowed.
        evidence_audience: the audience the workload's platform identity token is requested for, which
            the attester's discovery document must name. Required unless `metadata` is given: every
            evidence source (GCP, AWS, Azure, SPIRE) fetches a token for whatever audience it is asked
            for, so without a pin an attester could have the workload mint a token for another service
            that trusts it. A missing pin or a different discovered audience raises
            `ClientAttestationError` before any evidence is fetched. With static `metadata`, the pin is
            optional and, when given, must match `metadata.evidence_audience`.
    """

    def __init__(self, attester_url: str = None, *, evidence: SvidSource = None,
                 authorization_details: list = None,
                 operator: dict = None,
                 algorithm: str = "ES256", expiry_skew_seconds: int = DEFAULT_EXPIRY_SKEW_SECONDS,
                 timeout: float = 20.0, pop_method: str = "attestation_pop_jwt",
                 challenge_at_token: bool = True,
                 trace: list = None, trace_redact: bool = True,
                 require_challenge: bool = True, allow_insecure: bool = False,
                 profile: AttesterProfile = None, metadata: AttesterMetadata = None,
                 evidence_audience: str = None):
        if isinstance(expiry_skew_seconds, bool) or not isinstance(expiry_skew_seconds, (int, float)) \
                or not math.isfinite(expiry_skew_seconds) or expiry_skew_seconds < 0:
            raise ValueError("expiry_skew_seconds must be a finite number, not negative: "
                             f"{expiry_skew_seconds!r}")
        self._profile = profile if profile is not None else PingFederateProfile()
        self._allow_insecure = allow_insecure
        if attester_url is None and (metadata is not None or profile is not None):
            self.base_url = None
        else:
            self.base_url = _normalize_base_url(attester_url)
            _require_https(self.base_url, "attester_url", allow_insecure)
        self._metadata = metadata
        self._static_metadata = metadata is not None
        self._evidence_audience = evidence_audience
        self._evidence = evidence
        self._authorization_details = authorization_details
        self._operator = operator
        self._algorithm = algorithm
        self._skew = expiry_skew_seconds
        self._timeout = timeout
        self._pop_method = pop_method
        self._challenge_at_token = challenge_at_token
        self._trace = trace
        self._trace_redact = trace_redact
        self._require_challenge = require_challenge

        self._lock = threading.Lock()
        self._cached_token = None
        self._token_type = "Bearer"
        self._token_key = None   # the instance key the cached token is bound to (cnf); same lock
        self._expires_at = 0.0   # time.monotonic() deadline; a wall-clock step cannot extend it
        self._nonce_lock = threading.Lock()
        self._dpop_nonces = {}   # origin -> last DPoP-Nonce that origin returned, oldest first

    # ── public API ────────────────────────────────────────────────────────────────────────────────
    def token(self, *, force_refresh: bool = False, asserted_context: dict = None) -> str:
        """Return a valid access token, minting a new one only when the cached one is near expiry.

        `asserted_context` (`{"type": ..., "value": ...}`) carries an optional caller-supplied,
        UNVERIFIED discriminator to an attester-side `AssertedContextResolver` an opted-in client
        configures — e.g. an Entra Agent ID `oid` a directory-hosted gateway workload cannot itself
        cryptographically prove. Present, this always mints fresh (never served from cache, and never
        cached afterward): the resolved ceiling can differ per discriminator, so caching one token
        per `ClientAttestation` instance would silently reuse a stale/wrong ceiling for a different
        caller. Absent (the default), behavior is unchanged for every existing caller.
        """
        return self._token_state(force_refresh=force_refresh, asserted_context=asserted_context)[0]

    def _token_state(self, *, force_refresh: bool = False, asserted_context: dict = None):
        """`(access_token, token_type, instance_key)`, read or minted together under one lock so a
        DPoP-bound token is never paired with a key other than the one it was bound to."""
        with self._lock:
            now = time.monotonic()
            if asserted_context is None and not force_refresh \
                    and self._cached_token and now < self._expires_at:
                _log.emit(_logger, logging.DEBUG, "token.cache_hit", expires_in=int(self._expires_at - now))
                return self._cached_token, self._token_type, self._token_key
            reason = ("asserted_context" if asserted_context is not None else "forced" if force_refresh
                      else "initial" if not self._cached_token else "expired")
            _log.emit(_logger, logging.DEBUG, "token.refreshing", reason=reason)
            response, instance_key = self._run_flow(asserted_context=asserted_context)
            access_token = response["access_token"]
            token_type = _token_type(response)
            if asserted_context is None:
                lifetime = _token_lifetime(response.get("expires_in"))
                expires_at = time.monotonic() + lifetime - self._skew if lifetime is not None else 0.0
                self._cached_token = access_token
                self._token_type = token_type
                self._token_key = instance_key
                self._expires_at = expires_at
            return access_token, token_type, instance_key

    def authorization_header(self, *, force_refresh: bool = False) -> dict:
        """`{"Authorization": "Bearer <token>"}` — for httpx, fetch, an ADK header_provider, anything.

        For a DPoP-bound token (token_type `DPoP`, from `pop_method="dpop_combined"`) this returns
        `{"Authorization": "DPoP <token>"}`, and a resource will ALSO require a per-request DPoP proof:
        use :meth:`request_headers` (or :meth:`requests_auth` / :meth:`httpx_auth`) instead."""
        access_token, token_type, _ = self._token_state(force_refresh=force_refresh)
        return {"Authorization": f"{token_type} {access_token}"}

    def request_headers(self, method: str, url: str) -> dict:
        """The headers to send with one request to a resource, getting or refreshing the token as
        :meth:`token` does.

        - Bearer token: `{"Authorization": "Bearer <token>"}`.
        - DPoP-bound token: `{"Authorization": "DPoP <token>", "DPoP": <proof>}`, where the proof is
          fresh for this call, signed by the instance key the token is bound to, and carries `htm`,
          `htu` (the URL without query or fragment), `ath` and the last `DPoP-Nonce` the URL's origin
          returned, if any.

        `url` must be https, like every other URL the client sends a credential to (loopback hosts
        and `allow_insecure=True` excepted).

        Pass the exact URL your HTTP client sends (after any normalisation it does): the proof is only
        valid for the `htu` it names. A URL with a backslash, ASCII whitespace or a control character
        before its query or fragment raises `ClientAttestationError`, because parsers disagree on where
        it goes - `requests` sends `https://evil.example\\@as.example/t` to evil.example, but its `htu`
        would name as.example. For a DPoP-bound token, so does a URL that is not an absolute http(s) URL
        with a valid ASCII host, port and path (the rule is in vectors/README.md); with
        `pop_method="dpop_combined"` that is checked before the token is fetched. `requests_auth()` and
        `httpx_auth()` use the prepared URL for you.
        """
        return self._request_headers(method, url)

    def _request_headers(self, method: str, url: str, nonce=None) -> dict:
        """:meth:`request_headers`, with the proof carrying `nonce` when given (the nonce of the
        challenge being answered) instead of the origin's remembered one."""
        _require_https(url, "resource URL", self._allow_insecure)
        # A client configured for DPoP checks the whole htu before fetching the token, so a URL with no
        # htu never costs a mint and token request on a cold cache. Otherwise only what parsers disagree
        # on is refused up front: a Bearer token carries no htu.
        check = _normalize_htu if self._pop_method == "dpop_combined" else _check_htu
        try:
            check(url)
        except ValueError as error:
            raise ClientAttestationError(str(error)) from None
        access_token, token_type, instance_key = self._token_state()
        if token_type != "DPoP":
            return {"Authorization": f"{token_type} {access_token}"}
        try:   # also for a DPoP token from a client not configured for DPoP (the AS chose the type)
            _normalize_htu(url)
        except ValueError as error:
            raise ClientAttestationError(str(error)) from None
        proof = (DpopProofBuilder(instance_key).method(method).uri(url).access_token(access_token)
                 .nonce(nonce if nonce is not None else self._nonce_for(url)).build())
        return {"Authorization": "DPoP " + access_token, DPOP_HEADER: proof}

    def requests_auth(self):
        """A `requests` auth object that attaches the token (and refreshes it) on every call.

        For a DPoP-bound token it also attaches a fresh proof, and when the resource answers with a
        DPoP nonce challenge (`use_dpop_nonce` plus a `DPoP-Nonce` header) it remembers the nonce and
        re-sends the request once with a proof carrying it. A request whose body cannot be replayed
        (a stream or generator) is not re-sent. At most 64 KiB of a 400 body is read to look for the
        challenge (a longer body is not one), and the response still hands back the whole body.

        For a DPoP-bound token, the token and proof never follow a redirect. Once a response comes
        back, the hook takes `Authorization` and `DPoP` off the request that `requests` copies to build
        each redirect hop, including after a nonce retry. The hook does nothing (no retry, no nonce
        memory) for a response from any origin other than the one the request was sent to. For a
        Bearer token no hook is registered, and `requests` applies its own rule: it drops
        `Authorization` when a redirect changes the host, but keeps it on a same-host hop."""
        source = self

        class _Auth:
            def __call__(self, request):
                headers = source.request_headers(request.method, request.url)
                request.headers.update(headers)
                if DPOP_HEADER in headers:
                    origin = _origin(request.url)
                    request.register_hook("response", lambda response, **kwargs:
                                          self._on_response(response, origin, **kwargs))
                return request

            def _on_response(self, response, origin, **kwargs):
                # requests copies this request (headers and hooks) for each redirect hop, and it only
                # drops Authorization when the host changes. The hook therefore also runs on every hop,
                # so it must leave a response from another origin alone. A nonce retry there would sign
                # a proof for the redirect target and attach the token to it.
                request = response.request
                if _origin(request.url) != origin or DPOP_HEADER not in request.headers:
                    _strip_credentials(request)
                    return response
                nonce = None
                if not response.is_redirect:
                    nonce = source._observe_response(request.url, response.status_code,
                                                     response.headers,
                                                     lambda: _requests_body(response))
                if nonce is None or not _replayable(request.body):
                    _strip_credentials(request)
                    return response
                _log_nonce_retry(request.url, response.status_code, "resource")
                retry = request.copy()
                retry.hooks = {"response": []}
                # Answer this challenge with its own nonce, not one a concurrent response stored since.
                retry.headers.update(source._request_headers(retry.method, retry.url, nonce))
                # Session.send builds any redirect hop from the ORIGINAL request, even when this hook
                # returns the retry's response. Take the credentials off both before handing it back.
                _strip_credentials(request)
                response.content  # drain, so the connection can be reused  # noqa: B018
                response.close()
                second = response.connection.send(retry, **kwargs)
                _strip_credentials(retry)
                second.history.append(response)
                second.request = retry
                return second

        return _Auth()

    def httpx_auth(self):
        """An `httpx.Auth` that attaches the token (and refreshes it) on every call. For a DPoP-bound
        token it behaves as :meth:`requests_auth` does: fresh proof per request, one re-send on a DPoP
        nonce challenge (only when the request body is in memory). A 400 body is looked at only with a
        sync client; with an async one only a 401 challenge is retried. With `follow_redirects=True`, a
        response whose redirect chain left the request's origin is never answered with a retry, and its
        `DPoP-Nonce` is not remembered. httpx follows redirects itself, after this auth has attached the
        headers, so it cannot strip them per hop. httpx drops Authorization on a cross-origin redirect
        but forwards the original DPoP proof (signed for the original URL), so leave `follow_redirects`
        off (the httpx default) with this auth."""
        import httpx  # imported lazily so httpx is not a hard dependency

        source = self

        class _Auth(httpx.Auth):
            def auth_flow(self, request):
                url = str(request.url)
                headers = source.request_headers(request.method, url)
                request.headers.update(headers)
                response = yield request
                if DPOP_HEADER not in headers:
                    return
                if response.history and any(_origin(str(hop.url)) != _origin(url)
                                            for hop in (*response.history, response)):
                    return
                nonce = source._observe_response(url, response.status_code, response.headers,
                                                 lambda: _httpx_body(response))
                if nonce is None or not isinstance(request.stream, httpx.ByteStream):
                    return
                _log_nonce_retry(url, response.status_code, "resource")
                request.headers.update(source._request_headers(request.method, url, nonce))
                yield request

        return _Auth()

    # ── DPoP nonces (RFC 9449 section 8/9) ──────────────────────────────────────────────────────
    def _nonce_for(self, url: str):
        with self._nonce_lock:
            return self._dpop_nonces.get(_origin(url))

    def _remember_nonce(self, url: str, nonce: str) -> None:
        """Store `nonce` as the origin's latest, forgetting the origin stored longest ago when a new
        one would go over `_MAX_DPOP_NONCE_ORIGINS`."""
        key = _origin(url)
        with self._nonce_lock:
            self._dpop_nonces.pop(key, None)
            if len(self._dpop_nonces) >= _MAX_DPOP_NONCE_ORIGINS:
                del self._dpop_nonces[next(iter(self._dpop_nonces))]
            self._dpop_nonces[key] = nonce

    def _observe_response(self, url: str, status: int, headers, body) -> "str | None":
        """Remember any `DPoP-Nonce` the response carries; return it when the response is a nonce
        challenge (a request worth re-sending with a proof that carries it), else None. A nonce longer
        than `_MAX_DPOP_NONCE_LENGTH` is ignored."""
        nonce = headers.get(DPOP_NONCE_HEADER)
        if not nonce or len(nonce) > _MAX_DPOP_NONCE_LENGTH:
            return None
        self._remember_nonce(url, nonce)
        return nonce if _is_nonce_challenge(status, headers, body) else None

    def discovery(self) -> dict:
        """The attester's discovery document (for the PingFederate profile,
        `/.well-known/client-attester`), fetched once and then cached. With static `metadata`, the fields
        that were given."""
        return self.attester_metadata().as_document()

    def attester_metadata(self) -> AttesterMetadata:
        """The attester's endpoints: the static `metadata`, or what the profile discovered (once, then
        cached)."""
        host = _log.host(self.base_url) if self.base_url else None
        if self._metadata is None:
            self._metadata = self._profile.discover(self._transport(), self.base_url)
            _log.emit(_logger, logging.DEBUG, "discovery.fetched", host=host)
        else:
            _log.emit(_logger, logging.DEBUG, "discovery.cached", host=host)
        return self._metadata

    def _transport(self):
        """The transport handed to the profile: this client's https rule, timeout, logging and trace."""
        source = self

        class _Transport:
            def request_json(self, step: str, method: str, url: str, body: dict = None) -> dict:
                _require_https(url, _STEP_LABELS.get(step, f"{step} URL"), source._allow_insecure)
                return source._get_json(method, url, json_body=body, step=step)

        return _Transport()

    # ── tracing (opt-in; see `trace` and `trace_redact` in __init__) ────────────────────────────
    def _record(self, step: str, method: str, url: str, headers: dict, *,
                json_body: dict = None, form: dict = None) -> None:
        if self._trace is None:
            return
        q = shlex.quote
        parts = [f"curl -s -X {q(method)} {q(url)}"]
        for key, value in headers.items():
            if self._trace_redact and key.lower() in _SECRET_HEADERS:
                value = _redacted(value)
            parts.append("  -H " + q(f"{key}: {value}"))
        has_content_type = any(key.lower() == "content-type" for key in headers)
        if json_body is not None:
            if not has_content_type:
                parts.append("  -H " + q("Content-Type: application/json"))
            shown = _redact_json(json_body) if self._trace_redact else json_body
            parts.append("  -d " + q(json.dumps(shown, indent=2)))
        elif form is not None:
            if not has_content_type:
                parts.append("  -H " + q("Content-Type: application/x-www-form-urlencoded"))
            shown = _redact_json(form) if self._trace_redact else form
            parts.append("  -d " + q(urllib.parse.urlencode(shown)))
        self._trace.append({"step": step, "curl": " \\\n".join(parts)})

    def _annotate(self, key: str, value: str) -> None:
        """Attach an artifact (`value`, `jwt`) to the latest trace record, redacted unless disabled."""
        if self._trace is not None and self._trace:
            self._trace[-1][key] = _redacted(value) if self._trace_redact else value

    # ── the flow ──────────────────────────────────────────────────────────────────────────────────
    def _run_flow(self, *, asserted_context: dict = None):
        """Run the flow once; returns `(token_response, instance_key)`."""
        if not self._evidence_audience and not self._static_metadata:
            raise ClientAttestationError(_PIN_REQUIRED)
        meta = self.attester_metadata()
        audience = meta.evidence_audience
        if not audience:
            raise ClientAttestationError("attester discovery document has no evidence_audience")
        if self._evidence_audience and audience != self._evidence_audience:
            raise ClientAttestationError(
                f"the attester asks for evidence for {audience!r}, but evidence_audience is "
                f"{self._evidence_audience!r}")

        evidence_source = self._evidence or auto_detect_evidence()
        svid = evidence_source.fetch(audience)
        _log.emit(_logger, logging.DEBUG, "evidence.obtained", source=type(evidence_source).__name__)

        instance_key = SigningKeyPair.generate(self._algorithm)
        challenge = self._fetch_challenge(meta.challenge_endpoint)
        minted = self._profile.mint(self._transport(), meta, MintRequest(
            instance_key=instance_key, evidence=svid, challenge=challenge,
            authorization_details=self._authorization_details or None, operator=self._operator or None,
            asserted_context=asserted_context or None))
        attestation = minted.attestation
        self._annotate("jwt", attestation)

        # The profile resolves the token endpoint (PingFederate: the advertised one, else the standard
        # path on the attester host).
        token_endpoint = meta.token_endpoint
        if not token_endpoint:
            raise ClientAttestationError("attester metadata has no token_endpoint")
        _require_https(token_endpoint, "token_endpoint", self._allow_insecure)
        client_id = _jwt_sub(attestation)
        _log.emit(_logger, logging.DEBUG, "attestation.minted",
                  host=_log.host(meta.attestation_endpoint) if meta.attestation_endpoint else None,
                  client_id=client_id, alg=self._algorithm)
        # See `challenge_at_token` on __init__: some attesters consume the challenge the moment the
        # mint's instance proof uses it, and reject a token request that presents the same value a
        # second time. Against one of those, only the mint gets the challenge.
        token_challenge = challenge if self._challenge_at_token else None

        if self._pop_method == "dpop_combined":
            # RFC 9449 DPoP proof, bound to the same instance key the attestation's cnf names. The
            # attester-issued challenge rides as the DPoP nonce — the AS ties it back to the mint the
            # same way it would a PoP JWT's `challenge` claim. If the AS demands its own nonce
            # (400 use_dpop_nonce), the retry carries the server's value instead.
            def dpop_proof(nonce):
                return DpopProofBuilder(instance_key).method("POST").uri(token_endpoint).nonce(nonce).build()

            proof = dpop_proof(token_challenge or self._nonce_for(token_endpoint))
            proof_header = DPOP_HEADER
            retry_proof = dpop_proof
        else:
            # The PoP audience must be PF's configured issuer, which the attester advertises as
            # pop_audience. Falling back to the token endpoint URL only works when the dialed URL
            # matches PF's issuer (no proxy in between) — so prefer the advertised value.
            pop_audience = meta.pop_audience or token_endpoint
            proof = (PopBuilder(instance_key).client_id(client_id).audience(pop_audience)
                     .challenge(token_challenge).build())
            proof_header = POP_HEADER
            retry_proof = None

        response = self._call_token_endpoint(token_endpoint, attestation, proof, proof_header,
                                             operator=self._operator, retry_proof=retry_proof)
        lifetime = _token_lifetime(response.get("expires_in"))
        _log.emit(_logger, logging.INFO, "token.obtained", host=_log.host(token_endpoint), client_id=client_id,
                  token_type=_token_type(response),
                  expires_in=int(lifetime) if lifetime is not None else None, pop_method=self._pop_method)
        return response, instance_key

    def _fetch_challenge(self, endpoint):
        if not endpoint:
            return None
        _require_https(endpoint, "challenge_endpoint", self._allow_insecure)
        try:
            body = self._get_json("POST", endpoint, step="challenge")
            value = body.get("attestation_challenge")
            if not value or not isinstance(value, str):
                raise ClientAttestationError("challenge endpoint response has no attestation_challenge")
        except ClientAttestationError as error:
            if not self._require_challenge:
                # Opted out (require_challenge=False): mint without one, as older releases did.
                _log.emit(_logger, logging.WARNING, "challenge.skipped", host=_log.host(endpoint))
                return None
            # The attester advertises a challenge, so it is part of the anti-replay contract; minting
            # without one would silently weaken it. Fail closed.
            raise ClientAttestationError(f"could not get an attestation challenge from {endpoint}: {error}",
                                         status=error.status, body=error.body) from error
        self._annotate("value", value)
        _log.emit(_logger, logging.DEBUG, "challenge.fetched", host=_log.host(endpoint))
        return value

    def _call_token_endpoint(self, endpoint: str, attestation: str, proof: str, proof_header: str,
                             *, operator: dict = None, retry_proof=None) -> dict:
        params = {"grant_type": "client_credentials"}
        if operator:
            # Extension parameter, sent only when configured. The attestation is the authoritative
            # carrier (the attester signed it); this repeats it on the wire so an AS that wants to
            # populate RFC 8693 `may_act` from it can, without having to parse the attestation in
            # its attribute mapping. An AS that does not know the parameter ignores it, so sending
            # it is safe against a stock authorization server.
            params["operator"] = json.dumps(operator, separators=(",", ":"), sort_keys=True)
        form = urllib.parse.urlencode(params).encode("utf-8")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            ATTESTATION_HEADER: attestation,
            proof_header: proof,
        }
        self._record("token", "POST", endpoint, headers, form=params)
        response = self._send("token", "POST", endpoint, headers, form)
        if retry_proof is not None:
            # RFC 9449 section 8: the AS may demand its own nonce. Retry once with a proof carrying it.
            nonce = self._observe_response(endpoint, response.status, response.headers, response.body)
            if nonce is not None:
                _log_nonce_retry(endpoint, response.status, "token_endpoint")
                headers[proof_header] = retry_proof(nonce)
                self._record("token", "POST", endpoint, headers, form=params)
                response = self._send("token", "POST", endpoint, headers, form)
        parsed = self._json_ok("token", "POST", endpoint, response, "token endpoint")
        if "access_token" not in parsed:
            # No body: a 2xx token response may hold the token under another name.
            raise ClientAttestationError("token endpoint returned no access_token")
        self._annotate("jwt", parsed["access_token"])
        return parsed

    def _get_json(self, method: str, url: str, *, json_body: dict = None, step: str = None) -> dict:
        data = json.dumps(json_body).encode("utf-8") if json_body is not None else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if step:
            self._record(step, method, url, headers, json_body=json_body)
        response = self._send(step, method, url, headers, data)
        return self._json_ok(step, method, url, response, f"{method} {url}", allow_empty=True)

    def _send(self, step, method: str, url: str, headers: dict, body) -> _http.HttpResponse:
        """One call through the shared transport, logging `http.failed` when it raises."""
        try:
            return _http.request(method, url, headers=headers, body=body, timeout=self._timeout)
        except TransportError as error:
            _log_http_failed(step, method, url, error)
            raise

    @staticmethod
    def _json_ok(step, method: str, url: str, response: _http.HttpResponse, what: str, *,
                 allow_empty: bool = False) -> dict:
        try:
            return _http.json_ok(response, what, allow_empty=allow_empty)
        except TransportError as error:
            _log_http_failed(step, method, url, error)
            raise


def _normalize_base_url(attester_url: str) -> str:
    host = (attester_url or "").strip().rstrip("/")
    if not host:
        raise ValueError("attester_url is required")
    if "://" not in host:
        host = "https://" + host
    return host


# Shared with the issuance client and the OpenBao signer.
_require_https = _http.require_https


_NUMERIC_STRING = re.compile(r"[0-9]+(?:\.[0-9]+)?")


def _token_lifetime(expires_in) -> "float | None":
    """How long to cache a token, in seconds: `expires_in` as a JSON number, or a string of decimal
    digits, capped at `_MAX_TOKEN_LIFETIME`. Anything else — missing, null, not a number, not finite, zero
    or negative — is None, and the token is not cached, as with no `expires_in` at all."""
    if isinstance(expires_in, bool):
        return None
    if isinstance(expires_in, str) and _NUMERIC_STRING.fullmatch(expires_in):
        expires_in = float(expires_in)
    if not isinstance(expires_in, (int, float)):
        return None
    try:
        seconds = float(expires_in)
    except OverflowError:  # an integer too large for a float: not finite, as the other ports read it
        return None
    if not math.isfinite(seconds) or seconds <= 0:
        return None
    return min(seconds, _MAX_TOKEN_LIFETIME)


def _token_type(response: dict) -> str:
    """The token response's `token_type`, normalised: `DPoP` or `Bearer` (absent or unknown = Bearer)."""
    token_type = response.get("token_type")
    if isinstance(token_type, str) and token_type.lower() == "dpop":
        return "DPoP"
    return "Bearer"


_DPOP_SCHEME = re.compile(r"(?:^|,)\s*dpop\b", re.IGNORECASE)
_USE_DPOP_NONCE = re.compile(r'error\s*=\s*"?use_dpop_nonce"?', re.IGNORECASE)


def _is_nonce_challenge(status: int, headers, body) -> bool:
    """A 401 whose WWW-Authenticate is a DPoP challenge with error="use_dpop_nonce", or a 400 whose JSON
    error is "use_dpop_nonce". `body` is the bytes, or a callable returning them (read only for a 400)."""
    if status == 401:
        challenge = headers.get("WWW-Authenticate") or ""
        return bool(_DPOP_SCHEME.search(challenge) and _USE_DPOP_NONCE.search(challenge))
    if status == 400:
        raw = body() if callable(body) else body
        try:
            parsed = json.loads(raw) if raw else None
        except (ValueError, TypeError):
            return False
        return isinstance(parsed, dict) and parsed.get("error") == "use_dpop_nonce"
    return False


def _strip_credentials(request) -> None:
    """Take the token and DPoP proof off a `requests` PreparedRequest that has already been sent, so a
    redirect hop that `requests` copies from it carries neither."""
    request.headers.pop("Authorization", None)
    request.headers.pop(DPOP_HEADER, None)


def _replayable(body) -> bool:
    return body is None or isinstance(body, (bytes, bytearray, str))


def _requests_body(response):
    """A `requests` response's body if it is at most `_MAX_NONCE_CHALLENGE_BODY` bytes, else None. Only
    that much is read from the stream, and what was read is put back, so the caller still gets the whole
    body."""
    raw = getattr(response, "raw", None)
    if getattr(response, "_content", False) is not False or raw is None:
        return _capped(response.content)  # already in memory
    head = b""
    complete = False
    error = None
    try:
        while len(head) <= _MAX_NONCE_CHALLENGE_BODY:
            chunk = raw.read(_MAX_NONCE_CHALLENGE_BODY + 1 - len(head), decode_content=True)
            if not chunk:
                complete = True
                break
            head += chunk
    except Exception as failure:  # noqa: BLE001 - a failed read: not a challenge
        error = failure  # raised to the caller once it has read what came before it
    if complete:
        response._content, response._content_consumed = head, True  # what `requests` does on a full read
        return head
    response.raw = _ReplayedRaw(raw, head, error)
    return None


class _ReplayedRaw:
    """A urllib3 response with its first bytes, already read (and decoded), put back in front. If reading
    them failed, the failure is raised once those bytes have been handed back, as the read would have."""

    def __init__(self, raw, head: bytes, error=None):
        self._raw = raw
        self._head = head
        self._error = error

    def _raise_pending(self):
        if self._error is not None:
            error, self._error = self._error, None
            raise error

    def read(self, amt=None, *args, **kwargs):
        if not self._head:
            self._raise_pending()
            return self._raw.read(amt, *args, **kwargs)
        if amt is None:
            self._raise_pending()  # a read of everything fails as a whole, as urllib3's own does
            head, self._head = self._head, b""
            return head + self._raw.read(None, *args, **kwargs)
        head, self._head = self._head[:amt], self._head[amt:]
        return head

    def stream(self, amt=2 ** 16, decode_content=None):
        if self._head:
            head, self._head = self._head, b""
            yield head
        self._raise_pending()
        yield from self._raw.stream(amt, decode_content=decode_content)

    def __getattr__(self, name):
        return getattr(self._raw, name)


def _httpx_body(response):
    """An `httpx` response's body if it is at most `_MAX_NONCE_CHALLENGE_BODY` bytes, else None. Only
    that much is read from a sync stream, and what was read is put back, so the caller still gets the
    whole body. An async stream is not read here (None)."""
    import httpx

    try:
        return _capped(response.content)  # already in memory
    except httpx.ResponseNotRead:
        pass
    stream = response.stream
    if not isinstance(stream, httpx.SyncByteStream):
        return None
    chunks = iter(stream)
    head = b""
    complete = False
    error = None
    try:
        while len(head) <= _MAX_NONCE_CHALLENGE_BODY:
            chunk = next(chunks, None)
            if chunk is None:
                complete = True
                break
            head += chunk
    except Exception as failure:  # noqa: BLE001 - a failed read: not a challenge
        error = failure  # raised to the caller after the bytes that came before it

    class _Replayed(httpx.SyncByteStream):
        def __iter__(self):
            if head:
                yield head
            if error is not None:
                raise error
            yield from chunks

        def close(self):
            stream.close()

    response.stream = _Replayed()
    if not complete:
        return None
    # The stream is the body as sent: decode a gzip or deflate one, at most the cap; any other coding
    # is not looked at.
    coding = (response.headers.get("Content-Encoding") or "identity").strip().lower()
    if coding == "identity":
        return _capped(head)
    if coding not in ("gzip", "x-gzip", "deflate"):
        return None
    try:
        decoder = zlib.decompressobj(32 + zlib.MAX_WBITS)  # a gzip or zlib header
        return _capped(decoder.decompress(head, _MAX_NONCE_CHALLENGE_BODY + 1))
    except zlib.error:
        return None


def _capped(body):
    return body if body is not None and len(body) <= _MAX_NONCE_CHALLENGE_BODY else None


def _log_http_failed(step, method: str, url: str, error: TransportError) -> None:
    _log.emit(_logger, logging.WARNING, "http.failed", step=step, method=method, host=_log.host(url),
              path=_log.path(url), status=error.status, reason=_log.failure_reason(error))


def _log_nonce_retry(url: str, status: int, at: str) -> None:
    _log.emit(_logger, logging.INFO, "dpop.nonce_retry", host=_log.host(url), status=status, at=at)


def _jwt_sub(compact_jwt: str) -> str:
    try:
        payload = compact_jwt.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        sub = claims.get("sub")
    except (IndexError, ValueError, TypeError, AttributeError):
        raise ClientAttestationError("minted attestation is not a decodable JWT") from None
    if not sub:
        raise ClientAttestationError("minted attestation has no sub (client id)")
    return sub
