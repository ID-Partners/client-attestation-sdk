"""One call to get an access token with client attestation.

Point it at a PingFederate host and call `.token()`. It runs the whole flow:

    discover -> get platform identity (evidence) -> get a challenge -> mint the attestation ->
    call the token endpoint with the attestation headers -> cache the access token

The workload sends no client secret and no client_id. Its only credential is the attestation, built
from the identity its runtime already gives it (auto-detected; see `evidence.py`).

    from client_attestation_sdk import ClientAttestation

    ca = ClientAttestation("pf.example.com")
    token = ca.token()                                   # access token, cached until it nears expiry

    import requests
    requests.get(api, auth=ca.requests_auth())           # attaches Authorization (and DPoP, if bound)

    # or hand the headers to anything (httpx, fetch, an ADK header_provider):
    headers = ca.request_headers("GET", api)
"""
from __future__ import annotations

import base64
import json
import re
import shlex
import threading
import time
import urllib.parse
import uuid

from . import _http
from .builders import DpopProofBuilder, PopBuilder, url_origin as _origin
from .errors import ClientAttestationError, TransportError  # noqa: F401 - re-exported
from .evidence import auto_detect_evidence
from .keys import SigningKeyPair, sign_compact
from .svid_source import SvidSource

ATTESTATION_HEADER = "OAuth-Client-Attestation"
POP_HEADER = "OAuth-Client-Attestation-PoP"
DPOP_HEADER = "DPoP"
INSTANCE_PROOF_TYP = "oauth-attestation-instance-proof+jwt"
WELL_KNOWN_PATH = "/.well-known/client-attester"
# Refresh this many seconds before the token actually expires, so a token is never used at the edge.
DEFAULT_EXPIRY_SKEW_SECONDS = 30
DPOP_NONCE_HEADER = "DPoP-Nonce"
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

# Trace redaction (see `trace_redact`): header names and JSON/form members whose values are credentials.
_SECRET_HEADERS = frozenset(h.lower() for h in ("Authorization", DPOP_HEADER, ATTESTATION_HEADER, POP_HEADER))
_SECRET_FIELDS = frozenset({"svid", "proof", "assertion", "client_assertion", "subject_token", "actor_token",
                            "client_secret", "attestation", "access_token", "refresh_token", "id_token"})
_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "k", "oth"})


class ClientAttestation:
    """Gets and caches an access token from a PingFederate host using client attestation.

    Args:
        pf_host: the PingFederate host — `"pf.example.com"`, or a full base URL
            `"https://pf.example.com"`. Plain hostnames default to https.
        evidence: how to get the workload's platform identity. Leave as None to auto-detect the
            runtime (env token, projected token file, SPIRE socket, or GCP metadata). Pass an
            `SvidSource` to override.
        authorization_details: optional RFC 9396 access request sent at mint time; the attester grants
            at most what the workload is entitled to.
        algorithm: instance-key signature algorithm (default ES256).
        expiry_skew_seconds: refresh this long before the token expires.
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
            private JWK members) of a request body, and the `value` and `jwt` keys. `False` records
            them verbatim — for local debugging only; a trace kept that way holds live credentials.
        require_challenge: when the discovery document advertises a `challenge_endpoint` and the
            challenge cannot be fetched (network, HTTP status, bad JSON, no `attestation_challenge`),
            fail with `ClientAttestationError` (default `True`). `False` keeps the old behaviour of
            minting without a challenge. No advertised endpoint means no challenge and no error.
        allow_insecure: allow plain-http `pf_host` and discovery endpoints for non-loopback hosts
            (default `False`). Loopback (`localhost`, `127.0.0.1`, `::1`) is always allowed.
    """

    def __init__(self, pf_host: str, *, evidence: SvidSource = None, authorization_details: list = None,
                 operator: dict = None,
                 algorithm: str = "ES256", expiry_skew_seconds: int = DEFAULT_EXPIRY_SKEW_SECONDS,
                 timeout: float = 20.0, pop_method: str = "attestation_pop_jwt",
                 challenge_at_token: bool = True,
                 trace: list = None, trace_redact: bool = True,
                 require_challenge: bool = True, allow_insecure: bool = False):
        self.base_url = _normalize_base_url(pf_host)
        self._allow_insecure = allow_insecure
        _require_https(self.base_url, "pf_host", allow_insecure)
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
        self._expires_at = 0.0
        self._discovery = None
        self._nonce_lock = threading.Lock()
        self._dpop_nonces = {}   # origin -> last DPoP-Nonce that origin returned

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
            if asserted_context is None and not force_refresh \
                    and self._cached_token and time.time() < self._expires_at:
                return self._cached_token, self._token_type, self._token_key
            response, instance_key = self._run_flow(asserted_context=asserted_context)
            access_token = response["access_token"]
            token_type = _token_type(response)
            if asserted_context is None:
                self._cached_token = access_token
                self._token_type = token_type
                self._token_key = instance_key
                expires_in = response.get("expires_in")
                self._expires_at = time.time() + (float(expires_in) - self._skew) if expires_in else 0.0
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
        """
        access_token, token_type, instance_key = self._token_state()
        if token_type != "DPoP":
            return {"Authorization": f"{token_type} {access_token}"}
        proof = (DpopProofBuilder(instance_key).method(method).uri(url).access_token(access_token)
                 .nonce(self._nonce_for(url)).build())
        return {"Authorization": "DPoP " + access_token, DPOP_HEADER: proof}

    def requests_auth(self):
        """A `requests` auth object that attaches the token (and refreshes it) on every call.

        For a DPoP-bound token it also attaches a fresh proof, and when the resource answers with a
        DPoP nonce challenge (`use_dpop_nonce` plus a `DPoP-Nonce` header) it remembers the nonce and
        re-sends the request once with a proof carrying it. A request whose body cannot be replayed
        (a stream or generator) is not re-sent."""
        source = self

        class _Auth:
            def __call__(self, request):
                headers = source.request_headers(request.method, request.url)
                request.headers.update(headers)
                if DPOP_HEADER in headers:
                    request.register_hook("response", self._on_response)
                return request

            def _on_response(self, response, **kwargs):
                nonce = source._observe_response(response.request.url, response.status_code,
                                                 response.headers, lambda: response.content)
                if nonce is None or not _replayable(response.request.body):
                    return response
                retry = response.request.copy()
                retry.hooks = {"response": []}
                retry.headers.update(source.request_headers(retry.method, retry.url))
                response.content  # drain, so the connection can be reused  # noqa: B018
                response.close()
                second = response.connection.send(retry, **kwargs)
                second.history.append(response)
                second.request = retry
                return second

        return _Auth()

    def httpx_auth(self):
        """An `httpx.Auth` that attaches the token (and refreshes it) on every call. For a DPoP-bound
        token it behaves as :meth:`requests_auth` does: fresh proof per request, one re-send on a DPoP
        nonce challenge (only when the request body is in memory)."""
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
                nonce = source._observe_response(url, response.status_code, response.headers,
                                                 lambda: _httpx_body(response))
                if nonce is None or not isinstance(request.stream, httpx.ByteStream):
                    return
                request.headers.update(source.request_headers(request.method, url))
                yield request

        return _Auth()

    # ── DPoP nonces (RFC 9449 section 8/9) ──────────────────────────────────────────────────────
    def _nonce_for(self, url: str):
        with self._nonce_lock:
            return self._dpop_nonces.get(_origin(url))

    def _remember_nonce(self, url: str, nonce: str) -> None:
        with self._nonce_lock:
            self._dpop_nonces[_origin(url)] = nonce

    def _observe_response(self, url: str, status: int, headers, body) -> "str | None":
        """Remember any `DPoP-Nonce` the response carries; return it when the response is a nonce
        challenge (a request worth re-sending with a proof that carries it), else None."""
        nonce = headers.get(DPOP_NONCE_HEADER)
        if not nonce:
            return None
        self._remember_nonce(url, nonce)
        return nonce if _is_nonce_challenge(status, headers, body) else None

    def discovery(self) -> dict:
        """The attester's `/.well-known/client-attester` document (fetched once, then cached)."""
        if self._discovery is None:
            self._discovery = self._get_json("GET", self.base_url + WELL_KNOWN_PATH, step="discover")
        return self._discovery

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
        doc = self.discovery()
        audience = doc.get("evidence_audience")
        if not audience:
            raise ClientAttestationError("attester discovery document has no evidence_audience")

        evidence_source = self._evidence or auto_detect_evidence()
        svid = evidence_source.fetch(audience)

        instance_key = SigningKeyPair.generate(self._algorithm)
        challenge = self._fetch_challenge(doc)
        attestation = self._mint(doc, instance_key, svid, challenge, asserted_context=asserted_context)

        # token_endpoint is advertised by current attesters; fall back to the standard PF path so an
        # older discovery document still works from the host alone.
        token_endpoint = doc.get("token_endpoint") or (self.base_url + "/as/token.oauth2")
        _require_https(token_endpoint, "token_endpoint", self._allow_insecure)
        client_id = _jwt_sub(attestation)
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
            pop_audience = doc.get("pop_audience") or token_endpoint
            proof = (PopBuilder(instance_key).client_id(client_id).audience(pop_audience)
                     .challenge(token_challenge).build())
            proof_header = POP_HEADER
            retry_proof = None

        response = self._call_token_endpoint(token_endpoint, attestation, proof, proof_header,
                                             operator=self._operator, retry_proof=retry_proof)
        return response, instance_key

    def _fetch_challenge(self, doc: dict):
        endpoint = doc.get("challenge_endpoint")
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
                return None
            # The attester advertises a challenge, so it is part of the anti-replay contract; minting
            # without one would silently weaken it. Fail closed.
            raise ClientAttestationError(f"could not get an attestation challenge from {endpoint}: {error}",
                                         status=error.status, body=error.body) from error
        self._annotate("value", value)
        return value

    def _mint(self, doc: dict, instance_key: SigningKeyPair, svid: str, challenge,
              *, asserted_context: dict = None) -> str:
        now = int(time.time())
        proof_claims = {"aud": doc["evidence_audience"], "jti": str(uuid.uuid4()), "iat": now}
        if challenge:
            proof_claims["challenge"] = challenge
        proof = sign_compact(proof_claims, instance_key, INSTANCE_PROOF_TYP, embed_jwk=False)

        # Evidence-first: no client_id. The attester maps the identity to a client.
        body = {"instance_key": instance_key.public_jwk(), "svid": svid, "proof": proof}
        if self._authorization_details:
            body["authorization_details"] = self._authorization_details
        if asserted_context:
            body["asserted_context"] = asserted_context
        if self._operator:
            # The client's OPERATOR — who answers for this workload — asked for at mint time so the
            # ATTESTER is what states it, rather than the client asserting it about itself at the
            # token endpoint. An attester that does not know this key ignores it; one that does can
            # refuse to name an operator it cannot corroborate.
            body["operator"] = self._operator
        endpoint = _http.require(doc, "attestation_endpoint", "attester discovery document")
        _require_https(endpoint, "attestation_endpoint", self._allow_insecure)
        response = self._get_json("POST", endpoint, json_body=body, step="mint")
        attestation = response.get("attestation")
        if not attestation:
            raise ClientAttestationError("attester response contained no attestation", body=json.dumps(response))
        self._annotate("jwt", attestation)
        return attestation

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
        response = _http.request("POST", endpoint, headers=headers, body=form, timeout=self._timeout)
        if retry_proof is not None:
            # RFC 9449 section 8: the AS may demand its own nonce. Retry once with a proof carrying it.
            nonce = self._observe_response(endpoint, response.status, response.headers, response.body)
            if nonce is not None:
                headers[proof_header] = retry_proof(nonce)
                self._record("token", "POST", endpoint, headers, form=params)
                response = _http.request("POST", endpoint, headers=headers, body=form, timeout=self._timeout)
        parsed = _http.json_ok(response, "token endpoint")
        if "access_token" not in parsed:
            raise ClientAttestationError("token endpoint returned no access_token", body=json.dumps(parsed))
        self._annotate("jwt", parsed["access_token"])
        return parsed

    def _get_json(self, method: str, url: str, *, json_body: dict = None, step: str = None) -> dict:
        data = json.dumps(json_body).encode("utf-8") if json_body is not None else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if step:
            self._record(step, method, url, headers, json_body=json_body)
        response = _http.request(method, url, headers=headers, body=data, timeout=self._timeout)
        return _http.json_ok(response, f"{method} {url}", allow_empty=True)


def _normalize_base_url(pf_host: str) -> str:
    host = pf_host.strip().rstrip("/")
    if not host:
        raise ValueError("pf_host is required")
    if "://" not in host:
        host = "https://" + host
    return host


def _require_https(url: str, what: str, allow_insecure: bool) -> None:
    """Credentials travel on every call, so endpoints must be https — except loopback (local fakes and
    sidecars) or when the caller explicitly passed `allow_insecure=True`."""
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme == "https" or allow_insecure:
        return
    if scheme == "http" and (parts.hostname or "").lower() in _LOOPBACK_HOSTS:
        return
    raise ClientAttestationError(
        f"{what} must use https: {url} (plain http is allowed only for loopback hosts, "
        "or pass allow_insecure=True)")


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


def _replayable(body) -> bool:
    return body is None or isinstance(body, (bytes, bytearray, str))


def _httpx_body(response):
    try:
        return response.read()
    except Exception:  # noqa: BLE001 - an async or already-closed stream: treat as no body
        return None


def _redacted(value) -> str:
    raw = value if isinstance(value, str) else json.dumps(value)
    return f"<redacted:{len(raw.encode('utf-8'))} bytes>"


def _redact_json(value):
    """A copy of a request body with credential members (and private JWK members) redacted."""
    if isinstance(value, list):
        return [_redact_json(item) for item in value]
    if not isinstance(value, dict):
        return value
    is_jwk = "kty" in value
    return {key: _redacted(item) if key in _SECRET_FIELDS or (is_jwk and key in _PRIVATE_JWK_MEMBERS)
            else _redact_json(item) for key, item in value.items()}


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
