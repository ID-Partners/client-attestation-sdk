"""CibaClient against a fake AS: request shape, client auth, and — above all — the poll throttle.
The throttle is the property that keeps a PingFederate grant alive; every port must reproduce it."""
import json

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from client_attestation_sdk.authz_challenge import (
    APPROVED, AUDIENCE_ENDPOINT, AUDIENCE_ISSUER, DENIED, EXPIRED, PENDING,
    CibaClient, CibaError, CibaRequest, PrivateKeyJwtAuth, private_key_jwt_assertion,
)

BC = "https://pf.example/as/bc-auth.ciba"
TOK = "https://pf.example/as/token.oauth2"
ISS = "https://localhost:9031"


def _pem():
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode(), key.public_key()


class FakeClock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


class FakeAS:
    """Scripted token-endpoint answers; records every call."""

    def __init__(self, bc_body=None):
        self.calls = []
        self.bc_body = bc_body if bc_body is not None else {"auth_req_id": "req-1", "interval": 3, "expires_in": 120}
        self.token_answers = []      # list of (status, body-dict) popped per token call

    def __call__(self, method, url, form, headers):
        self.calls.append((method, url, dict(form), dict(headers)))
        if url == BC:
            return 200, json.dumps(self.bc_body)
        if url == TOK:
            if self.token_answers:
                status, body = self.token_answers.pop(0)
            else:
                status, body = 400, {"error": "authorization_pending"}
            return status, json.dumps(body)
        return 404, "{}"

    @property
    def token_calls(self):
        return [c for c in self.calls if c[1] == TOK]


def _client(fake, clock, pem, *, signed=True):
    return CibaClient(bc_auth_endpoint=BC, token_endpoint=TOK, client_id="urn:agent:x",
                      client_auth=PrivateKeyJwtAuth(client_id="urn:agent:x", private_key_pem=pem, kid="k1",
                                                    extra_audiences=(ISS + "/as/token.oauth2", ISS)),
                      issuer=ISS, request_signing_key_pem=pem if signed else None,
                      request_signing_kid="k1" if signed else None, http=fake, clock=clock)


def test_private_key_jwt_assertion_carries_audience_array():
    pem, pub = _pem()
    a = private_key_jwt_assertion(client_id="c", endpoint=BC, private_key_pem=pem, kid="k1",
                                  extra_audiences=(ISS + "/as/token.oauth2", ISS))
    claims = jwt.decode(a, pub, algorithms=["ES256"], audience=BC)
    assert claims["aud"] == [BC, ISS + "/as/token.oauth2", ISS]     # endpoint first, then the AS's internal ids
    assert claims["iss"] == claims["sub"] == "c"
    assert jwt.get_unverified_header(a)["kid"] == "k1"
    # No extras -> plain string aud (RFC 7523 allows either)
    b = private_key_jwt_assertion(client_id="c", endpoint=BC, private_key_pem=pem, kid="k1")
    assert jwt.decode(b, pub, algorithms=["ES256"], audience=BC)["aud"] == BC


def test_request_signed_request_object_and_client_assertion():
    pem, pub = _pem()
    fake, clock = FakeAS(), FakeClock()
    c = _client(fake, clock, pem)
    req = c.request(login_hint="alice", binding_message="PAY-abc123", scope="openid")
    assert isinstance(req, CibaRequest)
    assert (req.auth_req_id, req.interval, req.expires_in) == ("req-1", 3, 120)
    assert req.requested_at == clock.t
    method, url, form, _ = fake.calls[0]
    assert (method, url) == ("POST", BC)
    assert form["client_assertion_type"].endswith("jwt-bearer")
    # the request object is stamped with the FAKE clock (1970), so don't let pyjwt judge exp/iat
    ro = jwt.decode(form["request"], pub, algorithms=["ES256"], audience=ISS,
                    options={"verify_exp": False, "verify_iat": False, "verify_nbf": False})
    assert ro["iat"] == int(clock.t) and ro["exp"] == int(clock.t) + 300
    assert ro["login_hint"] == "alice" and ro["binding_message"] == "PAY-abc123" and ro["scope"] == "openid"
    assert ro["iss"] == "urn:agent:x"
    assert "login_hint" not in form            # signed: params ride INSIDE the request object


def test_request_flat_when_no_signing_key_and_rar_is_always_flat():
    pem, _ = _pem()
    fake, clock = FakeAS(), FakeClock()
    c = _client(fake, clock, pem, signed=False)
    c.request(login_hint="alice", authorization_details=[{"type": "payment_initiation", "amount": 9000}])
    form = fake.calls[0][2]
    assert form["login_hint"] == "alice" and "request" not in form
    assert json.loads(form["authorization_details"])[0]["type"] == "payment_initiation"


def test_request_errors():
    pem, _ = _pem()
    fake, clock = FakeAS(), FakeClock()
    fake.bc_body = {"error": "invalid_client"}
    c = _client(fake, clock, pem)

    def _http_400(m, u, f, h):
        return 400, json.dumps({"error": "invalid_client"})
    c.http = _http_400
    with pytest.raises(CibaError) as ei:
        c.request(login_hint="alice")
    assert ei.value.status == 400 and "invalid_client" in str(ei.value)

    fake2 = FakeAS(bc_body={"interval": 5})       # no auth_req_id
    c2 = _client(fake2, clock, pem)
    with pytest.raises(CibaError):
        c2.request(login_hint="alice")


def test_poll_is_throttled_to_the_interval():
    """The whole point. A caller polling every 1s must produce ONE token call per interval."""
    pem, _ = _pem()
    fake, clock = FakeAS(), FakeClock()
    c = _client(fake, clock, pem)
    req = c.request(login_hint="alice")
    assert req.interval == 3
    # t=0: first poll -> real call
    assert c.poll(req) == PENDING
    assert len(fake.token_calls) == 1
    # hammer it inside the interval: cached, no calls
    for dt in (0.5, 1.0, 1.5, 2.0, 2.5, 3.0):
        clock.t = req.requested_at + dt
        assert c.poll(req) == PENDING
    assert len(fake.token_calls) == 1
    # just past interval + 0.5 grace -> one more real call
    clock.t = req.requested_at + 3.6
    assert c.poll(req) == PENDING
    assert len(fake.token_calls) == 2
    # the token call is well-formed
    form = fake.token_calls[0][2]
    assert form["grant_type"] == "urn:openid:params:grant-type:ciba" and form["auth_req_id"] == "req-1"
    assert "client_assertion" in form


def test_slow_down_backs_off_five_seconds():
    pem, _ = _pem()
    fake, clock = FakeAS(), FakeClock()
    c = _client(fake, clock, pem)
    req = c.request(login_hint="alice")
    fake.token_answers = [(400, {"error": "slow_down"})]
    assert c.poll(req) == PENDING
    assert req.interval == 8                    # 3 + 5 (CIBA Core §11)
    clock.t += 3.6                              # would have been due under the OLD interval
    assert c.poll(req) == PENDING and len(fake.token_calls) == 1     # ...but not under the new one
    clock.t += 5.0
    assert c.poll(req) == PENDING and len(fake.token_calls) == 2


def test_pf_interval_violation_warning_backs_off_hard():
    pem, _ = _pem()
    fake, clock = FakeAS(), FakeClock()
    c = _client(fake, clock, pem)
    req = c.request(login_hint="alice")
    fake.token_answers = [(400, {"error": "invalid_request",
                                 "error_description": "please respect the 3 second polling interval"})]
    assert c.poll(req) == PENDING
    assert req.interval == 8 and "polling interval" in req.last_error


def test_terminal_outcomes_and_caching():
    pem, _ = _pem()
    for answer, expect in [((200, {"access_token": "at.jwt", "token_type": "Bearer"}), APPROVED),
                           ((400, {"error": "access_denied"}), DENIED),
                           ((400, {"error": "expired_token"}), EXPIRED),
                           ((400, {"error": "invalid_grant"}), EXPIRED)]:   # PF after killing the grant
        fake, clock = FakeAS(), FakeClock()
        c = _client(fake, clock, pem)
        req = c.request(login_hint="alice")
        fake.token_answers = [answer]
        assert c.poll(req) == expect
        # terminal is sticky and costs no more calls, however long you keep polling
        clock.t += 100
        assert c.poll(req) == expect
        assert len(fake.token_calls) == 1
        if expect == APPROVED:
            assert req.access_token == "at.jwt"


def test_client_clock_expiry_without_asking_the_as():
    pem, _ = _pem()
    fake, clock = FakeAS(), FakeClock()
    c = _client(fake, clock, pem)
    req = c.request(login_hint="alice")          # expires_in 120
    assert c.poll(req) == PENDING
    clock.t = req.requested_at + 121
    assert c.poll(req) == EXPIRED
    assert len(fake.token_calls) == 1


def test_transport_failure_is_not_a_verdict():
    pem, _ = _pem()
    fake, clock = FakeAS(), FakeClock()
    c = _client(fake, clock, pem)
    req = c.request(login_hint="alice")

    def boom(*a):
        raise OSError("connection reset")
    c.http = boom
    assert c.poll(req) == PENDING and "transport" in req.last_error


def test_rehydrate_seeds_the_throttle():
    """A rebuilt request must NOT poll immediately — its throttle state was lost with the process."""
    pem, _ = _pem()
    fake, clock = FakeAS(), FakeClock()
    c = _client(fake, clock, pem)
    req = c.request(login_hint="alice")
    d = req.to_dict()
    # rehydrate uses time.time() for last_poll_at (real clock) — emulate by patching after
    r2 = CibaRequest.rehydrate(d)
    r2.last_poll_at = clock.t                    # what rehydrate did, in fake-clock terms
    assert (r2.auth_req_id, r2.interval, r2.expires_in) == ("req-1", 3, 120)
    assert c.poll(r2) == PENDING and len(fake.token_calls) == 0        # throttled: no call yet
    clock.t += 3.6
    assert c.poll(r2) == PENDING and len(fake.token_calls) == 1


@pytest.mark.parametrize("text", ["", "<html>signed in</html>", "null", "[]", '"ok"', "{}",
                                  '{"token_type": "Bearer"}', '{"access_token": ""}',
                                  '{"access_token": 7}', '{"access_token": null}'])
def test_a_200_that_is_not_a_token_response_is_not_an_approval(text):
    pem, _ = _pem()
    fake, clock = FakeAS(), FakeClock()
    c = _client(fake, clock, pem)
    req = c.request(login_hint="alice")

    def http(method, url, form, headers):
        fake.calls.append((method, url, dict(form), dict(headers)))
        return 200, text
    c.http = http
    assert c.poll(req) == PENDING
    assert req.access_token is None and req.token_response is None
    assert "not a token response" in req.last_error
    # still pending, so the next due poll asks the AS again (here: it has killed the grant)
    c.http = fake
    fake.token_answers = [(400, {"error": "invalid_grant"})]
    clock.t += 3.6
    assert c.poll(req) == EXPIRED


@pytest.mark.parametrize("signed", [True, False])
@pytest.mark.parametrize("key", ["iss", "aud", "exp", "iat", "nbf", "jti", "scope", "login_hint",
                                 "binding_message"])
def test_extra_may_not_override_reserved_request_parameters(key, signed):
    pem, _ = _pem()
    fake, clock = FakeAS(), FakeClock()
    c = _client(fake, clock, pem, signed=signed)
    with pytest.raises(ValueError, match=key):
        c.request(login_hint="alice", binding_message="PAY-abc123", extra={key: "attacker", "acr_values": "x"})
    assert fake.calls == []                     # refused before anything is signed or sent


def test_extra_adds_unreserved_parameters_to_the_signed_request_object():
    pem, pub = _pem()
    fake, clock = FakeAS(), FakeClock()
    c = _client(fake, clock, pem)
    c.request(login_hint="alice", extra={"requested_expiry": 120, "acr_values": "urn:x"})
    ro = jwt.decode(fake.calls[0][2]["request"], pub, algorithms=["ES256"], audience=ISS,
                    options={"verify_exp": False, "verify_iat": False, "verify_nbf": False})
    assert ro["requested_expiry"] == 120 and ro["acr_values"] == "urn:x"
    assert ro["iss"] == "urn:agent:x" and ro["aud"] == ISS and ro["exp"] == int(clock.t) + 300


@pytest.mark.parametrize("text", ['["access_denied"]', '"access_denied"', "null", "42", "<html>bad gateway</html>"])
def test_a_non_200_whose_body_is_not_a_json_object_is_read_as_unparseable(text):
    pem, _ = _pem()
    fake, clock = FakeAS(), FakeClock()
    c = _client(fake, clock, pem)
    req = c.request(login_hint="alice")
    c.http = lambda method, url, form, headers: (502, text)
    assert c.poll(req) == PENDING                # no verdict, and no AttributeError
    assert req.last_error == f"502 {text[:80]}" and req.interval == 3


# ---- bc-auth timing is bounded; JSON parsing cannot raise; endpoints must be https ---------------
@pytest.mark.parametrize("raw, interval, expires_in", [
    ('{"auth_req_id":"r","interval":1e400,"expires_in":1e400}', 3, 120),     # infinity: OverflowError
    ('{"auth_req_id":"r","interval":-1e400,"expires_in":-5}', 3, 120),
    ('{"auth_req_id":"r","interval":1e300,"expires_in":1e300}', 600, 3600),  # finite but absurd: capped
    ('{"auth_req_id":"r"}', 3, 120),                                         # expires_in omitted
    ('{"auth_req_id":"r","interval":"x","expires_in":0}', 3, 120),
], ids=["infinite", "negative", "absurd", "missing", "unreadable"])
def test_bc_auth_timing_is_bounded(raw, interval, expires_in):
    pem, _ = _pem()
    clock = FakeClock()
    c = CibaClient(bc_auth_endpoint=BC, token_endpoint=TOK, client_id="c", issuer=ISS,
                   client_auth=PrivateKeyJwtAuth(client_id="c", private_key_pem=pem, kid="k"),
                   http=lambda m, u, f, h: (200, raw), clock=clock)
    req = c.request(login_hint="alice")
    assert (req.interval, req.expires_in) == (interval, expires_in)
    clock.advance(expires_in)
    assert req.expired_by_clock(clock())         # the request always ends on the client's clock


def test_rehydrate_bounds_timing_too():
    r = CibaRequest.rehydrate({"auth_req_id": "r", "interval": float("inf"), "expires_in": 0})
    assert (r.interval, r.expires_in) == (3, 120)


@pytest.mark.parametrize("body", ["[" * 200_000, '{"error":' * 100_000], ids=["deep", "deep_object"])
def test_unreadable_as_json_is_not_an_exception(body):
    pem, _ = _pem()
    clock = FakeClock()
    answers = {BC: (200, body), TOK: (400, body)}
    c = CibaClient(bc_auth_endpoint=BC, token_endpoint=TOK, client_id="c", issuer=ISS,
                   client_auth=PrivateKeyJwtAuth(client_id="c", private_key_pem=pem, kid="k"),
                   http=lambda m, u, f, h: answers[u], clock=clock)
    with pytest.raises(CibaError):
        c.request(login_hint="alice")
    req = CibaRequest(auth_req_id="r", interval=3, expires_in=120, requested_at=clock())
    clock.advance(5)
    assert c.poll(req) == PENDING
    answers[TOK] = (200, body)
    clock.advance(5)
    assert c.poll(req) == PENDING and "not a token response" in req.last_error


@pytest.mark.parametrize("bc, tok", [("http://pf.example/as/bc-auth.ciba", TOK),
                                     (BC, "http://pf.example/as/token.oauth2")])
def test_endpoints_must_be_https(bc, tok):
    from client_attestation_sdk.errors import ClientAttestationError
    pem, _ = _pem()
    auth = PrivateKeyJwtAuth(client_id="c", private_key_pem=pem, kid="k")
    with pytest.raises(ClientAttestationError, match="must use https"):
        CibaClient(bc_auth_endpoint=bc, token_endpoint=tok, client_id="c", issuer=ISS, client_auth=auth)
    CibaClient(bc_auth_endpoint=bc, token_endpoint=tok, client_id="c", issuer=ISS, client_auth=auth,
               allow_insecure=True)
    CibaClient(bc_auth_endpoint="http://127.0.0.1:9031/bc", token_endpoint="http://localhost/tok",
               client_id="c", issuer=ISS, client_auth=auth)       # loopback is exempt


def test_client_assertion_aud_is_the_issuer_as_one_string():
    """CIBA Core §7.1 and the 2025 private_key_jwt audience-confusion guidance: one audience, the AS's issuer."""
    pem, pub = _pem()
    fake, clock = FakeAS(), FakeClock()
    auth = PrivateKeyJwtAuth(client_id="urn:agent:x", private_key_pem=pem, kid="k1")
    c = CibaClient(bc_auth_endpoint=BC, token_endpoint=TOK, client_id="urn:agent:x", issuer=ISS,
                   client_auth=auth, http=fake, clock=clock)
    req = c.request(login_hint="alice")
    clock.advance(5)
    c.poll(req)
    for _, url, form, _ in fake.calls:
        assertion = form["client_assertion"]
        assert jwt.decode(assertion, pub, algorithms=["ES256"], audience=ISS)["aud"] == ISS, url
    assert auth.issuer is None and c.client_auth is auth     # the caller's object: not changed, not copied
    # A PrivateKeyJwtAuth with its own issuer keeps it.
    own = PrivateKeyJwtAuth(client_id="c", private_key_pem=pem, kid="k1", issuer="https://other.example")
    c2 = CibaClient(bc_auth_endpoint=BC, token_endpoint=TOK, client_id="c", issuer=ISS, client_auth=own,
                    http=fake, clock=clock)
    assert c2.client_auth is own
    c2.request(login_hint="alice")
    assert jwt.decode(fake.calls[-1][2]["client_assertion"], pub, algorithms=["ES256"],
                      audience="https://other.example")["aud"] == "https://other.example"
    # On its own, with an issuer: one string too.
    a = private_key_jwt_assertion(client_id="c", endpoint=BC, private_key_pem=pem, kid="k1", issuer=ISS)
    assert jwt.decode(a, pub, algorithms=["ES256"], audience=ISS)["aud"] == ISS


def test_extra_audiences_are_an_explicit_opt_in_array():
    pem, pub = _pem()
    a = private_key_jwt_assertion(client_id="c", endpoint=BC, private_key_pem=pem, kid="k1", issuer=ISS,
                                  extra_audiences=(ISS + "/as/token.oauth2", ISS, ""))
    # the issuer first, the endpoint called (what was sent before), then the extras, without repeats
    assert jwt.decode(a, pub, algorithms=["ES256"], audience=ISS)["aud"] == [ISS, BC, ISS + "/as/token.oauth2"]


@pytest.mark.parametrize("extras", [("",), ("", ""), ()])
def test_empty_extra_audiences_leave_one_string(extras):
    pem, pub = _pem()
    a = private_key_jwt_assertion(client_id="c", endpoint=BC, private_key_pem=pem, kid="k1", issuer=ISS,
                                  extra_audiences=extras)
    assert jwt.decode(a, pub, algorithms=["ES256"], audience=ISS)["aud"] == ISS
    auth = PrivateKeyJwtAuth(client_id="c", private_key_pem=pem, kid="k1", extra_audiences=extras)
    form = {}
    auth.apply(TOK, form, issuer=ISS)
    assert jwt.decode(form["client_assertion"], pub, algorithms=["ES256"], audience=ISS)["aud"] == ISS


def test_audience_mode_endpoint_sends_the_endpoint_called_as_one_string():
    """The explicit way back to what CibaClient sent before it used the issuer: each call's own URL."""
    pem, pub = _pem()
    fake, clock = FakeAS(), FakeClock()
    auth = PrivateKeyJwtAuth(client_id="c", private_key_pem=pem, kid="k1", audience_mode=AUDIENCE_ENDPOINT)
    c = CibaClient(bc_auth_endpoint=BC, token_endpoint=TOK, client_id="c", issuer=ISS, client_auth=auth,
                   http=fake, clock=clock)
    req = c.request(login_hint="alice")
    clock.advance(5)
    c.poll(req)
    assert [u for _, u, _, _ in fake.calls] == [BC, TOK]
    for _, url, form, _ in fake.calls:
        assert jwt.decode(form["client_assertion"], pub, algorithms=["ES256"], audience=url)["aud"] == url
    # an issuer of its own does not change that; on its own, the function does the same
    own = PrivateKeyJwtAuth(client_id="c", private_key_pem=pem, kid="k1", issuer=ISS,
                            audience_mode=AUDIENCE_ENDPOINT)
    form = {}
    own.apply(TOK, form, issuer=ISS)
    assert jwt.decode(form["client_assertion"], pub, algorithms=["ES256"], audience=TOK)["aud"] == TOK
    a = private_key_jwt_assertion(client_id="c", endpoint=TOK, private_key_pem=pem, kid="k1", issuer=ISS,
                                  audience_mode=AUDIENCE_ENDPOINT)
    assert jwt.decode(a, pub, algorithms=["ES256"], audience=TOK)["aud"] == TOK
    # with extras: the endpoint first, then the extras
    a = private_key_jwt_assertion(client_id="c", endpoint=TOK, private_key_pem=pem, kid="k1",
                                  audience_mode=AUDIENCE_ENDPOINT, extra_audiences=(ISS,))
    assert jwt.decode(a, pub, algorithms=["ES256"], audience=TOK)["aud"] == [TOK, ISS]
    assert PrivateKeyJwtAuth(client_id="c", private_key_pem=pem, kid="k1").audience_mode == AUDIENCE_ISSUER


def test_audience_arguments_are_checked():
    pem, _ = _pem()
    with pytest.raises(ValueError, match="audience_mode"):
        PrivateKeyJwtAuth(client_id="c", private_key_pem=pem, kid="k1", audience_mode="token_endpoint")
    with pytest.raises(ValueError, match="issuer"):         # not a silent route to the endpoint audience
        PrivateKeyJwtAuth(client_id="c", private_key_pem=pem, kid="k1", issuer="")
    with pytest.raises(ValueError, match="issuer"):
        private_key_jwt_assertion(client_id="c", endpoint=BC, private_key_pem=pem, kid="k1", issuer="")
    with pytest.raises(ValueError, match="audience_mode"):
        private_key_jwt_assertion(client_id="c", endpoint=BC, private_key_pem=pem, kid="k1", audience_mode="")


def test_client_auth_is_read_at_each_call_not_copied():
    """CibaClient passes its issuer at apply time: a later change to the caller's PrivateKeyJwtAuth (a
    rotated key and kid) applies to the next assertion."""
    pem, _ = _pem()
    pem2, pub2 = _pem()
    fake, clock = FakeAS(), FakeClock()
    auth = PrivateKeyJwtAuth(client_id="c", private_key_pem=pem, kid="k1")
    c = CibaClient(bc_auth_endpoint=BC, token_endpoint=TOK, client_id="c", issuer=ISS, client_auth=auth,
                   http=fake, clock=clock)
    auth.private_key_pem, auth.kid = pem2, "k2"
    c.request(login_hint="alice")
    assertion = fake.calls[-1][2]["client_assertion"]
    assert jwt.get_unverified_header(assertion)["kid"] == "k2"
    assert jwt.decode(assertion, pub2, algorithms=["ES256"], audience=ISS)["aud"] == ISS


def test_a_custom_client_auth_gets_the_issuer_when_it_takes_it():
    fake, clock = FakeAS(), FakeClock()
    seen = []

    class WithIssuer:
        def apply(self, endpoint, form, *, issuer=None):
            seen.append(("kw", endpoint, issuer))

    class WithKwargs:
        def apply(self, endpoint, form, **kw):
            seen.append(("kwargs", endpoint, kw.get("issuer")))

    class Legacy:                                  # the original two-argument signature still works
        def apply(self, endpoint, form):
            seen.append(("legacy", endpoint, None))

    for auth in (WithIssuer(), WithKwargs(), Legacy()):
        c = CibaClient(bc_auth_endpoint=BC, token_endpoint=TOK, client_id="c", issuer=ISS, client_auth=auth,
                       http=fake, clock=clock)
        req = c.request(login_hint="alice")
        clock.advance(5)
        c.poll(req)
    assert seen == [("kw", BC, ISS), ("kw", TOK, ISS), ("kwargs", BC, ISS), ("kwargs", TOK, ISS),
                    ("legacy", BC, None), ("legacy", TOK, None)]


class _GatedHttp:
    """Token calls for the auth_req_ids in ``hold`` block until ``release`` is set."""

    def __init__(self, hold):
        import threading
        self.hold, self.calls = set(hold), []
        self.entered, self.release = threading.Event(), threading.Event()

    def __call__(self, method, url, form, headers):
        self.calls.append(form.get("auth_req_id"))
        if url == TOK and form.get("auth_req_id") in self.hold:
            self.entered.set()
            assert self.release.wait(10)
        return 400, json.dumps({"error": "authorization_pending"})


def _poll_in_thread(c, req):
    import threading
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("outcome", c.poll(req)), daemon=True)
    t.start()
    return t, out


def test_a_slow_as_call_does_not_hold_up_other_requests():
    """The poll lock is not held across the network call: one ceremony's slow token call must not
    serialise every other ceremony's poll behind it."""
    pem, _ = _pem()
    clock = FakeClock()
    http = _GatedHttp(hold={"slow"})
    c = CibaClient(bc_auth_endpoint=BC, token_endpoint=TOK, client_id="c", issuer=ISS,
                   client_auth=PrivateKeyJwtAuth(client_id="c", private_key_pem=pem, kid="k"),
                   http=http, clock=clock)
    slow = CibaRequest(auth_req_id="slow", interval=3, expires_in=120, requested_at=clock())
    fast = CibaRequest(auth_req_id="fast", interval=3, expires_in=120, requested_at=clock())
    clock.advance(5)
    t1, _ = _poll_in_thread(c, slow)
    try:
        assert http.entered.wait(5)
        t2, out2 = _poll_in_thread(c, fast)
        t2.join(2)
        assert not t2.is_alive(), "poll of another request blocked behind a slow AS call"
        assert out2["outcome"] == PENDING and http.calls == ["slow", "fast"]
    finally:
        http.release.set()
        t1.join(5)


def test_a_request_with_a_call_in_flight_is_not_polled_again():
    """Two concurrent polls of the SAME request: one AS call, the other answers from cache at once."""
    pem, _ = _pem()
    clock = FakeClock()
    http = _GatedHttp(hold={"r"})
    c = CibaClient(bc_auth_endpoint=BC, token_endpoint=TOK, client_id="c", issuer=ISS,
                   client_auth=PrivateKeyJwtAuth(client_id="c", private_key_pem=pem, kid="k"),
                   http=http, clock=clock)
    req = CibaRequest(auth_req_id="r", interval=3, expires_in=120, requested_at=clock())
    clock.advance(5)
    t1, out1 = _poll_in_thread(c, req)
    try:
        assert http.entered.wait(5)
        clock.advance(10)                       # even past the interval, a call is already under way
        t2, out2 = _poll_in_thread(c, req)
        t2.join(2)
        assert not t2.is_alive(), "second poll of the same request blocked"
        assert out2["outcome"] == PENDING and http.calls == ["r"]
    finally:
        http.release.set()
        t1.join(5)
    assert out1["outcome"] == PENDING
    clock.advance(5)
    c.poll(req)
    assert http.calls == ["r", "r"]             # the flag is cleared: the next due poll goes out


def test_in_flight_flag_is_cleared_when_client_auth_raises():
    pem, _ = _pem()
    clock = FakeClock()

    class Broken:
        def apply(self, endpoint, form):
            raise RuntimeError("signer down")
    c = CibaClient(bc_auth_endpoint=BC, token_endpoint=TOK, client_id="c", issuer=ISS, client_auth=Broken(),
                   http=FakeAS(), clock=clock)
    req = CibaRequest(auth_req_id="r", interval=3, expires_in=120, requested_at=clock())
    clock.advance(5)
    with pytest.raises(RuntimeError):
        c.poll(req)
    clock.advance(5)
    with pytest.raises(RuntimeError):       # not stuck "in flight": the next due poll tries again
        c.poll(req)


def test_a_verdict_reached_while_a_call_was_in_flight_stands():
    """The client deadline passed while a call was out: a concurrent poll does not end the request on the
    client clock, and the AS's late approval is honoured for every caller (the AS is the authority)."""
    pem, _ = _pem()
    clock = FakeClock()
    c = CibaClient(bc_auth_endpoint=BC, token_endpoint=TOK, client_id="c", issuer=ISS,
                   client_auth=PrivateKeyJwtAuth(client_id="c", private_key_pem=pem, kid="k"), clock=clock)
    req = CibaRequest(auth_req_id="r", interval=3, expires_in=120, requested_at=clock())

    def late(method, url, form, headers):
        clock.advance(200)
        t, out = _poll_in_thread(c, req)         # a concurrent poll, past the deadline
        t.join(2)
        assert out.get("outcome") == PENDING     # the call in flight decides, not the client clock
        return 200, json.dumps({"access_token": "at"})
    c.http = late
    clock.advance(5)
    assert c.poll(req) == APPROVED and req.last_outcome == APPROVED and req.access_token == "at"
    assert c.poll(req) == APPROVED


class _HeldApproval:
    """The first token call blocks until ``release``, then answers with a token; ``entered`` is set once it
    is under way. Any later call answers authorization_pending."""

    def __init__(self):
        import threading
        self.entered, self.release, self.calls = threading.Event(), threading.Event(), 0

    def __call__(self, method, url, form, headers):
        self.calls += 1
        if self.calls == 1:
            self.entered.set()
            assert self.release.wait(10)
            return 200, json.dumps({"access_token": "at", "token_type": "Bearer"})
        return 400, json.dumps({"error": "authorization_pending"})


def test_an_approval_in_flight_at_the_deadline_is_not_lost():
    """The reviewer's race: poll A is waiting on the AS when the client deadline passes; poll B arrives.
    B must not mark the request expired, and A's approval must reach both callers."""
    pem, _ = _pem()
    clock = FakeClock()
    http = _HeldApproval()
    c = CibaClient(bc_auth_endpoint=BC, token_endpoint=TOK, client_id="c", issuer=ISS,
                   client_auth=PrivateKeyJwtAuth(client_id="c", private_key_pem=pem, kid="k"),
                   http=http, clock=clock)
    req = CibaRequest(auth_req_id="r", interval=3, expires_in=120, requested_at=clock())
    clock.advance(118)                            # the last due poll before the deadline
    ta, out_a = _poll_in_thread(c, req)
    try:
        assert http.entered.wait(5)               # A is waiting on the AS
        clock.advance(5)                          # ... and the client deadline passes meanwhile
        assert req.expired_by_clock(clock())
        tb, out_b = _poll_in_thread(c, req)
        tb.join(5)
        assert not tb.is_alive()
        assert out_b["outcome"] == PENDING and req.last_outcome == PENDING
    finally:
        http.release.set()                        # the human approved: the AS answers A with a token
        ta.join(5)
    assert out_a["outcome"] == APPROVED and req.access_token == "at"
    assert c.poll(req) == APPROVED                # B's next poll: the same verdict, no AS call
    assert http.calls == 1


def test_a_pending_answer_after_the_deadline_then_expires_on_the_client_clock():
    pem, _ = _pem()
    clock = FakeClock()
    fake = FakeAS()
    c = CibaClient(bc_auth_endpoint=BC, token_endpoint=TOK, client_id="c", issuer=ISS,
                   client_auth=PrivateKeyJwtAuth(client_id="c", private_key_pem=pem, kid="k"),
                   http=fake, clock=clock)
    req = CibaRequest(auth_req_id="r", interval=3, expires_in=120, requested_at=clock())
    clock.advance(121)
    assert c.poll(req) == EXPIRED and fake.token_calls == []    # no call in flight: the client clock rules


def test_ciba_polled_logs_the_outcome_returned(caplog):
    """When a final verdict was already in place, the event logs that verdict, not the AS's answer."""
    import logging
    pem, _ = _pem()
    clock = FakeClock()
    c = CibaClient(bc_auth_endpoint=BC, token_endpoint=TOK, client_id="c", issuer=ISS,
                   client_auth=PrivateKeyJwtAuth(client_id="c", private_key_pem=pem, kid="k"), clock=clock)
    req = CibaRequest(auth_req_id="r", interval=3, expires_in=120, requested_at=clock())

    def answer(method, url, form, headers):
        req.last_outcome = DENIED                 # e.g. another path recorded a verdict meanwhile
        return 200, json.dumps({"access_token": "at"})
    c.http = answer
    clock.advance(5)
    with caplog.at_level(logging.DEBUG, logger="client_attestation_sdk"):
        assert c.poll(req) == DENIED
    polled = [r for r in caplog.records if getattr(r, "event", None) == "authz.ciba_polled"]
    assert [r.attributes["outcome"] for r in polled] == [DENIED]
    assert req.access_token is None


def test_a_transport_error_after_a_final_verdict_leaves_the_state_alone():
    pem, _ = _pem()
    clock = FakeClock()
    c = CibaClient(bc_auth_endpoint=BC, token_endpoint=TOK, client_id="c", issuer=ISS,
                   client_auth=PrivateKeyJwtAuth(client_id="c", private_key_pem=pem, kid="k"), clock=clock)
    req = CibaRequest(auth_req_id="r", interval=3, expires_in=120, requested_at=clock())

    def broken(method, url, form, headers):
        req.last_outcome, req.last_error = DENIED, "403 access_denied"
        raise OSError("connection reset")
    c.http = broken
    clock.advance(5)
    assert c.poll(req) == DENIED
    assert req.last_error == "403 access_denied"


def test_last_poll_at_is_persisted_and_rehydrated():
    import time as _time
    req = CibaRequest(auth_req_id="r", interval=30, expires_in=120)
    ahead = _time.time() + 20                     # e.g. a replica whose last call was stamped later
    req.last_poll_at = ahead
    d = req.to_dict()
    assert d["last_poll_at"] == ahead
    assert CibaRequest.rehydrate(d).last_poll_at == ahead
    # an older or unreadable stored time, or one more than an interval ahead: the throttle starts from now
    for stored in (1.0, "junk", None, float("nan"), _time.time() + 10_000, _time.time() + 60,
                   _time.time() + 599):
        before = _time.time()
        r = CibaRequest.rehydrate({**d, "last_poll_at": stored})
        assert before <= r.last_poll_at <= _time.time()
