"""CibaClient against a fake AS: request shape, client auth, and — above all — the poll throttle.
The throttle is the property that keeps a PingFederate grant alive; every port must reproduce it."""
import json

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from authz_challenge import (
    APPROVED, DENIED, EXPIRED, PENDING,
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
