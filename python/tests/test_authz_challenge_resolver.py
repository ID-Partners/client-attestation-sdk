"""CibaResolver / WebConsentResolver: the ceremony state machine with all deployment edges faked."""
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from authz_challenge import (
    APPROVED, ASSURANCE_DEVICE_APPROVED, ASSURANCE_WEB_CONSENT, CHANNEL_DEVICE, CHANNEL_LOCAL,
    CHANNEL_WEB, DENIED, EXPIRED, PENDING, RESOURCE_AUTHORISATION,
    Ceremony, CibaClient, CibaResolver, Hooks, MemoryStore, Pending, PrivateKeyJwtAuth,
    Resolved, Unavailable, WebConsentResolver, parse_challenge, transaction_hash,
)

BC = "https://pf.example/as/bc-auth.ciba"
TOK = "https://pf.example/as/token.oauth2"


def _pem():
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


class Clock:
    def __init__(self, t=2_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class FakeAS:
    def __init__(self):
        self.calls = []
        self.token_answers = []
        self.n = 0

    def __call__(self, method, url, form, headers):
        self.calls.append((url, dict(form)))
        if url == BC:
            self.n += 1
            return 200, json.dumps({"auth_req_id": f"req-{self.n}", "interval": 3, "expires_in": 120})
        if self.token_answers:
            return self.token_answers.pop(0)
        return 400, json.dumps({"error": "authorization_pending"})

    @property
    def pushes(self):
        return [c for c in self.calls if c[0] == BC]


CHALLENGE = parse_challenge(401, {}, {"error": "insufficient_scope", "scope": "banking:payments:transfer",
                                     "reason": "over threshold", "pep": "PEP#2"})
INSTR = {"amount": "9000", "currency": "AUD", "debtor": "CHK-1001", "creditor": "SAV-2002"}


def _resolver(fake, clock, hooks=None, **kw):
    pem = _pem()
    client = CibaClient(bc_auth_endpoint=BC, token_endpoint=TOK, client_id="urn:agent:payments",
                        client_auth=PrivateKeyJwtAuth(client_id="urn:agent:payments", private_key_pem=pem, kid="k"),
                        issuer="https://localhost:9031", request_signing_key_pem=pem, request_signing_kid="k",
                        http=fake, clock=clock)
    return CibaResolver(client, hooks or Hooks(channel_for=lambda s: CHANNEL_DEVICE, settle_seconds=0),
                        clock=clock, **kw)


def test_transaction_hash_is_canonical_json():
    # sorted keys, compact separators, raw UTF-8, JSON types kept - reproducible in any language
    import hashlib
    fields = {"subject": "alice", **INSTR}
    canon = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert transaction_hash(fields) == hashlib.sha256(canon.encode()).hexdigest()
    assert transaction_hash({"a": 1, "b": 2}) == transaction_hash({"b": 2, "a": 1})       # order
    assert transaction_hash({"amount": 9000}) != transaction_hash({"amount": "9000"})     # types kept


def test_transaction_hash_pinned_bytes_for_other_ports():
    # Nested objects sorted at every level, arrays in order, non-ASCII as raw UTF-8, null kept.
    import hashlib
    fields = {"z": [3, 1, {"b": None, "a": "\u00e9"}], "a": {"y": True, "x": "1.50"}}
    expected = '{"a":{"x":"1.50","y":true},"z":[3,1,{"a":"\u00e9","b":null}]}'
    assert expected.encode("utf-8") == b'{"a":{"x":"1.50","y":true},"z":[3,1,{"a":"\xc3\xa9","b":null}]}'
    assert transaction_hash(fields) == hashlib.sha256(expected.encode("utf-8")).hexdigest()
    # nested values are no longer str()-ed (the old form was Python-repr dependent)
    assert transaction_hash({"n": {"a": 1}}) != transaction_hash({"n": str({"a": 1})})


def test_transaction_hash_refuses_non_portable_values():
    import pytest
    with pytest.raises(ValueError):
        transaction_hash({"amount": float("nan")})
    with pytest.raises(TypeError):
        transaction_hash({"when": object()})


def test_happy_path_push_then_approve():
    fake, clock = FakeAS(), Clock()
    events = []
    hooks = Hooks(channel_for=lambda s: CHANNEL_DEVICE, settle_seconds=0,
                  register_for_device=lambda c: events.append(("register", c.code)),
                  persist=lambda c: events.append(("persist", c.code, c.status)),
                  on_outcome=lambda c, st: events.append(("outcome", c.code, st, c.assurance)))
    r = _resolver(fake, clock, hooks)
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="urn:agent:payments")
    assert isinstance(res, Pending)
    assert res.channel == CHANNEL_DEVICE and res.kind == RESOURCE_AUTHORISATION
    # the handle is unguessable (128 bits); the short reference is what the device shows
    assert res.code.startswith("PAY-") and len(res.code) == len("PAY-") + 22
    assert res.reference.startswith("PAY-") and len(res.reference) <= 20 and res.reference != res.code
    assert res.interval == 3 and res.expires_in == 120 and res.attempt == 1 and not res.reused
    assert res.txn_hash == transaction_hash({"subject": "alice", **INSTR})
    # registered BEFORE the push (the phone resolves the code on arrival), then persisted
    assert events[0] == ("register", res.code)
    assert ("persist", res.code, PENDING) in events
    # the push carried the short reference as the binding message, never the handle
    assert len(fake.pushes) == 1
    pushed = json.dumps(fake.pushes[0][1])
    assert res.code not in pushed
    # poll: pending, then approved
    p = r.poll(res.code)
    assert p.status == PENDING
    fake.token_answers = [(200, json.dumps({"access_token": "x"}))]
    clock.t += 4
    p = r.poll(res.code)
    assert p.status == APPROVED and p.assurance == ASSURANCE_DEVICE_APPROVED
    assert ("outcome", res.code, APPROVED, ASSURANCE_DEVICE_APPROVED) in events
    # verify_resume: same instruction ok, tampered instruction refused
    ok, why = r.verify_resume(res.code, subject="alice", instruction={**INSTR, "amount": "90000"})
    assert not ok and "does not match" in why
    ok, why = r.verify_resume(res.code, subject="mallory", instruction=INSTR)
    assert not ok
    ok, why = r.verify_resume(res.code, subject="alice", instruction=INSTR)
    assert ok and why == ASSURANCE_DEVICE_APPROVED


def test_settle_window_holds_approved_until_device_verdict_or_timeout():
    fake, clock = FakeAS(), Clock()
    durable = {}

    def persist(c):
        durable[c.code] = c.to_dict()

    def rehydrate(code):
        return durable.get(code)
    hooks = Hooks(channel_for=lambda s: CHANNEL_DEVICE, settle_seconds=3, persist=persist, rehydrate=rehydrate)
    r = _resolver(fake, clock, hooks)
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    fake.token_answers = [(200, "{}")]
    p = r.poll(res.code)
    assert p.status == PENDING and p.detail.get("settling")          # AS said yes; we hold
    # the phone's stronger verdict lands in the durable store during the window
    durable[res.code]["assurance"] = "recognize-verified"
    clock.t += 1
    p = r.poll(res.code)
    assert p.status == APPROVED and p.assurance == "recognize-verified"    # not downgraded


def test_settle_window_falls_back_to_device_approved():
    fake, clock = FakeAS(), Clock()
    hooks = Hooks(channel_for=lambda s: CHANNEL_DEVICE, settle_seconds=3)
    r = _resolver(fake, clock, hooks)
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    fake.token_answers = [(200, "{}")]
    assert r.poll(res.code).status == PENDING
    clock.t += 3.5
    p = r.poll(res.code)
    assert p.status == APPROVED and p.assurance == ASSURANCE_DEVICE_APPROVED


def test_denied_and_expired_are_terminal_and_recorded():
    for answer, expect in [((400, json.dumps({"error": "access_denied"})), DENIED),
                           ((400, json.dumps({"error": "expired_token"})), EXPIRED)]:
        fake, clock = FakeAS(), Clock()
        outcomes = []
        hooks = Hooks(channel_for=lambda s: CHANNEL_DEVICE, settle_seconds=0,
                      on_outcome=lambda c, st: outcomes.append(st))
        r = _resolver(fake, clock, hooks)
        res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
        fake.token_answers = [answer]
        assert r.poll(res.code).status == expect
        assert outcomes == [expect]
        ok, _ = r.verify_resume(res.code, subject="alice", instruction=INSTR)
        assert not ok


def test_dedupe_returns_same_ceremony_not_a_second_push():
    fake, clock = FakeAS(), Clock()
    r = _resolver(fake, clock)
    a = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    b = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert isinstance(b, Pending) and b.code == a.code and b.reused
    assert len(fake.pushes) == 1
    # a DIFFERENT instruction is a different ceremony
    c = r.resolve(CHALLENGE, subject="alice", instruction={**INSTR, "amount": "50"}, initiator="a")
    assert c.code != a.code and len(fake.pushes) == 2


def test_dedupe_across_replicas_via_persisted_lookup():
    fake, clock = FakeAS(), Clock()
    other = Ceremony(code="PAY-elsewhere", kind=RESOURCE_AUTHORISATION, channel=CHANNEL_DEVICE,
                     subject="alice", txn_hash=transaction_hash({"subject": "alice", **INSTR}),
                     instruction=INSTR, initiator="replica-2", created_at=clock.t)
    other.extra["expires_in"] = 120
    hooks = Hooks(channel_for=lambda s: CHANNEL_DEVICE, settle_seconds=0,
                  find_live_persisted=lambda s, h: other.to_dict())
    r = _resolver(fake, clock, hooks)
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert isinstance(res, Pending) and res.code == "PAY-elsewhere" and res.reused
    assert fake.pushes == []


def test_stale_challenge_short_circuits_when_already_covered():
    fake, clock = FakeAS(), Clock()
    hooks = Hooks(channel_for=lambda s: CHANNEL_DEVICE, already_covered=lambda s, i: "recognize-verified")
    r = _resolver(fake, clock, hooks)
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert isinstance(res, Resolved) and res.assurance == "recognize-verified"
    assert fake.pushes == []


def test_no_device_is_unavailable_with_bubble_up_and_fails_closed():
    fake, clock = FakeAS(), Clock()
    r = _resolver(fake, clock, Hooks(channel_for=lambda s: CHANNEL_LOCAL))
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert isinstance(res, Unavailable) and res.fallback == "bubble_up"
    # web channel available -> the fallback names it
    r2 = _resolver(fake, clock, Hooks(channel_for=lambda s: CHANNEL_WEB))
    assert r2.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a").fallback == CHANNEL_WEB
    # hook blows up -> treated as no device
    def boom(s):
        raise RuntimeError("directory down")
    r3 = _resolver(fake, clock, Hooks(channel_for=boom))
    assert isinstance(r3.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a"), Unavailable)
    # no hook at all -> no device
    r4 = _resolver(fake, clock, Hooks())
    assert isinstance(r4.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a"), Unavailable)
    assert fake.pushes == []


def test_push_failure_is_unavailable_not_an_exception():
    fake, clock = FakeAS(), Clock()
    r = _resolver(fake, clock)

    def http_500(m, u, f, h):
        return 503, "down"
    r.client.http = http_500
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert isinstance(res, Unavailable) and "push failed" in res.reason and res.fallback == "bubble_up"


def test_attempt_cap_after_a_denial_but_not_after_an_approval():
    fake, clock = FakeAS(), Clock()
    r = _resolver(fake, clock, max_attempts=1)
    a = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    fake.token_answers = [(400, json.dumps({"error": "access_denied"}))]
    assert r.poll(a.code).status == DENIED
    b = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert isinstance(b, Unavailable) and "attempt" in b.reason           # she said no; don't nag
    assert len(fake.pushes) == 1
    # an APPROVED ceremony does not block a later identical instruction
    fake2, clock2 = FakeAS(), Clock()
    r2 = _resolver(fake2, clock2, max_attempts=1)
    a2 = r2.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    fake2.token_answers = [(200, "{}")]
    assert r2.poll(a2.code).status == APPROVED
    b2 = r2.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert isinstance(b2, Pending) and b2.code != a2.code and len(fake2.pushes) == 2


def test_wrong_kind_and_missing_subject():
    fake, clock = FakeAS(), Clock()
    r = _resolver(fake, clock)
    authn = parse_challenge(401, {}, {"error": "login_required"})
    assert isinstance(r.resolve(authn, subject="alice", instruction={}, initiator="a"), Unavailable)
    assert isinstance(r.resolve(CHALLENGE, subject="", instruction=INSTR, initiator="a"), Unavailable)


def test_poll_unknown_code_is_none_and_rehydrate_path():
    fake, clock = FakeAS(), Clock()
    r = _resolver(fake, clock)
    assert r.poll("PAY-nope") is None
    # rehydrate hook supplies a ceremony this process never saw
    cer = Ceremony(code="PAY-r", kind=RESOURCE_AUTHORISATION, channel=CHANNEL_DEVICE, subject="alice",
                   txn_hash="h", instruction=INSTR, initiator="x", created_at=clock.t, status=APPROVED,
                   assurance="device-signed")
    r2 = _resolver(fake, clock, Hooks(rehydrate=lambda code: cer.to_dict() if code == "PAY-r" else None))
    p = r2.poll("PAY-r")
    assert p.status == APPROVED and p.assurance == "device-signed"


def test_ceremony_roundtrip():
    c = Ceremony(code="PAY-1", kind=RESOURCE_AUTHORISATION, channel=CHANNEL_DEVICE, subject="alice",
                 txn_hash="h", instruction=INSTR, initiator="i", created_at=1.0, extra={"scope": "s"})
    from authz_challenge import CibaRequest
    c.ciba = CibaRequest(auth_req_id="r", interval=3, expires_in=120, requested_at=1.0)
    d = json.loads(json.dumps(c.to_dict()))
    back = Ceremony.from_dict(d)
    assert back.code == "PAY-1" and back.ciba.auth_req_id == "r" and back.ciba.interval == 3
    assert back.extra["scope"] == "s" and back.instruction == INSTR
    assert back.ciba.last_poll_at > 0          # rehydrate seeded the throttle


def test_web_consent_resolver():
    clock = Clock()
    outcomes = []
    state = {"status": PENDING}
    hooks = Hooks(consent_url_for=lambda c: f"https://bank.example/consent/{c.code}",
                  web_status=lambda c: state["status"],
                  on_outcome=lambda c, st: outcomes.append((st, c.assurance)))
    r = WebConsentResolver(hooks, ttl_seconds=300, interval=3, clock=clock)
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert isinstance(res, Pending) and res.channel == CHANNEL_WEB
    assert res.consent_url.endswith(res.code) and res.expires_in == 300
    # dedupe
    again = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert again.code == res.code and again.reused
    assert r.poll(res.code).status == PENDING
    state["status"] = APPROVED
    p = r.poll(res.code)
    assert p.status == APPROVED and p.assurance == ASSURANCE_WEB_CONSENT      # never more than that
    assert outcomes == [(APPROVED, ASSURANCE_WEB_CONSENT)]
    # expiry by clock
    res2 = r.resolve(CHALLENGE, subject="bob", instruction=INSTR, initiator="a")
    clock.t += 301
    assert r.poll(res2.code).status == EXPIRED
