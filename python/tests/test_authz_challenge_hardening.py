"""authz_challenge hardening: secret-free reprs, single-use + age-limited approvals, 128-bit handles,
canonical hashing, the reserved ``subject`` key, atomic dedupe, and the loud TLS-off switch."""
import json
import threading
import time
import warnings

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from client_attestation_sdk.authz_challenge import (
    APPROVED, CHANNEL_DEVICE, EXPIRED, IDENTITY_PROOFING, PENDING, RESOURCE_AUTHORISATION,
    Ceremony, CibaClient, CibaRequest, CibaResolver, Hooks, MemoryStore, Pending, PollResult,
    PrivateKeyJwtAuth, ProofingResolver, Resolved, Unavailable, WebConsentResolver, parse_challenge,
)
from client_attestation_sdk.authz_challenge import ciba as ciba_mod
from client_attestation_sdk.authz_challenge.ciba import urllib_http
from client_attestation_sdk.authz_challenge.resolver import new_code, new_handle

BC = "https://pf.example/as/bc-auth.ciba"
TOK = "https://pf.example/as/token.oauth2"
MDL = "org.iso.18013.5.1.mDL"
CHALLENGE = parse_challenge(401, {}, {"error": "insufficient_scope", "scope": "banking:payments:transfer"})
PROOF = parse_challenge(401, {}, {"error": "identity_verification_required", "doctype": MDL})
INSTR = {"amount": "9000", "currency": "AUD", "creditor": "SAV-2002"}


def _pem():
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


class Clock:
    def __init__(self, t=5_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class FakeAS:
    def __init__(self, delay=0.0):
        self.calls = []
        self.answers = []
        self.delay = delay
        self.n = 0
        self._lock = threading.Lock()

    def __call__(self, method, url, form, headers):
        if self.delay:
            time.sleep(self.delay)
        with self._lock:
            self.calls.append((url, dict(form)))
            if url == BC:
                self.n += 1
                return 200, json.dumps({"auth_req_id": f"secret-req-{self.n}", "interval": 3, "expires_in": 120})
            if self.answers:
                return self.answers.pop(0)
            return 400, json.dumps({"error": "authorization_pending"})

    @property
    def pushes(self):
        return [c for c in self.calls if c[0] == BC]


def _client(fake, clock, pem=None):
    pem = pem or _pem()
    return CibaClient(bc_auth_endpoint=BC, token_endpoint=TOK, client_id="urn:agent",
                      client_auth=PrivateKeyJwtAuth(client_id="urn:agent", private_key_pem=pem, kid="k"),
                      issuer="https://as", http=fake, clock=clock)


def _approved(store=None, hooks=None, **kw):
    fake, clock = FakeAS(), Clock()
    hooks = hooks or Hooks(channel_for=lambda s: CHANNEL_DEVICE, settle_seconds=0)
    r = CibaResolver(_client(fake, clock), hooks, store, clock=clock, **kw)
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    fake.answers = [(200, json.dumps({"access_token": "at-secret"}))]
    clock.t += 4
    assert r.poll(res.code).status == APPROVED
    return r, res, clock


class Proofer:
    def __init__(self):
        self.status = PENDING
        self.start_error = None
        self.n = 0

    def start(self, cer):
        if self.start_error:
            raise self.start_error
        self.n += 1
        return {"session_id": f"vs_{self.n}"}

    def hooks(self):
        return Hooks(channel_for=lambda s: CHANNEL_DEVICE, proofing_start=self.start,
                     proofing_status=lambda c: self.status)


# ---- item 12: no key material in repr --------------------------------------------------------------
def test_reprs_carry_no_key_material_tokens_or_handles():
    pem = _pem()
    auth = PrivateKeyJwtAuth(client_id="urn:agent", private_key_pem=pem, kid="k1")
    assert "PRIVATE KEY" not in repr(auth) and pem not in repr(auth) and "urn:agent" in repr(auth)

    req = CibaRequest(auth_req_id="secret-req", interval=3, expires_in=60,
                      access_token="at-secret", token_response={"access_token": "at-secret"})
    assert "secret-req" not in repr(req) and "at-secret" not in repr(req)

    cer = Ceremony(code="PAY-handle-secret", kind=RESOURCE_AUTHORISATION, channel=CHANNEL_DEVICE,
                   subject="alice", txn_hash="h", instruction={}, initiator="a", ciba=req,
                   consent_url="https://x/?t=url-secret", extra={"session_id": "extra-secret"},
                   reference="PAY-abc")
    text = repr(cer)
    for secret in ("handle-secret", "secret-req", "at-secret", "url-secret", "extra-secret"):
        assert secret not in text
    assert "PAY-abc" in text

    for obj in (Pending(code="PAY-handle-secret", kind="k", channel="c", interval=3, expires_in=1),
                Resolved(code="PAY-handle-secret", kind="k"),
                PollResult(code="PAY-handle-secret", status=PENDING, kind="k")):
        assert "handle-secret" not in repr(obj)


def test_resolver_flow_reprs_are_clean():
    r, res, _ = _approved()
    cer = r.store.get(res.code)
    assert res.code not in repr(res) and res.code not in repr(cer)
    assert "secret-req" not in repr(cer) and "at-secret" not in repr(cer.ciba)


# ---- 14a: single use + age limit ------------------------------------------------------------------
def test_verify_resume_is_single_use():
    durable = {}
    hooks = Hooks(channel_for=lambda s: CHANNEL_DEVICE, settle_seconds=0,
                  persist=lambda c: durable.__setitem__(c.code, c.to_dict()))
    r, res, _ = _approved(hooks=hooks)
    ok, _why = r.verify_resume(res.code, subject="alice", instruction=INSTR)
    assert ok
    ok, why = r.verify_resume(res.code, subject="alice", instruction=INSTR)
    assert not ok and "already been used" in why
    # consumption is persisted, so a replica that rehydrates the ceremony refuses it too
    assert durable[res.code]["consumed_at"] is not None
    rebuilt = Ceremony.from_dict(durable[res.code])
    assert rebuilt.consumed_at is not None


def test_verify_resume_consumption_survives_rehydrate_into_a_fresh_resolver():
    durable = {}
    hooks = Hooks(channel_for=lambda s: CHANNEL_DEVICE, settle_seconds=0,
                  persist=lambda c: durable.__setitem__(c.code, c.to_dict()),
                  rehydrate=lambda code: durable.get(code))
    r, res, clock = _approved(hooks=hooks)
    assert r.verify_resume(res.code, subject="alice", instruction=INSTR)[0]
    other = CibaResolver(_client(FakeAS(), clock), hooks, clock=clock)
    ok, why = other.verify_resume(res.code, subject="alice", instruction=INSTR)
    assert not ok and "already been used" in why


def test_verify_resume_concurrent_replays_only_one_wins():
    r, res, _ = _approved()
    results = []
    barrier = threading.Barrier(8)

    def go():
        barrier.wait()
        results.append(r.verify_resume(res.code, subject="alice", instruction=INSTR)[0])
    threads = [threading.Thread(target=go) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1


def test_verify_resume_refuses_an_old_approval():
    r, res, clock = _approved()
    assert r.max_approval_age == 300.0
    clock.t += 301
    ok, why = r.verify_resume(res.code, subject="alice", instruction=INSTR)
    assert not ok and "older than 300s" in why


def test_verify_resume_age_is_configurable_and_can_be_disabled():
    r, res, clock = _approved(max_approval_age=10)
    clock.t += 11
    assert r.verify_resume(res.code, subject="alice", instruction=INSTR)[0] is False
    r, res, clock = _approved(max_approval_age=None)
    clock.t += 100_000
    assert r.verify_resume(res.code, subject="alice", instruction=INSTR)[0] is True


def test_verify_resume_age_falls_back_to_created_at_without_approved_at():
    clock = Clock()
    cer = Ceremony(code="PAY-x", kind=RESOURCE_AUTHORISATION, channel=CHANNEL_DEVICE, subject="alice",
                   txn_hash="", instruction=dict(INSTR), initiator="a", created_at=clock.t, status=APPROVED,
                   resolver="ciba", approved_via="ciba_poll")
    from client_attestation_sdk.authz_challenge.resolver import _bound_hash
    cer.txn_hash = _bound_hash("alice", INSTR)
    store = MemoryStore()
    store.put(cer)
    r = CibaResolver(_client(FakeAS(), clock), Hooks(), store, clock=clock)
    clock.t += 400
    ok, why = r.verify_resume("PAY-x", subject="alice", instruction=INSTR)
    assert not ok and "older than" in why


def test_proofing_verify_resume_is_single_use_and_age_limited():
    world, fake, clock = Proofer(), FakeAS(), Clock()
    r = ProofingResolver(world.hooks(), _client(fake, clock), clock=clock, doctypes=(MDL,))
    instr = {"account": "savings"}
    res = r.resolve(PROOF, subject="alice", instruction=instr, initiator="a")
    world.status = APPROVED
    assert r.poll(res.code).status == APPROVED
    assert r.verify_resume(res.code, subject="alice", instruction=instr)[0]
    ok, why = r.verify_resume(res.code, subject="alice", instruction=instr)
    assert not ok and "already been used" in why

    world2, clock2 = Proofer(), Clock()
    r2 = ProofingResolver(world2.hooks(), _client(FakeAS(), clock2), clock=clock2, max_approval_age=60,
                          doctypes=(MDL,))
    res2 = r2.resolve(PROOF, subject="alice", instruction=instr, initiator="a")
    world2.status = APPROVED
    assert r2.poll(res2.code).status == APPROVED
    clock2.t += 61
    ok, why = r2.verify_resume(res2.code, subject="alice", instruction=instr)
    assert not ok and "older than 60s" in why


# ---- 14b: 128-bit handles, short reference kept separate ------------------------------------------
def test_handles_carry_128_bits_and_the_reference_is_display_only():
    h = new_handle("PAY")
    assert h.startswith("PAY-") and len(h) == 4 + 22          # token_urlsafe(16) == 128 bits
    assert len({new_handle() for _ in range(1000)}) == 1000
    assert len(new_code("PAY")) <= 20                            # still fits a binding_message

    fake, clock = FakeAS(), Clock()
    r = CibaResolver(_client(fake, clock), Hooks(channel_for=lambda s: CHANNEL_DEVICE), clock=clock)
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert res.reference and res.reference != res.code
    # the binding message on the wire is the short reference, the handle never leaves the process
    assert fake.pushes[0][1]["binding_message"] == res.reference
    # the reference does not unlock anything
    assert r.poll(res.reference) is None
    assert r.verify_resume(res.reference, subject="alice", instruction=INSTR)[0] is False
    # reference survives persistence
    assert Ceremony.from_dict(r.store.get(res.code).to_dict()).reference == res.reference


def test_explicit_binding_message_still_wins():
    fake, clock = FakeAS(), Clock()
    r = CibaResolver(_client(fake, clock), Hooks(channel_for=lambda s: CHANNEL_DEVICE), clock=clock)
    r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a", binding_message="Pay $9000")
    assert fake.pushes[0][1]["binding_message"] == "Pay $9000"


def test_web_and_proofing_codes_are_handles_too():
    clock = Clock()
    web = WebConsentResolver(Hooks(consent_url_for=lambda c: f"https://consent/{c.code}"), clock=clock)
    p = web.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert len(p.code) == len("WEB-") + 22 and p.reference.startswith("WEB-")
    world = Proofer()
    pr = ProofingResolver(world.hooks(), _client(FakeAS(), clock), clock=clock, doctypes=(MDL,))
    q = pr.resolve(PROOF, subject="alice", instruction={"account": "s"}, initiator="a")
    assert len(q.code) == len("MDL-") + 22 and q.reference.startswith("MDL-")


# ---- 14d: reserved subject key ---------------------------------------------------------------------
@pytest.mark.parametrize("which", ["ciba", "web", "proofing"])
def test_instruction_may_not_carry_subject(which):
    clock = Clock()
    evil = {**INSTR, "subject": "mallory"}
    if which == "ciba":
        r = CibaResolver(_client(FakeAS(), clock), Hooks(channel_for=lambda s: CHANNEL_DEVICE), clock=clock)
        challenge = CHALLENGE
    elif which == "web":
        r = WebConsentResolver(Hooks(consent_url_for=lambda c: "https://c"), clock=clock)
        challenge = CHALLENGE
    else:
        r = ProofingResolver(Proofer().hooks(), _client(FakeAS(), clock), clock=clock, doctypes=(MDL,))
        challenge = PROOF
    with pytest.raises(ValueError, match="reserved key 'subject'"):
        r.resolve(challenge, subject="alice", instruction=evil, initiator="a")


def test_verify_resume_rejects_a_subject_key():
    r, res, _ = _approved()
    with pytest.raises(ValueError):
        r.verify_resume(res.code, subject="alice", instruction={**INSTR, "subject": "alice"})
    world, clock = Proofer(), Clock()
    pr = ProofingResolver(world.hooks(), _client(FakeAS(), clock), clock=clock, doctypes=(MDL,))
    with pytest.raises(ValueError):
        pr.verify_resume("MDL-x", subject="alice", instruction={"subject": "alice"})


# ---- 14e: atomic dedupe -----------------------------------------------------------------------------
class BlindStore(MemoryStore):
    """find_live always misses — as if a concurrent resolve slipped in between the dedupe and the
    insert. Only the atomic put_if_no_live stands between that and a second push."""

    def find_live(self, subject, txn_hash, now=None):
        return None


def test_claim_is_atomic_even_when_the_fast_path_dedupe_misses():
    fake, clock = FakeAS(), Clock()
    r = CibaResolver(_client(fake, clock), Hooks(channel_for=lambda s: CHANNEL_DEVICE), BlindStore(), clock=clock)
    a = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    b = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert b.reused and b.code == a.code and len(fake.pushes) == 1


def test_web_and_proofing_claims_are_atomic():
    clock = Clock()
    minted = []
    web = WebConsentResolver(Hooks(consent_url_for=lambda c: minted.append(c.code) or "https://c"),
                             BlindStore(), clock=clock)
    a = web.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    b = web.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert b.reused and b.code == a.code and minted == [a.code]

    fake, world = FakeAS(), Proofer()
    pr = ProofingResolver(world.hooks(), _client(fake, clock), BlindStore(), clock=clock, doctypes=(MDL,))
    a = pr.resolve(PROOF, subject="alice", instruction={"account": "s"}, initiator="a")
    b = pr.resolve(PROOF, subject="alice", instruction={"account": "s"}, initiator="a")
    assert b.reused and b.code == a.code and len(fake.pushes) == 1 and world.n == 1


class PlainStore:
    """A deployment store with only the CeremonyStore protocol (no put_if_no_live / discard),
    slow enough on lookups to widen any race."""

    def __init__(self):
        self.d = {}

    def get(self, code):
        return self.d.get(code)

    def put(self, c):
        self.d[c.code] = c

    def find_live(self, subject, txn_hash, now=None):
        time.sleep(0.01)
        for c in list(self.d.values()):
            if c.subject == subject and c.txn_hash == txn_hash and c.is_live(now):
                return c
        return None


@pytest.mark.parametrize("store_factory", [MemoryStore, PlainStore])
def test_concurrent_resolves_push_once(store_factory):
    fake, clock = FakeAS(delay=0.02), Clock()
    hooks = Hooks(channel_for=lambda s: CHANNEL_DEVICE, register_for_device=lambda c: time.sleep(0.02))
    r = CibaResolver(_client(fake, clock), hooks, store_factory(), clock=clock)
    out = []
    barrier = threading.Barrier(6)

    def go():
        barrier.wait()
        out.append(r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a"))
    threads = [threading.Thread(target=go) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(fake.pushes) == 1
    assert len({p.code for p in out}) == 1 and sum(not p.reused for p in out) == 1


def test_failed_verifier_start_releases_the_claim():
    clock, world, fake = Clock(), Proofer(), FakeAS()
    pr = ProofingResolver(world.hooks(), _client(fake, clock), clock=clock, doctypes=(MDL,))
    world.start_error = RuntimeError("verifier down")
    res = pr.resolve(PROOF, subject="alice", instruction={"account": "s"}, initiator="a")
    assert isinstance(res, Unavailable) and "verifier down" in res.reason
    # not deduped onto a dead ceremony, and not counted as a failed attempt
    world.start_error = None
    res = pr.resolve(PROOF, subject="alice", instruction={"account": "s"}, initiator="a")
    assert isinstance(res, Pending) and not res.reused


def test_no_session_id_releases_the_claim_and_plain_stores_mark_it_expired():
    clock, fake = Clock(), FakeAS()
    store = PlainStore()
    hooks = Hooks(channel_for=lambda s: CHANNEL_DEVICE, proofing_start=lambda c: {})
    pr = ProofingResolver(hooks, _client(fake, clock), store, clock=clock, doctypes=(MDL,))
    res = pr.resolve(PROOF, subject="alice", instruction={"account": "s"}, initiator="a")
    assert isinstance(res, Unavailable) and "session_id" in res.reason
    assert [c.status for c in store.d.values()] == [EXPIRED]
    assert fake.pushes == []


def test_web_consent_url_failure_releases_the_claim():
    clock = Clock()
    calls = []

    def mint(c):
        calls.append(c.code)
        if len(calls) == 1:
            raise RuntimeError("boom")
        return "https://consent"
    web = WebConsentResolver(Hooks(consent_url_for=mint), clock=clock)
    with pytest.raises(RuntimeError):
        web.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    p = web.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert isinstance(p, Pending) and not p.reused and p.consent_url == "https://consent"


def test_identity_proofing_kind_through_ciba_resolver_still_works():
    fake, clock = FakeAS(), Clock()
    r = CibaResolver(_client(fake, clock), Hooks(channel_for=lambda s: CHANNEL_DEVICE), clock=clock)
    res = r.resolve(PROOF, subject="alice", instruction={"account": "s"}, initiator="a")
    assert isinstance(res, Pending) and res.kind == IDENTITY_PROOFING


# ---- 14f: the TLS-off switch -------------------------------------------------------------------------
def _captured_context(monkeypatch, **kw):
    seen = {}

    class Resp:
        status = 200

        def text(self):
            return "{}"

    def fake_request(method, url, *, headers, body, timeout, context):
        seen["ctx"] = context
        return Resp()
    monkeypatch.setattr(ciba_mod._http, "request", fake_request)
    urllib_http(**kw)("POST", "https://as/x", {}, {})
    return seen["ctx"]


def test_dangerously_disable_tls_verification_turns_verification_off_without_warning(monkeypatch):
    import ssl
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        ctx = _captured_context(monkeypatch, dangerously_disable_tls_verification=True)
        assert ctx.verify_mode == ssl.CERT_NONE and ctx.check_hostname is False
        assert _captured_context(monkeypatch) is None


def test_insecure_tls_alias_is_gone(monkeypatch):
    with pytest.raises(TypeError):
        _captured_context(monkeypatch, insecure_tls=True)

# ---- the handle never reaches Hooks.log ----------------------------------------------------------
def _boom(*a):
    raise RuntimeError("hook down")


def _assert_no_handle(lines, codes):
    assert lines, "the scenario should have logged something"
    for code in codes:
        assert code
        for line in lines:
            assert code not in line, line


def test_ciba_resolver_logs_name_the_reference_never_the_handle():
    fake, clock = FakeAS(), Clock()
    logs, durable = [], {}

    def persist(c):
        durable[c.code] = c.to_dict()
        raise RuntimeError("disk full")
    hooks = Hooks(channel_for=lambda s: CHANNEL_DEVICE, settle_seconds=0, persist=persist,
                  rehydrate=durable.get, register_for_device=_boom, on_outcome=_boom, log=logs.append)
    r = CibaResolver(_client(fake, clock), hooks, clock=clock)
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    fake.answers = [(200, json.dumps({"access_token": "at-secret"}))]
    clock.t += 4
    assert r.poll(res.code).status == APPROVED                       # on_outcome fails -> logged
    # a fresh resolver rehydrates it (logged), and a persisted record with no reference is fingerprinted
    r2 = CibaResolver(_client(fake, clock), hooks, clock=clock)
    assert r2.poll(res.code) is not None
    legacy = {**durable[res.code], "code": "PAY-legacy-handle", "reference": None}
    durable["PAY-legacy-handle"] = legacy
    assert r2.poll("PAY-legacy-handle") is not None
    _assert_no_handle(logs, [res.code, "PAY-legacy-handle"])
    assert any(res.reference in line and "rehydrated" in line for line in logs)
    assert any("#" in line and "rehydrated" in line for line in logs)
    for word in ("persist failed", "register_for_device failed", "on_outcome(approved) failed"):
        assert any(word in line and res.reference in line for line in logs), word
    # the CIBA auth_req_id is a bearer handle at the token endpoint: no part of it is logged
    assert any("pushed to" in line for line in logs)
    assert not any("auth_req_id" in line or "secret-r" in line for line in logs)


@pytest.mark.parametrize("which", ["ciba", "proofing"])
def test_push_failure_does_not_hand_back_the_handle(which):
    clock, raised = Clock(), []

    def http(method, url, form, headers):
        return 503, "down"
    if which == "ciba":
        hooks = Hooks(channel_for=lambda s: CHANNEL_DEVICE, register_for_device=raised.append)
        res = CibaResolver(_client(http, clock), hooks, clock=clock).resolve(
            CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    else:
        hooks = Proofer().hooks()
        hooks.register_for_device = raised.append
        res = ProofingResolver(hooks, _client(http, clock), clock=clock, doctypes=(MDL,)).resolve(
            PROOF, subject="alice", instruction={"account": "s"}, initiator="a")
    assert isinstance(res, Unavailable) and "push failed" in res.reason
    assert raised[0].code not in json.dumps(res.to_dict())
    assert res.detail["reference"] == raised[0].reference


def test_web_resolver_logs_never_carry_the_handle():
    clock, logs, status = Clock(), [], [_boom]

    def web_status(c):
        return status[0](c)
    hooks = Hooks(consent_url_for=lambda c: "https://consent", persist=_boom, web_status=web_status,
                  on_outcome=_boom, log=logs.append)
    web = WebConsentResolver(hooks, clock=clock)
    p = web.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert web.poll(p.code).status == PENDING                         # web_status fails -> logged
    status[0] = lambda c: APPROVED
    assert web.poll(p.code).status == APPROVED                        # on_outcome fails -> logged
    _assert_no_handle(logs, [p.code])
    assert len(logs) == 3 and all(p.reference in line for line in logs)


def test_proofing_resolver_logs_never_carry_the_handle():
    clock, fake, world, logs = Clock(), FakeAS(), Proofer(), []
    hooks = world.hooks()
    status = [_boom]
    hooks.proofing_status = lambda c: status[0](c)
    hooks.persist, hooks.register_for_device, hooks.on_outcome, hooks.log = _boom, _boom, _boom, logs.append
    pr = ProofingResolver(hooks, _client(fake, clock), clock=clock, doctypes=(MDL,))
    p = pr.resolve(PROOF, subject="alice", instruction={"account": "s"}, initiator="a")
    assert pr.poll(p.code).status == PENDING                          # proofing_status fails -> logged
    status[0] = lambda c: APPROVED
    assert pr.poll(p.code).status == APPROVED
    _assert_no_handle(logs, [p.code])
    for word in ("register_for_device failed", "persist failed", "pushed", "proofing_status failed",
                 "on_outcome(approved) failed", "-> approved"):
        assert any(word in line and p.reference in line for line in logs), word


# ---- a live ceremony is reused only by the initiator that raised it ------------------------------
def test_another_initiator_is_not_handed_a_live_ceremony():
    fake, clock = FakeAS(), Clock()
    r = CibaResolver(_client(fake, clock), Hooks(channel_for=lambda s: CHANNEL_DEVICE, settle_seconds=0),
                     clock=clock)
    a = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="agent-a")
    b = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="agent-b")
    assert isinstance(b, Unavailable) and "another initiator" in b.reason
    assert a.code not in json.dumps(b.to_dict()) and len(fake.pushes) == 1
    again = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="agent-a")
    assert again.reused and again.code == a.code
    # agent-a's approval still resumes; the audit record names agent-a
    fake.answers = [(200, json.dumps({"access_token": "at"}))]
    clock.t += 4
    assert r.poll(a.code).status == APPROVED
    assert r.store.get(a.code).initiator == "agent-a"
    assert r.verify_resume(a.code, subject="alice", instruction=INSTR)[0]


def test_initiator_check_covers_the_atomic_claim():
    fake, clock = FakeAS(), Clock()
    r = CibaResolver(_client(fake, clock), Hooks(channel_for=lambda s: CHANNEL_DEVICE), BlindStore(), clock=clock)
    a = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="agent-a")
    b = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="agent-b")
    assert isinstance(b, Unavailable) and a.code not in json.dumps(b.to_dict()) and len(fake.pushes) == 1


def test_initiator_survives_persist_and_rehydrate():
    """A replica that only knows the ceremony from the durable store applies the same rule."""
    durable = {}
    fake, clock = FakeAS(), Clock()

    def find_live_persisted(subject, txn_hash):
        return next((d for d in durable.values() if d["subject"] == subject and d["txn_hash"] == txn_hash), None)
    hooks = Hooks(channel_for=lambda s: CHANNEL_DEVICE, persist=lambda c: durable.__setitem__(c.code, c.to_dict()),
                  rehydrate=durable.get, find_live_persisted=find_live_persisted)
    a = CibaResolver(_client(fake, clock), hooks, clock=clock).resolve(
        CHALLENGE, subject="alice", instruction=INSTR, initiator="agent-a")
    other = CibaResolver(_client(fake, clock), hooks, clock=clock)    # fresh process, empty memory
    b = other.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="agent-b")
    assert isinstance(b, Unavailable) and a.code not in json.dumps(b.to_dict())
    same = CibaResolver(_client(fake, clock), hooks, clock=clock).resolve(
        CHALLENGE, subject="alice", instruction=INSTR, initiator="agent-a")
    assert same.reused and same.code == a.code and len(fake.pushes) == 1


def test_web_and_proofing_refuse_another_initiators_live_ceremony():
    clock = Clock()
    web = WebConsentResolver(Hooks(consent_url_for=lambda c: "https://c/?t=one-time"), clock=clock)
    a = web.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="agent-a")
    b = web.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="agent-b")
    assert isinstance(b, Unavailable)
    assert a.code not in json.dumps(b.to_dict()) and "one-time" not in json.dumps(b.to_dict())

    for store in (MemoryStore(), BlindStore()):                    # the fast-path dedupe, then the claim
        fake, world = FakeAS(), Proofer()
        pr = ProofingResolver(world.hooks(), _client(fake, clock), store, clock=clock, doctypes=(MDL,))
        a = pr.resolve(PROOF, subject="alice", instruction={"account": "s"}, initiator="agent-a")
        b = pr.resolve(PROOF, subject="alice", instruction={"account": "s"}, initiator="agent-b")
        assert isinstance(b, Unavailable) and a.code not in json.dumps(b.to_dict())
        assert len(fake.pushes) == 1 and world.n == 1


# ---- the resolver does not take a 200 that is not a token response as approval -------------------
def test_resolver_does_not_approve_on_a_200_without_an_access_token():
    fake, clock = FakeAS(), Clock()
    r = CibaResolver(_client(fake, clock), Hooks(channel_for=lambda s: CHANNEL_DEVICE, settle_seconds=0),
                     clock=clock)
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    fake.answers = [(200, "<html>proxy login</html>")]
    clock.t += 4
    assert r.poll(res.code).status == PENDING
    assert not r.verify_resume(res.code, subject="alice", instruction=INSTR)[0]


# ---- a resolver resumes only the ceremonies it raised and approved --------------------------------
def _shared_world():
    """Every resolver on ONE store and ONE set of hooks, as a deployment that wires them once would."""
    clock, fake, world = Clock(), FakeAS(), Proofer()
    hooks = world.hooks()
    hooks.settle_seconds = 0
    hooks.consent_url_for = lambda c: "https://consent"
    hooks.web_status = lambda c: APPROVED
    store = MemoryStore()
    client = _client(fake, clock)
    return (clock, fake, world, CibaResolver(client, hooks, store, clock=clock),
            WebConsentResolver(hooks, store, clock=clock),
            ProofingResolver(hooks, client, store, clock=clock))


def test_a_tap_or_a_click_never_satisfies_a_proofing():
    clock, fake, world, ciba, web, proof = _shared_world()
    instr = {"account": "savings", "doctype": MDL}
    tap = ciba.resolve(PROOF, subject="alice", instruction=instr, initiator="a")
    fake.answers = [(200, json.dumps({"access_token": "at"}))]
    clock.t += 4
    assert ciba.poll(tap.code).status == APPROVED
    assert proof.poll(tap.code) is None
    assert proof.verify_resume(tap.code, subject="alice", instruction=instr) == (False, "unknown proofing code")

    click = web.resolve(PROOF, subject="alice", instruction={"account": "current", "doctype": MDL}, initiator="a")
    assert web.poll(click.code).status == APPROVED
    assert not proof.verify_resume(click.code, subject="alice",
                                   instruction={"account": "current", "doctype": MDL})[0]
    # each still resumes through the resolver that raised it, as a tap / a click, and only once its own
    # poll saw the approval
    ciba.store.get(tap.code).approved_via = None
    assert ciba.verify_resume(tap.code, subject="alice", instruction=instr) == \
        (False, "ceremony was not approved through this resolver")
    ciba.store.get(tap.code).approved_via = "ciba_poll"
    assert ciba.verify_resume(tap.code, subject="alice", instruction=instr) == (True, "device-approved")
    assert web.verify_resume(click.code, subject="alice",
                             instruction={"account": "current", "doctype": MDL}) == (True, "app-asserted")


def test_a_tap_never_satisfies_a_proofing_through_shared_durable_hooks():
    durable = {}
    clock, fake = Clock(), FakeAS()
    hooks = Proofer().hooks()
    hooks.settle_seconds = 0
    hooks.persist = hooks.on_outcome = lambda c, *_: durable.__setitem__(c.code, c.to_dict())
    hooks.rehydrate = durable.get
    ciba = CibaResolver(_client(fake, clock), hooks, clock=clock)              # own MemoryStore
    proof = ProofingResolver(hooks, _client(fake, clock), clock=clock)
    instr = {"account": "savings", "doctype": MDL}
    p = ciba.resolve(CHALLENGE, subject="alice", instruction=instr, initiator="a")
    fake.answers = [(200, json.dumps({"access_token": "at"}))]
    clock.t += 4
    assert ciba.poll(p.code).status == APPROVED
    assert not proof.verify_resume(p.code, subject="alice", instruction=instr)[0]


def test_a_proofing_is_approved_only_by_the_verifier():
    clock, fake, world, ciba, web, proof = _shared_world()
    instr = {"account": "s", "doctype": MDL}
    p = proof.resolve(PROOF, subject="alice", instruction=instr, initiator="a")
    # the CIBA resolver will not poll (and so tap-approve) the proofing's push
    fake.answers = [(200, json.dumps({"access_token": "at"}))]
    clock.t += 4
    assert ciba.poll(p.code) is None and fake.calls[-1][0] == BC
    assert not ciba.verify_resume(p.code, subject="alice", instruction=instr)[0]
    # a record that says approved without the verifier's verdict (or a pre-upgrade record) is refused
    cer = proof.store.get(p.code)
    cer.status = APPROVED
    for via in (None, "ciba_poll"):
        cer.approved_via = via
        assert proof.verify_resume(p.code, subject="alice", instruction=instr) == \
            (False, "proofing was not verified by the verifier")
    cer.status = PENDING
    world.status = APPROVED
    assert proof.poll(p.code).status == APPROVED
    assert proof.verify_resume(p.code, subject="alice", instruction=instr) == (True, MDL)


def test_a_live_ceremony_of_another_resolver_is_not_reused():
    clock, fake, world, ciba, web, proof = _shared_world()
    w = web.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    res = ciba.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert isinstance(res, Unavailable) and "another resolver" in res.reason
    assert w.code not in json.dumps(res.to_dict()) and fake.pushes == []


def test_durable_records_for_another_code_or_instruction_are_ignored():
    clock, fake = Clock(), FakeAS()
    r, res, _ = _approved()
    stranger = r.store.get(res.code).to_dict()
    hooks = Hooks(channel_for=lambda s: CHANNEL_DEVICE, rehydrate=lambda code: stranger,
                  find_live_persisted=lambda s, h: dict(stranger, status=PENDING))
    other = CibaResolver(_client(fake, clock), hooks, clock=clock)
    assert other.poll("PAY-something-else") is None
    assert not other.verify_resume("PAY-something-else", subject="alice", instruction=INSTR)[0]
    p = other.resolve(CHALLENGE, subject="bob", instruction=INSTR, initiator="a")
    assert isinstance(p, Pending) and not p.reused and p.code != res.code and len(fake.pushes) == 1


# ---- single use holds across replicas, and fails closed when it cannot be recorded --------------
def _replicas(**hook_overrides):
    durable = {}
    clock, fake = Clock(), FakeAS()
    hooks = Hooks(channel_for=lambda s: CHANNEL_DEVICE, settle_seconds=0,
                  persist=lambda c: durable.__setitem__(c.code, c.to_dict()), rehydrate=durable.get,
                  on_outcome=lambda c, s: durable.__setitem__(c.code, c.to_dict()))
    for k, v in hook_overrides.items():
        setattr(hooks, k, v)
    a = CibaResolver(_client(fake, clock), hooks, clock=clock)
    b = CibaResolver(_client(fake, clock), hooks, clock=clock)
    p = a.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="agent")
    fake.answers = [(200, json.dumps({"access_token": "at"}))]
    clock.t += 4
    assert a.poll(p.code).status == APPROVED
    assert b.poll(p.code).status == APPROVED          # B now holds its own in-memory copy
    return durable, a, b, p


def test_a_replica_with_a_stale_copy_does_not_accept_a_used_approval():
    durable, a, b, p = _replicas()
    assert a.verify_resume(p.code, subject="alice", instruction=INSTR)[0]
    assert durable[p.code]["consumed_at"] is not None
    assert b.verify_resume(p.code, subject="alice", instruction=INSTR) == \
        (False, "ceremony approval has already been used")


def test_an_approval_whose_use_cannot_be_recorded_is_refused():
    down = [True]

    def persist(c):
        if down[0] and c.consumed_at:
            raise OSError("db down")
        durable[c.code] = c.to_dict()
    durable, a, b, p = _replicas(persist=persist)
    assert a.verify_resume(p.code, subject="alice", instruction=INSTR) == \
        (False, "ceremony approval could not be recorded as used")
    down[0] = False                                    # storage back: the approval is still good, once
    assert b.verify_resume(p.code, subject="alice", instruction=INSTR)[0]
    assert not a.verify_resume(p.code, subject="alice", instruction=INSTR)[0]


def test_an_unreadable_store_refuses_the_resume():
    durable, a, b, p = _replicas()
    a.hooks.rehydrate = _boom
    assert a.verify_resume(p.code, subject="alice", instruction=INSTR) == (False, "ceremony state could not be read")


def test_the_optional_consume_hook_is_the_atomic_single_use_write():
    used, calls = set(), []

    def consume(c):
        calls.append(c.consumed_at)
        if c.code in used:
            return False
        used.add(c.code)
        return True
    durable, a, b, p = _replicas(consume=consume)
    assert a.verify_resume(p.code, subject="alice", instruction=INSTR)[0]
    assert b.verify_resume(p.code, subject="alice", instruction=INSTR) == \
        (False, "ceremony approval has already been used")
    assert durable[p.code]["consumed_at"] is None       # consume replaced persist: the CAS alone decided
    assert len(calls) == 2 and all(calls)

    durable, a, b, p = _replicas(consume=_boom)
    assert a.verify_resume(p.code, subject="alice", instruction=INSTR) == \
        (False, "ceremony approval could not be recorded as used")


# ---- a failed push never leaves a claimed ceremony behind ----------------------------------------
class ConnectError(Exception):
    """What a custom HttpFn (httpx, requests) raises: not a CibaError."""


def test_any_push_exception_releases_the_claim():
    fake, clock = FakeAS(), Clock()
    r = CibaResolver(_client(fake, clock), Hooks(channel_for=lambda s: CHANNEL_DEVICE), clock=clock)
    healthy = r.client.http

    def reset(*a):
        raise ConnectError("connection reset")
    r.client.http = reset
    with pytest.raises(ConnectError):
        r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    r.client.http = healthy
    p = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert isinstance(p, Pending) and not p.reused and len(fake.pushes) == 1

    class BadAuth:
        def apply(self, endpoint, form):
            raise RuntimeError("signing key unavailable")
    r2 = CibaResolver(_client(fake, clock), Hooks(channel_for=lambda s: CHANNEL_DEVICE), clock=clock)
    r2.client.client_auth = BadAuth()
    with pytest.raises(RuntimeError):
        r2.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert r2.store.find_live("alice", p.txn_hash, clock()) is None


def test_an_infinite_interval_does_not_leave_a_ceremony_that_never_expires():
    clock = Clock()
    http = lambda m, u, f, h: (200, '{"auth_req_id":"abc","interval":1e400,"expires_in":1e400}') if u == BC \
        else (400, '{"error":"authorization_pending"}')
    r = CibaResolver(_client(http, clock), Hooks(channel_for=lambda s: CHANNEL_DEVICE), clock=clock)
    p = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert isinstance(p, Pending) and p.expires_in == 120
    assert not r.store.get(p.code).is_live(clock() + 121)


def test_a_ciba_ceremony_without_expires_in_gets_a_short_lifetime():
    clock = Clock()
    http = lambda m, u, f, h: (200, '{"auth_req_id":"abc","interval":3}') if u == BC \
        else (400, '{"error":"authorization_pending"}')
    r = CibaResolver(_client(http, clock), Hooks(channel_for=lambda s: CHANNEL_DEVICE), clock=clock)
    p = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert p.expires_in == 120
    clock.t += 121
    again = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert isinstance(again, Pending) and not again.reused


def test_a_failed_push_is_not_an_attempt():
    fake, clock = FakeAS(), Clock()
    r = CibaResolver(_client(fake, clock), Hooks(channel_for=lambda s: CHANNEL_DEVICE), clock=clock,
                     max_attempts=1)
    healthy = r.client.http
    r.client.http = lambda *a: (503, "busy")
    assert "push failed" in r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a").reason
    r.client.http = healthy
    p = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert isinstance(p, Pending) and p.attempt == 1


def test_proofing_releases_the_claim_on_any_push_failure():
    fake, clock, world = FakeAS(), Clock(), Proofer()
    pr = ProofingResolver(world.hooks(), _client(fake, clock), clock=clock, max_attempts=1)
    instr = {"account": "s", "doctype": MDL}
    healthy = pr.client.http

    def reset(*a):
        raise ConnectError("connection reset")
    pr.client.http = reset
    with pytest.raises(ConnectError):
        pr.resolve(PROOF, subject="alice", instruction=instr, initiator="a")
    pr.client.http = lambda *a: (503, "busy")
    assert "push failed" in pr.resolve(PROOF, subject="alice", instruction=instr, initiator="a").reason
    pr.client.http = healthy
    p = pr.resolve(PROOF, subject="alice", instruction=instr, initiator="a")
    assert isinstance(p, Pending) and not p.reused and p.attempt == 1 and len(fake.pushes) == 1


# ---- the PEP does not choose the credential -----------------------------------------------------
def test_a_pep_supplied_doctype_needs_the_callers_allowlist():
    PID = "eu.europa.ec.eudi.pid.1"
    pid_challenge = parse_challenge(401, {}, {"error": "identity_verification_required", "doctype": PID})
    clock, fake, world = Clock(), FakeAS(), Proofer()
    pr = ProofingResolver(world.hooks(), _client(fake, clock), clock=clock)
    res = pr.resolve(pid_challenge, subject="alice", instruction={"account": "s"}, initiator="a")
    assert isinstance(res, Unavailable) and "doctype" in res.reason
    pr2 = ProofingResolver(world.hooks(), _client(fake, clock), clock=clock, doctypes=[MDL])
    assert isinstance(pr2.resolve(pid_challenge, subject="alice", instruction={"account": "s"}, initiator="a"),
                      Unavailable)
    # a pinned doctype the challenge contradicts is refused too
    res = pr.resolve(pid_challenge, subject="alice", instruction={"account": "s", "doctype": MDL}, initiator="a")
    assert isinstance(res, Unavailable) and "different doctype" in res.reason
    assert world.n == 0 and fake.pushes == []
    # pinned by the caller, with or without the challenge naming it
    no_doctype = parse_challenge(401, {}, {"error": "identity_verification_required"})
    for ch in (PROOF, no_doctype):
        p = pr.resolve(ch, subject="alice", instruction={"account": ch.error + str(ch.doctype), "doctype": MDL},
                       initiator="a")
        assert isinstance(p, Pending) and p.detail["doctype"] == MDL
    with pytest.raises(ValueError):
        ProofingResolver(world.hooks(), doctypes=MDL)


def test_verify_resume_compares_the_proofed_doctype():
    clock, fake, world = Clock(), FakeAS(), Proofer()
    pr = ProofingResolver(world.hooks(), _client(fake, clock), clock=clock)
    p = pr.resolve(PROOF, subject="alice", instruction={"account": "s", "doctype": MDL}, initiator="a")
    world.status = APPROVED
    assert pr.poll(p.code).status == APPROVED
    ok, why = pr.verify_resume(p.code, subject="alice", instruction={"account": "s"})
    assert not ok and "doctype" in why                  # not pinned, not allowed: not accepted
    assert not pr.verify_resume(p.code, subject="alice",
                                instruction={"account": "s", "doctype": "eu.europa.ec.eudi.pid.1"})[0]
    assert pr.verify_resume(p.code, subject="alice", instruction={"account": "s", "doctype": MDL}) == (True, MDL)


# ---- WebConsentResolver: verify_resume, a subject, and a consent URL that does not leak ------------
def _web(clock, state, **kw):
    hooks = Hooks(consent_url_for=lambda c: "https://as/consent?otp=SECRET123", web_status=lambda c: state[0])
    return WebConsentResolver(hooks, clock=clock, **kw)


def test_web_consent_verify_resume_is_bound_single_use_and_age_limited():
    clock, state = Clock(), [PENDING]
    web = _web(clock, state)
    p = web.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert web.verify_resume(p.code, subject="alice", instruction=INSTR) == \
        (False, "consent is pending, not approved")
    state[0] = APPROVED
    assert web.poll(p.code).status == APPROVED
    assert not web.verify_resume(p.code, subject="alice", instruction={**INSTR, "amount": "90000"})[0]
    assert not web.verify_resume(p.code, subject="mallory", instruction=INSTR)[0]
    assert web.verify_resume(p.code, subject="alice", instruction=INSTR) == (True, "app-asserted")
    assert web.verify_resume(p.code, subject="alice", instruction=INSTR) == \
        (False, "consent approval has already been used")
    assert web.verify_resume("WEB-nope", subject="alice", instruction=INSTR)[1] == "unknown consent code"

    web2 = _web(clock, state, max_approval_age=60)
    p2 = web2.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    web2.poll(p2.code)
    clock.t += 61
    ok, why = web2.verify_resume(p2.code, subject="alice", instruction=INSTR)
    assert not ok and "older than" in why


def test_web_consent_needs_a_subject():
    res = _web(Clock(), [PENDING]).resolve(CHALLENGE, subject="", instruction=INSTR, initiator="a")
    assert isinstance(res, Unavailable) and "subject" in res.reason


def test_web_consent_url_is_out_of_reprs_and_gone_once_terminal():
    clock, state = Clock(), [PENDING]
    web = _web(clock, state)
    p = web.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert p.consent_url and "SECRET123" not in repr(p)
    pending = web.poll(p.code)
    assert pending.consent_url == p.consent_url and "SECRET123" not in repr(pending)
    assert "consent_url" not in pending.detail
    state[0] = APPROVED
    done = web.poll(p.code)
    assert done.status == APPROVED and done.consent_url is None
    assert "SECRET123" not in json.dumps(done.to_dict()) and "SECRET123" not in repr(done)
