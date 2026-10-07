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
                   txn_hash="", instruction=dict(INSTR), initiator="a", created_at=clock.t, status=APPROVED)
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
    r = ProofingResolver(world.hooks(), _client(fake, clock), clock=clock)
    instr = {"account": "savings"}
    res = r.resolve(PROOF, subject="alice", instruction=instr, initiator="a")
    world.status = APPROVED
    assert r.poll(res.code).status == APPROVED
    assert r.verify_resume(res.code, subject="alice", instruction=instr)[0]
    ok, why = r.verify_resume(res.code, subject="alice", instruction=instr)
    assert not ok and "already been used" in why

    world2, clock2 = Proofer(), Clock()
    r2 = ProofingResolver(world2.hooks(), _client(FakeAS(), clock2), clock=clock2, max_approval_age=60)
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
    pr = ProofingResolver(world.hooks(), _client(FakeAS(), clock), clock=clock)
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
        r = ProofingResolver(Proofer().hooks(), _client(FakeAS(), clock), clock=clock)
        challenge = PROOF
    with pytest.raises(ValueError, match="reserved key 'subject'"):
        r.resolve(challenge, subject="alice", instruction=evil, initiator="a")


def test_verify_resume_rejects_a_subject_key():
    r, res, _ = _approved()
    with pytest.raises(ValueError):
        r.verify_resume(res.code, subject="alice", instruction={**INSTR, "subject": "alice"})
    world, clock = Proofer(), Clock()
    pr = ProofingResolver(world.hooks(), _client(FakeAS(), clock), clock=clock)
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
    pr = ProofingResolver(world.hooks(), _client(fake, clock), BlindStore(), clock=clock)
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
    pr = ProofingResolver(world.hooks(), _client(fake, clock), clock=clock)
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
    pr = ProofingResolver(hooks, _client(fake, clock), store, clock=clock)
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