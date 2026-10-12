"""ProofingResolver: the mDL/VC presentation ceremony.

The properties that matter and are easy to get wrong:
  * the VERIFIER is the evidence, not the CIBA tap — the resolver must never poll the token endpoint;
  * the verifier session is opened BEFORE the push (no push into a dead end);
  * the code is registered for the device BEFORE the push (the phone resolves it on arrival);
  * an MDL- prefix is load-bearing (the approver app routes on it);
  * a proofing for one account must not satisfy another (hash covers the instruction);
  * no payment assurance rung is claimed.
"""
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from client_attestation_sdk.authz_challenge import (
    APPROVED, CHANNEL_DEVICE, CHANNEL_LOCAL, DENIED, EXPIRED, IDENTITY_PROOFING, PENDING,
    Ceremony, CibaClient, Hooks, Pending, PrivateKeyJwtAuth, ProofingResolver, Resolved,
    Unavailable, parse_challenge, transaction_hash,
)

BC = "https://pf.example/as/bc-auth.ciba"
TOK = "https://pf.example/as/token.oauth2"
MDL = "org.iso.18013.5.1.mDL"

CHALLENGE = parse_challenge(401, {}, {
    "error": "identity_verification_required", "doctype": MDL,
    "pep": "PEP#2 (Bank API edge)", "reason": "No verified identity-proofing record"})
INSTR = {"account": "savings", "doctype": MDL}


def _pem():
    k = ec.generate_private_key(ec.SECP256R1())
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption()).decode()


class Clock:
    def __init__(self, t=3_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class FakeAS:
    def __init__(self):
        self.calls = []

    def __call__(self, method, url, form, headers):
        self.calls.append((url, dict(form)))
        if url == BC:
            return 200, json.dumps({"auth_req_id": "req-mdl", "interval": 3, "expires_in": 120})
        return 400, json.dumps({"error": "authorization_pending"})

    @property
    def pushes(self):
        return [c for c in self.calls if c[0] == BC]

    @property
    def token_calls(self):
        return [c for c in self.calls if c[0] == TOK]


class World:
    """Verifier + device registry + outcome sink."""

    def __init__(self):
        self.sessions = {}
        self.status = "pending"
        self.registered = []
        self.outcomes = []
        self.started = []
        self.covered = None
        self.channel = CHANNEL_DEVICE
        self.n = 0

    def proofing_start(self, cer):
        self.n += 1
        sid = f"vs_{self.n}"
        self.started.append((cer.code, cer.instruction.get("doctype"), cer.instruction.get("account")))
        self.sessions[sid] = cer.code
        return {"session_id": sid,
                "request_uri": f"openid4vp://request?uri=https://verifier/{sid}",
                "dcApiRequest": {"nonce": sid}}

    def proofing_status(self, cer):
        return self.status

    def hooks(self, **kw):
        h = Hooks(channel_for=lambda s: self.channel,
                  already_covered=lambda s, i: self.covered,
                  register_for_device=lambda c: self.registered.append((c.code, c.extra.get("request_uri"))),
                  proofing_start=self.proofing_start,
                  proofing_status=self.proofing_status,
                  on_outcome=lambda c, st: self.outcomes.append((c.code, st)))
        for k, v in kw.items():
            setattr(h, k, v)
        return h


def _resolver(world, fake, clock, **kw):
    pem = _pem()
    client = CibaClient(bc_auth_endpoint=BC, token_endpoint=TOK, client_id="urn:agent:acct:ciba",
                        client_auth=PrivateKeyJwtAuth(client_id="urn:agent:acct:ciba",
                                                      private_key_pem=pem, kid="k"),
                        issuer="https://localhost:9031", request_signing_key_pem=pem,
                        request_signing_kid="k", http=fake, clock=clock)
    return ProofingResolver(world.hooks(), client, clock=clock, **kw)


def test_happy_path_session_then_register_then_push():
    world, fake, clock = World(), FakeAS(), Clock()
    r = _resolver(world, fake, clock)
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="urn:agent:acct")
    assert isinstance(res, Pending)
    assert res.kind == IDENTITY_PROOFING and res.channel == CHANNEL_DEVICE
    # the approver app routes on this prefix
    assert res.code.startswith("MDL-") and len(res.code) == len("MDL-") + 22
    assert res.reference.startswith("MDL-") and len(res.reference) <= 20
    # the ceremony's life is the VERIFIER's, not PF's 120s auth_req_id
    assert res.expires_in == 300
    assert res.detail["account"] == "savings" and res.detail["doctype"] == MDL
    # verifier session opened FIRST, then registered, then pushed
    assert world.started == [(res.code, MDL, "savings")]
    assert world.registered and world.registered[0][0] == res.code
    assert world.registered[0][1].startswith("openid4vp://")
    assert len(fake.pushes) == 1
    cer = r.store.get(res.code)
    assert cer.extra["session_id"] == "vs_1"

    # PENDING while the wallet hasn't presented — and the token endpoint is NEVER polled
    assert r.poll(res.code).status == PENDING
    assert fake.token_calls == []

    # verifier verifies -> APPROVED, outcome recorded, still no token poll
    world.status = APPROVED
    clock.t += 5
    p = r.poll(res.code)
    assert p.status == APPROVED and p.kind == IDENTITY_PROOFING
    assert p.detail["session_id"] == "vs_1" and p.detail["doctype"] == MDL
    assert world.outcomes == [(res.code, APPROVED)]
    assert fake.token_calls == []
    # no payment assurance rung is invented for a document presentation
    assert p.assurance is None


def test_verify_resume_binds_to_the_proofed_account():
    world, fake, clock = World(), FakeAS(), Clock()
    r = _resolver(world, fake, clock)
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    world.status = APPROVED
    assert r.poll(res.code).status == APPROVED
    ok, why = r.verify_resume(res.code, subject="alice", instruction=INSTR)
    assert ok and why == MDL
    # a DIFFERENT account is not covered by this proofing
    ok, why = r.verify_resume(res.code, subject="alice", instruction={"account": "checking", "doctype": MDL})
    assert not ok and "not what was proofed" in why
    # nor a different subject
    assert r.verify_resume(res.code, subject="mallory", instruction=INSTR)[0] is False


def test_stale_challenge_short_circuits():
    world, fake, clock = World(), FakeAS(), Clock()
    world.covered = MDL
    r = _resolver(world, fake, clock)
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert isinstance(res, Resolved) and res.assurance == MDL
    assert fake.pushes == [] and world.started == []


def test_no_device_is_unavailable_and_never_pushes():
    world, fake, clock = World(), FakeAS(), Clock()
    world.channel = CHANNEL_LOCAL
    r = _resolver(world, fake, clock)
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert isinstance(res, Unavailable) and res.fallback == "bubble_up"
    assert res.detail["doctype"] == MDL
    assert fake.pushes == [] and world.started == []      # no verifier session wasted either


def test_verifier_failure_means_no_push():
    world, fake, clock = World(), FakeAS(), Clock()

    def boom(cer):
        raise RuntimeError("verifier unreachable")
    r = _resolver(world, fake, clock)
    r.hooks.proofing_start = boom
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert isinstance(res, Unavailable) and "verifier" in res.reason
    assert fake.pushes == []          # never push a request the wallet cannot open

    # a session with no session_id is equally a non-starter
    r.hooks.proofing_start = lambda cer: {}
    assert isinstance(r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a"), Unavailable)
    assert fake.pushes == []


def test_push_failure_is_unavailable():
    world, fake, clock = World(), FakeAS(), Clock()
    r = _resolver(world, fake, clock)
    r.client.http = lambda m, u, f, h: (503, "down")
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert isinstance(res, Unavailable) and "push failed" in res.reason


def test_dedupe_one_live_request_per_instruction():
    world, fake, clock = World(), FakeAS(), Clock()
    r = _resolver(world, fake, clock)
    a = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    b = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert b.code == a.code and b.reused and len(fake.pushes) == 1
    # a different account IS a different proofing
    c = r.resolve(CHALLENGE, subject="alice", instruction={"account": "checking", "doctype": MDL}, initiator="a")
    assert c.code != a.code and len(fake.pushes) == 2


def test_expiry_by_clock_is_terminal_and_recorded():
    world, fake, clock = World(), FakeAS(), Clock()
    r = _resolver(world, fake, clock, ttl_seconds=300)
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    clock.t += 301
    p = r.poll(res.code)
    assert p.status == EXPIRED and world.outcomes == [(res.code, EXPIRED)]
    assert fake.token_calls == []


def test_denied_presentation_and_no_renag():
    world, fake, clock = World(), FakeAS(), Clock()
    r = _resolver(world, fake, clock, max_attempts=1)
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    world.status = DENIED
    assert r.poll(res.code).status == DENIED
    again = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    assert isinstance(again, Unavailable) and "failed" in again.reason
    assert len(fake.pushes) == 1


def test_status_hook_blip_is_not_a_verdict():
    world, fake, clock = World(), FakeAS(), Clock()
    r = _resolver(world, fake, clock)
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")

    def boom(cer):
        raise OSError("verifier 502")
    r.hooks.proofing_status = boom
    assert r.poll(res.code).status == PENDING
    assert world.outcomes == []


def test_doctype_defaults_from_the_challenge_when_allowed():
    world, fake, clock = World(), FakeAS(), Clock()
    r = _resolver(world, fake, clock, doctypes=[MDL])
    res = r.resolve(CHALLENGE, subject="alice", instruction={"account": "savings"}, initiator="a")
    assert res.detail["doctype"] == MDL          # taken from the challenge, because the caller allows it
    assert res.txn_hash == transaction_hash({"subject": "alice", "account": "savings", "doctype": MDL})


def test_rejects_a_non_proofing_challenge_and_a_missing_subject():
    world, fake, clock = World(), FakeAS(), Clock()
    r = _resolver(world, fake, clock)
    pay = parse_challenge(401, {}, {"error": "insufficient_scope", "scope": "banking:payments:transfer"})
    assert isinstance(r.resolve(pay, subject="alice", instruction=INSTR, initiator="a"), Unavailable)
    assert isinstance(r.resolve(CHALLENGE, subject="", instruction=INSTR, initiator="a"), Unavailable)


def test_rehydrate_from_a_persisted_ceremony():
    world, fake, clock = World(), FakeAS(), Clock()
    durable = {}
    r = _resolver(world, fake, clock)
    r.hooks.persist = lambda c: durable.__setitem__(c.code, c.to_dict())
    r.hooks.rehydrate = lambda code: durable.get(code)
    res = r.resolve(CHALLENGE, subject="alice", instruction=INSTR, initiator="a")
    # a fresh replica: empty store, rehydrates from durable state
    r2 = _resolver(world, fake, clock)
    r2.hooks.rehydrate = lambda code: durable.get(code)
    world.status = APPROVED
    p = r2.poll(res.code)
    assert p.status == APPROVED
    cer = Ceremony.from_dict(durable[res.code])
    assert cer.extra["session_id"] == "vs_1" and cer.kind == IDENTITY_PROOFING
