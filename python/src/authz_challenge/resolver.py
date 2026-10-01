"""Resolving a challenge: the ceremony an agent runs so the SAME call, re-sent, is permitted.

:mod:`.challenge` says *what* the PEP wants. This module is *how an agent gets it*, in a shape
that survives the two facts of life about human approval:

* it is **slow** (30 s – minutes) — far longer than any request an agent is inside of, so the
  ceremony is *asynchronous*: :meth:`ChallengeResolver.resolve` returns immediately with a
  :class:`Pending` handle, and the caller (or anyone holding the handle) drives
  :meth:`ChallengeResolver.poll` until a terminal state;
* it may be **impossible** on the channel the agent has — no paired device, no browser to redirect
  to — in which case the resolver says so (:class:`Unavailable`) and names the fallback, rather than
  quietly degrading the assurance it will later claim.

Two reference resolvers ship:

* :class:`CibaResolver` — a decoupled push to the human's paired authenticator via
  :class:`.ciba.CibaClient`, then a throttled poll. The approval is a SIGNAL, not a credential: the
  resolver reports "approved" and the caller records the authorisation where its PDP will find it
  (a consent record, a grant), then re-sends the original call. Whether the AS also minted a token is
  incidental (on PingFederate the CIBA grant's subject is fixed by a default mapping, so it is
  discarded).
* :class:`WebConsentResolver` — no device: hand back a URL the human completes in a browser (behind
  the AS's own login, federated if need be), and poll a "has it landed" hook.

Everything that is *this deployment's business* — how to look up whether the human has a paired
device, where to persist the in-flight ceremony so it survives a restart, how to tell the approver app
what the push is about, how to record the outcome — is an injected callable on :class:`Hooks`. The
SDK owns the protocol and the state machine; the deployment owns its directories.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, Optional, Protocol

from . import ciba as _ciba
from .challenge import Challenge, IDENTITY_PROOFING, RESOURCE_AUTHORISATION

# ---- ceremony status vocabulary (== ciba outcomes, plus a client-side "unavailable") ------------
PENDING = _ciba.PENDING
APPROVED = _ciba.APPROVED
DENIED = _ciba.DENIED
EXPIRED = _ciba.EXPIRED
TERMINAL = (APPROVED, DENIED, EXPIRED)

# ---- channels -----------------------------------------------------------------------------------
CHANNEL_DEVICE = "device"          # a paired authenticator exists -> decoupled push
CHANNEL_WEB = "web_consent"        # no device, but a URL can be handed to the human
CHANNEL_LOCAL = "local"            # neither -> the caller must fall back to its own UI (bubble up)

# ---- assurance rungs the resolver is allowed to CLAIM ------------------------------------------
# A CIBA approve is evidence a paired device was tapped, NOT that anything was signed over the
# instruction. Anything stronger (a signature over the hash, a biometric verdict) is written by the
# device-facing surface that actually saw it — never by this poll.
ASSURANCE_DEVICE_APPROVED = "device-approved"
ASSURANCE_WEB_CONSENT = "app-asserted"


#: The instruction key the resolvers bind the subject under. Callers may not supply it themselves.
SUBJECT_KEY = "subject"

#: Default lifetime of an approval for :meth:`CibaResolver.verify_resume` (seconds after approval).
DEFAULT_MAX_APPROVAL_AGE = 300.0


def transaction_hash(fields: Dict[str, Any]) -> str:
    """Canonical SHA-256 over the INSTRUCTION — what a signing device would sign and what a dispute
    layer re-derives to prove what the human actually approved.

    Canonicalisation (every port MUST reproduce it byte for byte):

    1. Serialise ``fields`` as JSON with object keys sorted (by code point), no insignificant
       whitespace (separators ``,`` and ``:``), and non-ASCII characters emitted as raw UTF-8, not
       ``\\uXXXX`` escapes. In Python:
       ``json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)``.
       Nested objects are sorted the same way at every level; arrays keep their order.
    2. Encode that string as UTF-8.
    3. SHA-256 it; the result is the lowercase hex digest.

    Values keep their JSON type: ``9000`` and ``"9000"`` hash differently, and ``None`` is ``null``.
    Pass amounts and other decimals as STRINGS — float formatting differs between languages, so a
    float is not portable. NaN/Infinity and values JSON cannot represent raise ``ValueError`` /
    ``TypeError``. Both sides of a ceremony (the pusher and the approver surface) MUST pass the same
    keys and value types, or the hashes will not agree and a signature over one is worthless for the
    other.
    """
    canon = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _bound_hash(subject: str, instruction: Dict[str, Any]) -> str:
    """The hash the resolvers bind a ceremony to: the instruction plus the subject under
    :data:`SUBJECT_KEY`. The key is reserved — an instruction carrying its own ``subject`` could
    otherwise override (or impersonate) the human the ceremony is for — so it is refused."""
    if SUBJECT_KEY in instruction:
        raise ValueError(f"instruction must not contain the reserved key {SUBJECT_KEY!r}")
    return transaction_hash({SUBJECT_KEY: subject, **instruction})


def new_code(prefix: str = "PAY", nbytes: int = 3) -> str:
    """A short human-relayable REFERENCE (``PAY-a1b2c3``): ≤20 chars so it fits a CIBA
    ``binding_message``, charset-safe for every push renderer we have met.

    Display only. At the default 24 bits it is guessable and MUST NOT be what authorises anything —
    the resolvers key a ceremony by :func:`new_handle` and carry this as :attr:`Ceremony.reference`."""
    return f"{prefix}-{secrets.token_hex(nbytes)}"


def new_handle(prefix: str = "PAY") -> str:
    """An unguessable ceremony handle: ``<prefix>-`` plus 128 bits from :mod:`secrets` (url-safe
    base64, 22 chars). This is what :meth:`CibaResolver.poll` and :meth:`CibaResolver.verify_resume`
    are keyed by, so anyone holding it can ask after (and resume) the ceremony."""
    return f"{prefix}-{secrets.token_urlsafe(16)}"


# ---- results ------------------------------------------------------------------------------------
@dataclass
class Pending:
    """The ceremony has been raised; poll ``code`` until terminal. ``reference`` is the short code the
    human sees on the device (the CIBA ``binding_message``); ``code`` is the unguessable handle."""
    code: str = field(repr=False)
    kind: str                       # challenge type being resolved
    channel: str                    # CHANNEL_DEVICE | CHANNEL_WEB
    interval: int                   # suggested poll cadence (seconds)
    expires_in: int                 # seconds until the ceremony dies on its own
    txn_hash: str = ""
    consent_url: Optional[str] = None       # CHANNEL_WEB only
    detail: Dict[str, Any] = field(default_factory=dict)   # what the human is being asked
    attempt: int = 1
    reused: bool = False            # True when an identical live ceremony was found and returned
    reference: Optional[str] = None  # the short display code pushed to the device

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class Resolved:
    """No ceremony was needed — an authorisation covering this instruction already stands."""
    code: Optional[str] = field(repr=False)
    kind: str
    assurance: Optional[str] = None
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class Unavailable:
    """This resolver cannot run a ceremony for this challenge on the channels it has.
    ``fallback`` tells the caller what to do instead (``bubble_up`` = surface the original challenge
    to whatever UI exists; ``enrol`` = the human has no authenticator at all)."""
    kind: str
    reason: str
    fallback: str = "bubble_up"
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class PollResult:
    code: str = field(repr=False)
    status: str                     # PENDING | APPROVED | DENIED | EXPIRED
    kind: str
    assurance: Optional[str] = None
    elapsed: float = 0.0
    interval: int = 3
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


# ---- the ceremony record ------------------------------------------------------------------------
@dataclass
class Ceremony:
    """One in-flight (or finished) ceremony. This is the unit the deployment persists.

    ``code`` is the unguessable handle (:func:`new_handle`) and is kept out of ``repr``;
    ``reference`` is the short display code pushed to the device (:func:`new_code`)."""
    code: str = field(repr=False)
    kind: str
    channel: str
    subject: str                    # the human (login_hint / principal)
    txn_hash: str
    instruction: Dict[str, Any]     # what is being approved (amount, creditor, …) — for the device
    initiator: str                  # which agent raised it (audit)
    created_at: float = field(default_factory=time.time)
    status: str = PENDING
    assurance: Optional[str] = None
    attempt: int = 1
    ciba: Optional[_ciba.CibaRequest] = field(default=None, repr=False)
    consent_url: Optional[str] = field(default=None, repr=False)   # may embed a one-time token
    approved_at: Optional[float] = None
    settle_until: float = 0.0       # hold "approved" until then so out-of-band evidence can land
    extra: Dict[str, Any] = field(default_factory=dict, repr=False)
    reference: Optional[str] = None     # short display code (the CIBA binding_message)
    consumed_at: Optional[float] = None  # set when verify_resume accepted it; never accepted again

    @property
    def expires_in(self) -> int:
        # An explicit lifetime wins over the CIBA grant's. They diverge on purpose for an
        # identity proofing: CIBA is only the push channel there (the grant is never redeemed),
        # so the ceremony lives as long as the VERIFIER's presentation request, not the ~120s
        # PingFederate gives an auth_req_id.
        explicit = self.extra.get("expires_in")
        if explicit:
            return int(explicit)
        if self.ciba:
            return self.ciba.expires_in
        return 0

    @property
    def interval(self) -> int:
        return self.ciba.interval if self.ciba else int(self.extra.get("interval") or 3)

    def is_live(self, now: Optional[float] = None) -> bool:
        now = now or time.time()
        if self.status in TERMINAL:
            return False
        exp = self.expires_in
        return not exp or now < self.created_at + exp

    def to_dict(self) -> dict:
        d = {"code": self.code, "kind": self.kind, "channel": self.channel, "subject": self.subject,
             "txn_hash": self.txn_hash, "instruction": dict(self.instruction),
             "initiator": self.initiator, "created_at": self.created_at, "status": self.status,
             "assurance": self.assurance, "attempt": self.attempt,
             "consent_url": self.consent_url, "approved_at": self.approved_at,
             "extra": dict(self.extra), "reference": self.reference, "consumed_at": self.consumed_at}
        if self.ciba:
            d["ciba"] = self.ciba.to_dict()
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Ceremony":
        c = cls(code=d["code"], kind=d.get("kind", RESOURCE_AUTHORISATION),
                channel=d.get("channel", CHANNEL_DEVICE), subject=d.get("subject", ""),
                txn_hash=d.get("txn_hash", ""), instruction=dict(d.get("instruction") or {}),
                initiator=d.get("initiator", ""), created_at=float(d.get("created_at") or time.time()),
                status=d.get("status", PENDING), assurance=d.get("assurance"),
                attempt=int(d.get("attempt") or 1), consent_url=d.get("consent_url"),
                approved_at=d.get("approved_at"), extra=dict(d.get("extra") or {}),
                reference=d.get("reference"), consumed_at=d.get("consumed_at"))
        if d.get("ciba"):
            c.ciba = _ciba.CibaRequest.rehydrate(d["ciba"])
        return c


class CeremonyStore(Protocol):
    """Where in-flight ceremonies live. The default is in-memory; a deployment wraps it with
    something durable via :attr:`Hooks.persist` / :attr:`Hooks.rehydrate`."""

    def get(self, code: str) -> Optional[Ceremony]: ...        # noqa: E704
    def put(self, c: Ceremony) -> None: ...                     # noqa: E704
    def find_live(self, subject: str, txn_hash: str, now: Optional[float] = None) -> Optional[Ceremony]: ...   # noqa: E704,E501


class MemoryStore:
    def __init__(self) -> None:
        self._d: Dict[str, Ceremony] = {}
        self._lock = threading.Lock()

    def get(self, code: str) -> Optional[Ceremony]:
        with self._lock:
            return self._d.get(code)

    def put(self, c: Ceremony) -> None:
        with self._lock:
            self._d[c.code] = c

    def find_live(self, subject: str, txn_hash: str, now: Optional[float] = None) -> Optional[Ceremony]:
        with self._lock:
            return self._find_live_locked(subject, txn_hash, now)

    def _find_live_locked(self, subject: str, txn_hash: str, now: Optional[float]) -> Optional[Ceremony]:
        now = now if now is not None else time.time()
        for c in self._d.values():
            if c.subject == subject and c.txn_hash == txn_hash and c.is_live(now):
                return c
        return None

    def put_if_no_live(self, c: Ceremony, now: Optional[float] = None) -> Optional[Ceremony]:
        """Atomically: if a live ceremony for ``c``'s (subject, txn_hash) exists, return it and store
        nothing; otherwise store ``c`` and return ``None``. Closes the find-then-put race two
        concurrent resolves of the same instruction would otherwise both win."""
        with self._lock:
            live = self._find_live_locked(c.subject, c.txn_hash, now)
            if live is not None:
                return live
            self._d[c.code] = c
            return None

    def discard(self, code: str) -> None:
        """Drop a ceremony that was claimed but never raised (the push channel was never reached)."""
        with self._lock:
            self._d.pop(code, None)


def _claim(store: CeremonyStore, lock: threading.Lock, c: Ceremony, now: float) -> Optional[Ceremony]:
    """Insert ``c`` unless a live ceremony for the same (subject, txn_hash) already exists, as ONE
    atomic step. Uses the store's own ``put_if_no_live`` when it has one (so resolvers sharing a store
    are covered); otherwise the resolver's lock serialises the find and the put."""
    atomic = getattr(store, "put_if_no_live", None)
    if callable(atomic):
        return atomic(c, now)
    with lock:
        live = store.find_live(c.subject, c.txn_hash, now)
        if live is not None:
            return live
        store.put(c)
        return None


def _unclaim(store: CeremonyStore, c: Ceremony) -> None:
    """Release a claimed ceremony that was never raised, so it neither dedupes nor counts as an
    attempt. Stores without ``discard`` get it marked EXPIRED instead."""
    discard = getattr(store, "discard", None)
    if callable(discard):
        discard(c.code)
    else:
        c.status = EXPIRED
        store.put(c)


def _check_resume(cer: Ceremony, now: float, max_age: Optional[float], noun: str) -> Optional[str]:
    """Shared single-use and freshness checks for verify_resume; a reason string when refused."""
    if cer.consumed_at is not None:
        return f"{noun} approval has already been used"
    if max_age is not None:
        approved = cer.approved_at if cer.approved_at is not None else cer.created_at
        if now - float(approved) > max_age:
            return f"{noun} approval is older than {max_age:g}s"
    return None


# ---- deployment hooks ---------------------------------------------------------------------------
@dataclass
class Hooks:
    """The deployment-specific edges of a ceremony. Every hook is optional; a missing hook means
    "this deployment has no such thing" and the resolver behaves accordingly.

    ``channel_for(subject) -> CHANNEL_DEVICE | CHANNEL_WEB | CHANNEL_LOCAL``
        Which channel can carry an authorisation request to this human right now. Fail CLOSED to
        ``CHANNEL_LOCAL``: never assume a device exists.
    ``already_covered(subject, instruction) -> Optional[str]``
        Ask the same question the PDP will: is there ALREADY an authorisation on record that covers
        this instruction? Return its assurance (truthy) if so — the challenge is stale and no
        ceremony is needed. Return ``None`` otherwise.
    ``persist(ceremony)`` / ``rehydrate(code) -> Optional[dict]``
        Durable storage for the in-flight ceremony (a deploy mid-approval must not lose it). The
        rehydrate hook returns a dict in :meth:`Ceremony.to_dict` shape, or ``None``.
    ``find_live_persisted(subject, txn_hash) -> Optional[dict]``
        Dedupe across replicas/restarts: a live ceremony for the same instruction. Same dict shape.
    ``register_for_device(ceremony)``
        Publish the full instruction wherever the approver app resolves pushed codes. The push itself
        carries only the short code; without this the phone buzzes and shows nothing.
    ``consent_url_for(ceremony) -> str``
        CHANNEL_WEB: mint the URL the human completes in a browser.
    ``on_outcome(ceremony, status)``
        Terminal write: record approved/denied/expired where the PDP and the audit will find it.
    ``web_status(ceremony) -> str``
        CHANNEL_WEB: has the human completed the web consent? Returns a status word.
    ``proofing_start(ceremony) -> dict``
        IDENTITY_PROOFING: open a presentation request with the verifier for the doctype in
        ``ceremony.instruction``. Return at least ``{"session_id": …}``, plus whatever the holder
        needs to answer it — ``request_uri`` (the ``openid4vp://`` link a wallet opens app2app) for
        the cross-device path, ``dcApiRequest`` for a same-device browser picker. Raise to abort.
    ``proofing_status(ceremony) -> str``
        IDENTITY_PROOFING: has the credential been presented and verified? Returns a status word.
        This is the evidence for a proofing — NOT the CIBA tap (see :class:`ProofingResolver`).
    ``settle_seconds``
        After the AS says approved, hold PENDING this long so a stronger, out-of-band verdict from the
        device (a signature, a biometric) can land and be recorded FIRST. If it never lands,
        ``device-approved`` stands — honest, just lower.
    """
    channel_for: Optional[Callable[[str], str]] = None
    already_covered: Optional[Callable[[str, Dict[str, Any]], Optional[str]]] = None
    persist: Optional[Callable[[Ceremony], None]] = None
    rehydrate: Optional[Callable[[str], Optional[dict]]] = None
    find_live_persisted: Optional[Callable[[str, str], Optional[dict]]] = None
    register_for_device: Optional[Callable[[Ceremony], None]] = None
    consent_url_for: Optional[Callable[[Ceremony], str]] = None
    on_outcome: Optional[Callable[[Ceremony, str], None]] = None
    web_status: Optional[Callable[[Ceremony], str]] = None
    proofing_start: Optional[Callable[[Ceremony], Dict[str, Any]]] = None
    proofing_status: Optional[Callable[[Ceremony], str]] = None
    settle_seconds: float = 3.0
    log: Callable[[str], None] = lambda _m: None


class ChallengeResolver(Protocol):
    """The interface every resolver implements. Language ports declare this shape; reference
    implementations may ship in fewer languages than the parser does."""

    def resolve(self, challenge: Challenge, *, subject: str, instruction: Dict[str, Any],
                initiator: str, binding_message: Optional[str] = None) -> "Pending | Resolved | Unavailable": ...  # noqa: E704,E501

    def poll(self, code: str) -> Optional[PollResult]: ...   # noqa: E704


# ---- the CIBA resolver ---------------------------------------------------------------------------
class CibaResolver:
    """Resolve a resource-authorisation (or identity-proofing) challenge with a decoupled push.

    :param client: the configured :class:`.ciba.CibaClient`
    :param hooks: this deployment's edges
    :param store: in-process ceremony store (default :class:`MemoryStore`)
    :param code_prefix: reference-code prefix (``PAY``, ``MDL``, …) — a per-kind map is fine
    :param max_attempts: how many times the SAME instruction may be pushed and DENIED/EXPIRED
        within ``attempt_window`` seconds before the resolver refuses to push it again (a human who
        said no, or a policy that will never permit, must not become a push loop). Approved
        ceremonies do not count — a legitimate second identical payment, after the first consent was
        consumed, is a new ceremony.
    :param max_approval_age: seconds after approval during which :meth:`verify_resume` accepts it
        (default 300). ``None`` disables the age limit; the single-use rule still applies.

    The ``instruction`` dict may not carry a ``subject`` key (it is reserved for the subject the
    ceremony is bound to); :meth:`resolve` and :meth:`verify_resume` raise ``ValueError`` if it does.
    """

    kinds = (RESOURCE_AUTHORISATION, IDENTITY_PROOFING)

    def __init__(self, client: _ciba.CibaClient, hooks: Optional[Hooks] = None,
                 store: Optional[CeremonyStore] = None, *, code_prefix: Any = "PAY",
                 max_attempts: int = 1, attempt_window: float = 600.0,
                 clock: Callable[[], float] = time.time,
                 max_approval_age: Optional[float] = DEFAULT_MAX_APPROVAL_AGE):
        self.client = client
        self.hooks = hooks or Hooks()
        self.store = store or MemoryStore()
        self.code_prefix = code_prefix
        self.max_attempts = max_attempts
        self.attempt_window = attempt_window
        self.clock = clock
        self.max_approval_age = max_approval_age
        self._lock = threading.Lock()

    # ---- helpers ------------------------------------------------------------------------------
    def _prefix(self, kind: str) -> str:
        if isinstance(self.code_prefix, dict):
            return str(self.code_prefix.get(kind) or self.code_prefix.get("*") or "REQ")
        return str(self.code_prefix)

    def _load(self, code: str) -> Optional[Ceremony]:
        c = self.store.get(code)
        if c is None and self.hooks.rehydrate:
            d = self.hooks.rehydrate(code)
            if d:
                c = Ceremony.from_dict(d)
                self.store.put(c)
                self.hooks.log(f"ceremony {code} rehydrated")
        return c

    def _persist(self, c: Ceremony) -> None:
        self.store.put(c)
        if self.hooks.persist:
            try:
                self.hooks.persist(c)
            except Exception as exc:  # noqa: BLE001 — persistence must never block the push
                self.hooks.log(f"ceremony {c.code} persist failed: {exc}")

    def _pending(self, c: Ceremony, *, reused: bool = False) -> Pending:
        return Pending(code=c.code, kind=c.kind, channel=c.channel, interval=c.interval,
                       expires_in=c.expires_in, txn_hash=c.txn_hash, consent_url=c.consent_url,
                       detail=dict(c.instruction), attempt=c.attempt, reused=reused,
                       reference=c.reference)

    # ---- resolve ------------------------------------------------------------------------------
    def resolve(self, challenge: Challenge, *, subject: str, instruction: Dict[str, Any],
                initiator: str, binding_message: Optional[str] = None,
                scope: str = "openid") -> "Pending | Resolved | Unavailable":
        kind = challenge.type
        if kind not in self.kinds:
            return Unavailable(kind=kind, reason=f"CibaResolver does not resolve '{kind}' challenges")
        if not subject:
            return Unavailable(kind=kind, reason="no subject to push to (login_hint)")

        txn_hash = _bound_hash(subject, instruction)

        # 1) Is the challenge stale? Ask exactly what the PDP asks.
        if self.hooks.already_covered:
            try:
                assurance = self.hooks.already_covered(subject, instruction)
            except Exception as exc:  # noqa: BLE001
                assurance = None
                self.hooks.log(f"already_covered failed: {exc}")
            if assurance:
                return Resolved(code=None, kind=kind, assurance=str(assurance),
                                detail={"note": "an authorisation covering this instruction already stands"})

        # 2) Dedupe: an identical live ceremony (in-process, then persisted) is returned, not re-pushed.
        live = self.store.find_live(subject, txn_hash, self.clock())
        if live is None and self.hooks.find_live_persisted:
            try:
                d = self.hooks.find_live_persisted(subject, txn_hash)
            except Exception as exc:  # noqa: BLE001
                d = None
                self.hooks.log(f"find_live_persisted failed: {exc}")
            if d:
                live = Ceremony.from_dict(d)
                self.store.put(live)
        if live is not None:
            return self._pending(live, reused=True)

        # 3) Attempt cap: how many ceremonies has this instruction already had?
        prior = self._prior_attempts(subject, txn_hash)
        if prior >= self.max_attempts:
            return Unavailable(kind=kind, fallback="bubble_up",
                               reason=f"instruction already had {prior} ceremony attempt(s); not pushing again",
                               detail={"txn_hash": txn_hash, "attempts": prior})

        # 4) Which channel?
        channel = CHANNEL_LOCAL
        if self.hooks.channel_for:
            try:
                channel = self.hooks.channel_for(subject) or CHANNEL_LOCAL
            except Exception as exc:  # noqa: BLE001 — fail CLOSED
                self.hooks.log(f"channel_for failed ({exc}); assuming no device")
                channel = CHANNEL_LOCAL
        if channel != CHANNEL_DEVICE:
            return Unavailable(kind=kind, fallback="bubble_up" if channel == CHANNEL_LOCAL else channel,
                               reason="no paired authenticator for a decoupled push",
                               detail={"channel": channel, "txn_hash": txn_hash})

        # 5) Raise it. Claim the (subject, instruction) slot atomically first: two concurrent
        #    resolves that both missed the dedupe above must not both push.
        prefix = self._prefix(kind)
        code = new_handle(prefix)
        cer = Ceremony(code=code, kind=kind, channel=CHANNEL_DEVICE, subject=subject,
                       txn_hash=txn_hash, instruction=dict(instruction), initiator=initiator,
                       created_at=self.clock(), attempt=prior + 1,
                       extra={"scope": challenge.scope, "doctype": challenge.doctype},
                       reference=new_code(prefix))
        live = _claim(self.store, self._lock, cer, self.clock())
        if live is not None:
            return self._pending(live, reused=True)
        if self.hooks.register_for_device:
            try:
                self.hooks.register_for_device(cer)     # BEFORE the push: the phone resolves the code on arrival
            except Exception as exc:  # noqa: BLE001
                self.hooks.log(f"register_for_device failed for {code}: {exc}")
        try:
            cer.ciba = self.client.request(login_hint=subject,
                                           binding_message=binding_message or cer.reference,
                                           scope=scope)
        except _ciba.CibaError as exc:
            cer.status = EXPIRED
            cer.extra["push_error"] = str(exc)
            self._persist(cer)
            return Unavailable(kind=kind, fallback="bubble_up", reason=f"push failed: {exc}",
                               detail={"code": code, "txn_hash": txn_hash})
        self._persist(cer)
        self.hooks.log(f"ceremony {cer.reference} pushed to {subject} (auth_req_id={cer.ciba.auth_req_id[:8]}…, "
                       f"interval={cer.ciba.interval}s, expires_in={cer.ciba.expires_in}s)")
        return self._pending(cer)

    def _prior_attempts(self, subject: str, txn_hash: str) -> int:
        """Failed (denied/expired) ceremonies for this instruction inside the attempt window.
        Only the in-process store is enumerable; a deployment wanting cross-replica counting can
        pre-load recent failures into the store via rehydrate."""
        n = 0
        store = self.store
        if isinstance(store, MemoryStore):
            cutoff = self.clock() - self.attempt_window
            with store._lock:  # noqa: SLF001 — same module
                for c in store._d.values():  # noqa: SLF001
                    if (c.subject == subject and c.txn_hash == txn_hash
                            and c.status in (DENIED, EXPIRED) and c.created_at >= cutoff):
                        n += 1
        return n

    # ---- poll ---------------------------------------------------------------------------------
    def poll(self, code: str) -> Optional[PollResult]:
        cer = self._load(code)
        if cer is None:
            return None
        now = self.clock()
        if cer.status in TERMINAL:
            return PollResult(code=code, status=cer.status, kind=cer.kind, assurance=cer.assurance,
                              elapsed=now - cer.created_at, interval=cer.interval,
                              detail={"txn_hash": cer.txn_hash})
        if cer.ciba is None:
            return PollResult(code=code, status=PENDING, kind=cer.kind, elapsed=now - cer.created_at,
                              interval=cer.interval)

        outcome = self.client.poll(cer.ciba)
        if outcome == APPROVED:
            # Settle window: let a stronger out-of-band verdict land first (see Hooks.settle_seconds).
            if not cer.settle_until:
                cer.settle_until = now + max(0.0, self.hooks.settle_seconds)
            if now < cer.settle_until and not cer.assurance:
                # Re-check durable state: the device surface may have written its verdict already.
                if self.hooks.rehydrate:
                    try:
                        d = self.hooks.rehydrate(code)
                        if d and d.get("assurance"):
                            cer.assurance = d["assurance"]
                    except Exception as exc:  # noqa: BLE001
                        self.hooks.log(f"rehydrate during settle failed: {exc}")
                if not cer.assurance:
                    return PollResult(code=code, status=PENDING, kind=cer.kind,
                                      elapsed=now - cer.created_at, interval=cer.interval,
                                      detail={"settling": True})
            cer.status = APPROVED
            cer.approved_at = now
            if not cer.assurance:
                cer.assurance = ASSURANCE_DEVICE_APPROVED
            self._finish(cer, APPROVED)
        elif outcome in (DENIED, EXPIRED):
            cer.status = outcome
            self._finish(cer, outcome)
        return PollResult(code=code, status=cer.status, kind=cer.kind, assurance=cer.assurance,
                          elapsed=now - cer.created_at, interval=cer.interval,
                          detail={"txn_hash": cer.txn_hash, "last_error": (cer.ciba.last_error or None)})

    def _finish(self, cer: Ceremony, status: str) -> None:
        self.store.put(cer)
        if self.hooks.on_outcome:
            try:
                self.hooks.on_outcome(cer, status)
            except Exception as exc:  # noqa: BLE001
                self.hooks.log(f"on_outcome({status}) failed for {cer.code}: {exc}")
        self.hooks.log(f"ceremony {cer.code} -> {status} (assurance={cer.assurance})")

    # ---- verify a resumed call against the approved instruction ------------------------------
    def verify_resume(self, code: str, *, subject: str, instruction: Dict[str, Any]) -> "tuple[bool, str]":
        """On a re-sent call carrying ``code``, confirm the ceremony is APPROVED and that the
        instruction NOW presented hashes to what was approved. Closes the argument-tampering seam:
        the resumed call is the one the human approved, byte for byte.

        An approval is SINGLE-USE: a successful call marks it consumed (and persists that through
        :attr:`Hooks.persist`), so presenting the same code again is refused. It is also refused once
        more than ``max_approval_age`` seconds have passed since approval. Single use is atomic
        within this process; across replicas it is only as strong as the deployment's persist /
        rehydrate store."""
        want = _bound_hash(subject, instruction)
        with self._lock:
            cer = self._load(code)
            if cer is None:
                return False, "unknown ceremony code"
            if cer.status != APPROVED:
                return False, f"ceremony is {cer.status}, not approved"
            if cer.subject != subject:
                return False, "ceremony subject does not match"
            if want != cer.txn_hash:
                return False, "instruction does not match what was approved"
            refused = _check_resume(cer, self.clock(), self.max_approval_age, "ceremony")
            if refused:
                return False, refused
            cer.consumed_at = self.clock()
            self._persist(cer)
        return True, cer.assurance or ASSURANCE_DEVICE_APPROVED


# ---- the web-consent resolver ------------------------------------------------------------------
class WebConsentResolver:
    """No device: hand the human a URL. The URL is minted by the deployment
    (:attr:`Hooks.consent_url_for`) — typically a page behind the AS's own login, so the person who
    completes it is provably the subject the agent is acting for — and completion is detected by
    :attr:`Hooks.web_status`.

    Assurance claimed on approval is :data:`ASSURANCE_WEB_CONSENT` — a browser interaction, not a
    device-signed one. Never more."""

    kinds = (RESOURCE_AUTHORISATION, IDENTITY_PROOFING)

    def __init__(self, hooks: Hooks, store: Optional[CeremonyStore] = None, *,
                 code_prefix: Any = "WEB", ttl_seconds: int = 300, interval: int = 3,
                 clock: Callable[[], float] = time.time):
        self.hooks = hooks
        self.store = store or MemoryStore()
        self.code_prefix = code_prefix
        self.ttl = ttl_seconds
        self.interval = interval
        self.clock = clock
        self._lock = threading.Lock()

    def resolve(self, challenge: Challenge, *, subject: str, instruction: Dict[str, Any],
                initiator: str, binding_message: Optional[str] = None) -> "Pending | Resolved | Unavailable":
        kind = challenge.type
        if kind not in self.kinds:
            return Unavailable(kind=kind, reason=f"WebConsentResolver does not resolve '{kind}'")
        if not self.hooks.consent_url_for:
            return Unavailable(kind=kind, reason="no consent_url_for hook configured")
        txn_hash = _bound_hash(subject, instruction)
        prefix = self.code_prefix.get(kind, "WEB") if isinstance(self.code_prefix, dict) else self.code_prefix
        cer = Ceremony(code=new_handle(str(prefix)), kind=kind, channel=CHANNEL_WEB, subject=subject,
                       txn_hash=txn_hash, instruction=dict(instruction), initiator=initiator,
                       created_at=self.clock(), extra={"expires_in": self.ttl, "interval": self.interval},
                       reference=new_code(str(prefix)))
        # Dedupe and insert as one step, so two concurrent resolves cannot both mint a URL.
        live = _claim(self.store, self._lock, cer, self.clock())
        if live is not None:
            return Pending(code=live.code, kind=kind, channel=CHANNEL_WEB, interval=self.interval,
                           expires_in=live.expires_in, txn_hash=txn_hash, consent_url=live.consent_url,
                           detail=dict(instruction), attempt=live.attempt, reused=True,
                           reference=live.reference)
        try:
            cer.consent_url = self.hooks.consent_url_for(cer)
        except BaseException:
            _unclaim(self.store, cer)
            raise
        self.store.put(cer)
        if self.hooks.persist:
            try:
                self.hooks.persist(cer)
            except Exception as exc:  # noqa: BLE001
                self.hooks.log(f"persist failed for {cer.code}: {exc}")
        return Pending(code=cer.code, kind=kind, channel=CHANNEL_WEB, interval=self.interval,
                       expires_in=self.ttl, txn_hash=txn_hash, consent_url=cer.consent_url,
                       detail=dict(instruction), reference=cer.reference)

    def poll(self, code: str) -> Optional[PollResult]:
        cer = self.store.get(code)
        if cer is None and self.hooks.rehydrate:
            d = self.hooks.rehydrate(code)
            if d:
                cer = Ceremony.from_dict(d)
                self.store.put(cer)
        if cer is None:
            return None
        now = self.clock()
        if cer.status not in TERMINAL:
            if not cer.is_live(now):
                cer.status = EXPIRED
            elif self.hooks.web_status:
                try:
                    st = self.hooks.web_status(cer)
                except Exception as exc:  # noqa: BLE001
                    st = PENDING
                    self.hooks.log(f"web_status failed for {code}: {exc}")
                if st in TERMINAL:
                    cer.status = st
                    if st == APPROVED:
                        cer.approved_at = now
                        cer.assurance = cer.assurance or ASSURANCE_WEB_CONSENT
            if cer.status in TERMINAL:
                self.store.put(cer)
                if self.hooks.on_outcome:
                    try:
                        self.hooks.on_outcome(cer, cer.status)
                    except Exception as exc:  # noqa: BLE001
                        self.hooks.log(f"on_outcome failed for {code}: {exc}")
        return PollResult(code=code, status=cer.status, kind=cer.kind, assurance=cer.assurance,
                          elapsed=now - cer.created_at, interval=self.interval,
                          detail={"txn_hash": cer.txn_hash, "consent_url": cer.consent_url})


# ---- the identity-proofing resolver ---------------------------------------------------------
class ProofingResolver:
    """Resolve an IDENTITY_PROOFING challenge: the policy wants a verified credential (an ISO
    18013-5 mDL, a PID) presented for this subject before the operation may proceed.

    Same asynchronous shape as :class:`CibaResolver`, but the evidence is different in a way that
    changes the protocol:

    * A CIBA approval means *a paired device tapped approve*. For a proofing that is worth nothing
      on its own — what the policy needs is a **credential presentation the verifier cryptographically
      checked**. So this resolver uses CIBA as a **push channel only**: it fires ``bc-auth`` to get the
      request onto the human's phone and then never redeems or polls the token endpoint. It polls the
      **verifier** (:attr:`Hooks.proofing_status`). The approval signal and the evidence are not the
      same event, and conflating them would let a tap stand in for a presentation.
    * The push carries only a short reference code, so the holder's app resolves the actual
      ``openid4vp://`` request by that code (:attr:`Hooks.register_for_device`). The code's PREFIX is
      therefore load-bearing: an approver app routes an ``MDL-…`` code to its wallet path and anything
      else to its payment path. Keep :paramref:`code_prefix` aligned with whatever the app expects.

    ``instruction`` is what the proofing is FOR — typically ``{"account": "savings", "doctype":
    "org.iso.18013.5.1.mDL"}``. It is hashed like any other instruction, so a proofing raised for one
    account is never silently reused to satisfy another, and :meth:`verify_resume` can check that the
    resumed operation is the one that was proofed.

    No assurance rung is claimed. The payment ladder (device-approved / device-signed /
    recognize-verified) describes *how a human authorised a transaction*; a proofing is a different
    kind of fact — a verified document — and its strength lives in the verifier's own record
    (doctype, method, checks). Reporting one as the other would overstate both.
    """

    kinds = (IDENTITY_PROOFING,)

    def __init__(self, hooks: Hooks, client: Optional[_ciba.CibaClient] = None,
                 store: Optional[CeremonyStore] = None, *, code_prefix: Any = "MDL",
                 ttl_seconds: int = 300, interval: int = 3, max_attempts: int = 1,
                 attempt_window: float = 600.0, clock: Callable[[], float] = time.time,
                 max_approval_age: Optional[float] = DEFAULT_MAX_APPROVAL_AGE):
        self.hooks = hooks
        self.client = client          # optional: without it, no push (local/DC-API paths only)
        self.store = store or MemoryStore()
        self.code_prefix = code_prefix
        self.ttl = ttl_seconds
        self.interval = interval
        self.max_attempts = max_attempts
        self.attempt_window = attempt_window
        self.clock = clock
        self.max_approval_age = max_approval_age   # see CibaResolver
        self._lock = threading.Lock()

    # ---- helpers --------------------------------------------------------------------------
    def _load(self, code: str) -> Optional[Ceremony]:
        c = self.store.get(code)
        if c is None and self.hooks.rehydrate:
            d = self.hooks.rehydrate(code)
            if d:
                c = Ceremony.from_dict(d)
                self.store.put(c)
        return c

    def _persist(self, c: Ceremony) -> None:
        self.store.put(c)
        if self.hooks.persist:
            try:
                self.hooks.persist(c)
            except Exception as exc:  # noqa: BLE001 — never block the ceremony
                self.hooks.log(f"proofing {c.code} persist failed: {exc}")

    def _prior_failures(self, subject: str, txn_hash: str) -> int:
        n = 0
        if isinstance(self.store, MemoryStore):
            cutoff = self.clock() - self.attempt_window
            with self.store._lock:  # noqa: SLF001 — same module
                for c in self.store._d.values():  # noqa: SLF001
                    if (c.subject == subject and c.txn_hash == txn_hash
                            and c.status in (DENIED, EXPIRED) and c.created_at >= cutoff):
                        n += 1
        return n

    # ---- resolve --------------------------------------------------------------------------
    def resolve(self, challenge: Challenge, *, subject: str, instruction: Dict[str, Any],
                initiator: str, binding_message: Optional[str] = None,
                scope: str = "openid") -> "Pending | Resolved | Unavailable":
        kind = challenge.type
        if kind not in self.kinds:
            return Unavailable(kind=kind, reason=f"ProofingResolver does not resolve '{kind}' challenges")
        if not subject:
            return Unavailable(kind=kind, reason="no subject to proof")
        if not self.hooks.proofing_start:
            return Unavailable(kind=kind, reason="no proofing_start hook configured (no verifier)")

        instruction = dict(instruction)
        instruction.setdefault("doctype", challenge.doctype or "")
        txn_hash = _bound_hash(subject, instruction)

        # 1) Is the challenge stale? Ask what the PDP asks: is a proofing already on record
        #    for this subject and this account?
        if self.hooks.already_covered:
            try:
                have = self.hooks.already_covered(subject, instruction)
            except Exception as exc:  # noqa: BLE001
                have = None
                self.hooks.log(f"proofing already_covered failed: {exc}")
            if have:
                return Resolved(code=None, kind=kind, assurance=str(have),
                                detail={"note": "a verified proofing already covers this operation"})

        # 2) Dedupe — one live presentation request per (subject, instruction). A second push
        #    would put two wallet links on the phone for the same thing.
        live = self.store.find_live(subject, txn_hash, self.clock())
        if live is None and self.hooks.find_live_persisted:
            try:
                d = self.hooks.find_live_persisted(subject, txn_hash)
            except Exception as exc:  # noqa: BLE001
                d = None
                self.hooks.log(f"proofing find_live_persisted failed: {exc}")
            if d:
                live = Ceremony.from_dict(d)
                self.store.put(live)
        if live is not None:
            return self._reused(live, txn_hash)

        prior = self._prior_failures(subject, txn_hash)
        if prior >= self.max_attempts:
            return Unavailable(kind=kind, fallback="bubble_up",
                               reason=f"proofing already failed {prior} time(s) for this operation",
                               detail={"txn_hash": txn_hash})

        # 3) Which channel can carry the request? A wallet presentation needs EITHER a paired
        #    device (push the openid4vp link to it) or a browser on the holder's own device (the
        #    Digital Credentials API picker). An agent has neither locally, so CHANNEL_LOCAL means
        #    "hand this back to whatever has a browser" — never a QR to nowhere.
        channel = CHANNEL_LOCAL
        if self.hooks.channel_for:
            try:
                channel = self.hooks.channel_for(subject) or CHANNEL_LOCAL
            except Exception as exc:  # noqa: BLE001 — fail CLOSED
                self.hooks.log(f"proofing channel_for failed ({exc}); assuming no device")
                channel = CHANNEL_LOCAL
        if channel != CHANNEL_DEVICE:
            return Unavailable(kind=kind, fallback="bubble_up",
                               reason="no paired authenticator to receive the presentation request",
                               detail={"channel": channel, "txn_hash": txn_hash,
                                       "doctype": instruction.get("doctype")})
        if self.client is None:
            return Unavailable(kind=kind, fallback="bubble_up",
                               reason="no CIBA client configured to push the presentation request")

        # 4) Open the presentation request with the verifier FIRST — if the verifier is down there
        #    is nothing for the phone to open, and a push would be a dead end.
        #    The (subject, instruction) slot is claimed atomically first so two concurrent resolves
        #    cannot both open a session and push.
        prefix = (self.code_prefix.get(kind, "MDL") if isinstance(self.code_prefix, dict)
                  else str(self.code_prefix))
        code = new_handle(prefix)
        cer = Ceremony(code=code, kind=kind, channel=CHANNEL_DEVICE, subject=subject,
                       txn_hash=txn_hash, instruction=instruction, initiator=initiator,
                       created_at=self.clock(), attempt=prior + 1,
                       extra={"expires_in": self.ttl, "interval": self.interval,
                              "doctype": instruction.get("doctype")},
                       reference=new_code(prefix))
        live = _claim(self.store, self._lock, cer, self.clock())
        if live is not None:
            return self._reused(live, txn_hash)
        try:
            session = self.hooks.proofing_start(cer) or {}
        except Exception as exc:  # noqa: BLE001
            _unclaim(self.store, cer)
            return Unavailable(kind=kind, fallback="bubble_up",
                               reason=f"verifier could not open a presentation request: {exc}",
                               detail={"txn_hash": txn_hash})
        if not session.get("session_id"):
            _unclaim(self.store, cer)
            return Unavailable(kind=kind, fallback="bubble_up",
                               reason="verifier returned no session_id", detail={"txn_hash": txn_hash})
        cer.extra.update({k: v for k, v in session.items() if v is not None})

        # 5) Publish it where the holder's app resolves the pushed code, THEN push.
        if self.hooks.register_for_device:
            try:
                self.hooks.register_for_device(cer)
            except Exception as exc:  # noqa: BLE001
                self.hooks.log(f"proofing register_for_device failed for {code}: {exc}")
        try:
            # Push channel ONLY: we never poll or redeem this grant (see the class docstring).
            cer.ciba = self.client.request(login_hint=subject,
                                          binding_message=binding_message or cer.reference,
                                          scope=scope)
        except _ciba.CibaError as exc:
            cer.status = EXPIRED
            cer.extra["push_error"] = str(exc)
            self._persist(cer)
            return Unavailable(kind=kind, fallback="bubble_up", reason=f"push failed: {exc}",
                               detail={"code": code, "txn_hash": txn_hash})
        self._persist(cer)
        self.hooks.log(f"proofing {code} pushed to {subject} for {instruction.get('doctype')} "
                       f"(verifier session {session.get('session_id')})")
        return Pending(code=code, kind=kind, channel=CHANNEL_DEVICE, interval=self.interval,
                       expires_in=self.ttl, txn_hash=txn_hash, detail=dict(instruction),
                       reference=cer.reference)

    def _reused(self, live: Ceremony, txn_hash: str) -> Pending:
        return Pending(code=live.code, kind=live.kind, channel=live.channel, interval=self.interval,
                       expires_in=live.expires_in, txn_hash=txn_hash,
                       detail=dict(live.instruction), attempt=live.attempt, reused=True,
                       reference=live.reference)

    # ---- poll -----------------------------------------------------------------------------
    def poll(self, code: str) -> Optional[PollResult]:
        cer = self._load(code)
        if cer is None:
            return None
        now = self.clock()
        detail = {"txn_hash": cer.txn_hash, "doctype": cer.instruction.get("doctype"),
                  "session_id": cer.extra.get("session_id")}
        if cer.status in TERMINAL:
            return PollResult(code=code, status=cer.status, kind=cer.kind, assurance=cer.assurance,
                              elapsed=now - cer.created_at, interval=self.interval, detail=detail)
        if not cer.is_live(now):
            cer.status = EXPIRED
            self._finish(cer, EXPIRED)
            return PollResult(code=code, status=EXPIRED, kind=cer.kind,
                              elapsed=now - cer.created_at, interval=self.interval, detail=detail)
        if not self.hooks.proofing_status:
            return PollResult(code=code, status=PENDING, kind=cer.kind,
                              elapsed=now - cer.created_at, interval=self.interval, detail=detail)
        try:
            status = self.hooks.proofing_status(cer)
        except Exception as exc:  # noqa: BLE001 — a blip is not a verdict
            self.hooks.log(f"proofing_status failed for {code}: {exc}")
            return PollResult(code=code, status=PENDING, kind=cer.kind,
                              elapsed=now - cer.created_at, interval=self.interval, detail=detail)
        if status in TERMINAL:
            cer.status = status
            if status == APPROVED:
                cer.approved_at = now
            self._finish(cer, status)
        detail["claims"] = cer.extra.get("claims")
        return PollResult(code=code, status=cer.status, kind=cer.kind, assurance=cer.assurance,
                          elapsed=now - cer.created_at, interval=self.interval, detail=detail)

    def _finish(self, cer: Ceremony, status: str) -> None:
        self.store.put(cer)
        if self.hooks.on_outcome:
            try:
                self.hooks.on_outcome(cer, status)
            except Exception as exc:  # noqa: BLE001
                self.hooks.log(f"proofing on_outcome({status}) failed for {cer.code}: {exc}")
        self.hooks.log(f"proofing {cer.code} -> {status}")

    def verify_resume(self, code: str, *, subject: str, instruction: Dict[str, Any]) -> "tuple[bool, str]":
        """On a re-sent operation carrying ``code``, confirm the presentation was verified and that
        it was for THIS operation — a proofing of one account must not wave through another.

        Single-use and age-limited exactly like :meth:`CibaResolver.verify_resume`."""
        if SUBJECT_KEY in instruction:
            raise ValueError(f"instruction must not contain the reserved key {SUBJECT_KEY!r}")
        with self._lock:
            cer = self._load(code)
            if cer is None:
                return False, "unknown proofing code"
            if cer.status != APPROVED:
                return False, f"proofing is {cer.status}, not verified"
            if cer.subject != subject:
                return False, "proofing subject does not match"
            want = dict(instruction)
            want.setdefault("doctype", cer.instruction.get("doctype", ""))
            if _bound_hash(subject, want) != cer.txn_hash:
                return False, "this operation is not what was proofed"
            refused = _check_resume(cer, self.clock(), self.max_approval_age, "proofing")
            if refused:
                return False, refused
            cer.consumed_at = self.clock()
            self._persist(cer)
        return True, cer.instruction.get("doctype") or "verified"
