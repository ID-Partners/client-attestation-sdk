"""Agent-side handling of a policy enforcement point's AUTHORIZATION CHALLENGES.

When a PEP will not let a call proceed as presented, it does not simply deny — it says what would
make the call permissible: an authenticated user, a specific authorisation for THIS instruction, a
verified credential, a consent, a lodged intent. This package is the client half of that
conversation:

* :func:`parse_challenge` — turn whatever the PEP said (REST status + ``WWW-Authenticate`` + body,
  a JSON-RPC error, an MCP tool result) into one typed :class:`Challenge`. Pure; vector-pinned across
  language ports.
* :class:`CibaClient` — the OpenID CIBA client: raise a decoupled push to the human's authenticator
  and poll for the answer at the AS's cadence (the pacing rules are the part everyone gets wrong).
* :class:`CibaResolver` / :class:`WebConsentResolver` — the ceremony state machines: dedupe, channel
  choice, push, settle, terminal record, and verification that a resumed call matches what the human
  approved. Deployment edges (directories, device registries) are injected via :class:`Hooks`.

Vocabulary is fixed in :mod:`.challenge` (challenge types) and :mod:`.resolver` (statuses,
channels, assurance rungs the resolver may claim).

This package is **Experimental** (see docs/api.md): it exists only in Python, and its names may change in
any minor release. The default CIBA transport (``ciba.urllib_http``) and the ceremony code generators
(``resolver.new_code``, ``resolver.new_handle``) are not exported here; they are internal.
"""
from . import challenge as _challenge
from . import ciba as _ciba
from . import resolver as _resolver
from .challenge import (
    AUTHN, CHALLENGE_TYPES, CONSENT, IDENTITY_PROOFING, INTENT, RESOURCE_AUTHORISATION,
    Challenge, parse_challenge, parse_www_authenticate,
)
from .ciba import (
    APPROVED, AUDIENCE_ENDPOINT, AUDIENCE_ISSUER, CIBA_GRANT, DENIED, EXPIRED, PENDING,
    CibaClient, CibaError, CibaRequest, ClientAuth, PrivateKeyJwtAuth,
    private_key_jwt_assertion,
)
from .resolver import (
    ASSURANCE_DEVICE_APPROVED, ASSURANCE_WEB_CONSENT, CHANNEL_DEVICE, CHANNEL_LOCAL, CHANNEL_WEB,
    TERMINAL, Ceremony, CeremonyStore, ChallengeResolver, CibaResolver, Hooks, MemoryStore,
    Pending, PollResult, ProofingResolver, Resolved, Unavailable, WebConsentResolver,
    SUBJECT_KEY, transaction_hash,
)

__all__ = [
    # challenge
    "Challenge", "parse_challenge", "parse_www_authenticate", "CHALLENGE_TYPES",
    "AUTHN", "RESOURCE_AUTHORISATION", "CONSENT", "IDENTITY_PROOFING", "INTENT",
    # ciba
    "CibaClient", "CibaError", "CibaRequest", "ClientAuth", "PrivateKeyJwtAuth",
    "private_key_jwt_assertion", "CIBA_GRANT", "AUDIENCE_ISSUER", "AUDIENCE_ENDPOINT",
    "PENDING", "APPROVED", "DENIED", "EXPIRED",
    # resolver
    "ChallengeResolver", "CibaResolver", "WebConsentResolver", "ProofingResolver", "Hooks",
    "Ceremony", "CeremonyStore", "MemoryStore",
    "Pending", "Resolved", "Unavailable", "PollResult",
    "transaction_hash", "SUBJECT_KEY", "TERMINAL",
    "CHANNEL_DEVICE", "CHANNEL_WEB", "CHANNEL_LOCAL",
    "ASSURANCE_DEVICE_APPROVED", "ASSURANCE_WEB_CONSENT",
]
__version__ = "1.1.0"
