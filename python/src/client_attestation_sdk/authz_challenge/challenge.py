"""Normalise a policy enforcement point's authorization CHALLENGE into one typed object.

A PEP that will not let a call proceed as presented can say so in more than one way, and the ways
do not agree with each other:

* **REST**: an HTTP status + an RFC 6750 ``WWW-Authenticate: Bearer error="…"`` header + a JSON body
  (``{"error": "insufficient_scope", "scope": "…", "reason": "…", "pep": "…"}``).
* **JSON-RPC** (an MCP edge): HTTP 200 carrying ``{"error": {"code": -32401, "message": "…",
  "data": {"authz_challenge": {…}}}}`` — the ``data`` member is the structured form; older PEPs put
  the same facts only in the prose ``message`` (``"insufficient_scope scope=… :: reason"``).
* **Tool result**: an MCP server that already translated the gateway's answer into a tool payload
  (``{"authorized": false, "insufficient_scope": true, "scope_required": "…"}``).

The status code alone cannot classify a challenge — this demo's PEPs answer 401 both for "no user
at all" and for "user present, scope missing", and a plain deny is 403 with no challenge in it. So the
first job of an agent-side SDK is *not* to resolve the challenge; it is to say, deterministically,
which one it is. That is what :func:`parse_challenge` does. It is pure (no I/O, no clock) so it can
be pinned by shared vectors across every language port.

The five challenge types are the demo's authorisation taxonomy — the same words the resource-authz
directory records use — so a challenge, the ceremony that resolves it, and the record it leaves
behind all agree on the term:

======================  ======================================================  =====================
type                    what the PEP is asking for                              distinguishing field
======================  ======================================================  =====================
``authn``               an authenticated end user (there is none)               ``acr_values``
``resource_authorisation``  a specific, fine-grained authorisation (RFC 9470)   ``scope``
``consent``             a coarse-grained agreement (reserved — no PEP signal)   —
``identity_proofing``   a verified-credential presentation (e.g. an mDL)        ``doctype``
``intent``              a lodged intent / Grant Management grant (reserved)     ``grant_id``
======================  ======================================================  =====================
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Optional

# ---- challenge types --------------------------------------------------------------------------
# String values match the resource-authorisation directory's AUTHZ_TYPE_* constants so records and
# challenges use one vocabulary. Do not rename without renaming the records.
AUTHN = "authn"
RESOURCE_AUTHORISATION = "resource_authorisation"
CONSENT = "consent"
IDENTITY_PROOFING = "identity_proofing"
INTENT = "intent"

CHALLENGE_TYPES = (AUTHN, RESOURCE_AUTHORISATION, CONSENT, IDENTITY_PROOFING, INTENT)

# ---- wire vocabulary ---------------------------------------------------------------------------
# RFC 6750 / RFC 9470 error codes and this demo's PEP-specific ones, mapped to a challenge type.
_ERROR_TO_TYPE = {
    # RFC 9470 §3: the RS wants a stronger / fresher user authentication.
    "insufficient_user_authentication": AUTHN,
    # Demo PEPs (Kong authzen-pdp, coaz-pep): no X-User-Token at all.
    "login_required": AUTHN,
    # RFC 6750 §3.1: the token lacks a scope the RS needs. Here: a specific authorisation.
    "insufficient_scope": RESOURCE_AUTHORISATION,
    # Demo PEPs: the customer has no verified identity-proofing record.
    "identity_verification_required": IDENTITY_PROOFING,
    # Reserved — no PEP emits these today; recognised so a future PEP needs no client change.
    "consent_required": CONSENT,
    "intent_required": INTENT,
}

# The legacy JSON-RPC prose forms a coaz-pep emitted before the structured `data` member existed.
#   "insufficient_scope scope=<scope> :: <reason>"
#   "identity_verification_required doctype=<doctype> :: <reason>"
_PROSE_RE = re.compile(
    r"^\s*(?P<error>insufficient_scope|identity_verification_required|login_required)"
    r"(?:\s+(?P<key>scope|doctype|acr_values)=(?P<value>\S+))?"
    r"(?:\s*::\s*(?P<reason>.*))?\s*$", re.DOTALL)

# RFC 6750 §3 auth-param grammar, permissively: key="value" or key=token, comma/space separated.
# The lookbehind stops a key starting in the middle of a token: without it a long run of token
# characters is retried from every offset, which is quadratic on an untrusted header.
_AUTH_PARAM_RE = re.compile(r'(?<![A-Za-z0-9_\-])([A-Za-z_][A-Za-z0-9_\-]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]+))')
# A bare token that is not a key: the auth-scheme that starts the next challenge (RFC 9110 §11.6.1).
_AUTH_SCHEME_RE = re.compile(r"(?<![^\s,])([!#$%&'*+.^_`|~0-9A-Za-z-]+)(?=[\s,]|$)")
_AUTH_PART_RE = re.compile(_AUTH_PARAM_RE.pattern + "|" + _AUTH_SCHEME_RE.pattern)

# Larger inputs are not read: a challenge is a few hundred bytes, and the JSON parser recurses.
_MAX_HEADER_CHARS = 8 * 1024
_MAX_BODY_CHARS = 64 * 1024


@dataclass
class Challenge:
    """One normalised authorization challenge.

    ``type`` is one of :data:`CHALLENGE_TYPES`. Exactly the fields that carry meaning for that type
    are set (``scope`` for a resource authorisation, ``doctype`` for identity proofing, ``acr_values``
    for authn); the rest are ``None``. ``error`` is the wire-level error code the PEP used; ``reason``
    is the policy's human-readable explanation; ``pep`` names which enforcement point answered
    (an audit convenience, not a protocol field). ``raw`` keeps the untouched source for callers
    that need something this model does not carry.
    """
    type: str
    error: str
    scope: Optional[str] = None
    doctype: Optional[str] = None
    acr_values: Optional[str] = None
    grant_id: Optional[str] = None
    reason: Optional[str] = None
    pep: Optional[str] = None
    source: str = "rest"          # "rest" | "jsonrpc" | "tool_result"
    raw: Any = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("raw", None)
        return {k: v for k, v in d.items() if v is not None}


def parse_www_authenticate(value: Optional[str]) -> dict:
    """Parse an RFC 6750 ``WWW-Authenticate: Bearer …`` header value into its auth-params.

    Returns ``{}`` for a missing header, a header with no Bearer challenge, or one over 8 KiB. When the
    header carries several challenges (``Bearer realm="api", DPoP algs="ES256"``) only the Bearer
    challenge's params are returned. Values are unquoted; backslash escapes inside quoted strings are
    resolved. Keys are lower-cased.
    """
    if not value or len(value) > _MAX_HEADER_CHARS:
        return {}
    scheme: Optional[str] = None
    out: dict = {}
    for m in _AUTH_PART_RE.finditer(value):
        if m.group(4) is not None:
            if scheme == "bearer":
                break           # the Bearer challenge ended where the next scheme starts
            scheme = m.group(4).lower()
            continue
        if scheme != "bearer":
            continue
        key = m.group(1).lower()
        quoted, bare = m.group(2), m.group(3)
        val = re.sub(r"\\(.)", r"\1", quoted) if quoted is not None else bare
        out[key] = val
    return out


def _from_error(error: Optional[str], fields: Mapping[str, Any], *, source: str, raw: Any) -> Optional[Challenge]:
    """Build a Challenge from a wire error code plus whichever fields came with it."""
    if not error:
        return None
    ctype = _ERROR_TO_TYPE.get(str(error).lower())
    if not ctype:
        return None
    return Challenge(
        type=ctype, error=str(error).lower(),
        scope=_s(fields.get("scope")),
        doctype=_s(fields.get("doctype")),
        acr_values=_s(fields.get("acr_values")),
        grant_id=_s(fields.get("grant_id")),
        reason=_s(fields.get("reason") or fields.get("error_description")),
        pep=_s(fields.get("pep")),
        source=source, raw=raw)


def _s(v: Any) -> Optional[str]:
    """A string field, or ``None``. A list of strings is joined with spaces (a scope array); any other
    type (an object, a number) is dropped rather than turned into its Python repr."""
    if isinstance(v, (list, tuple)) and all(isinstance(x, str) for x in v):
        v = " ".join(v)
    if not isinstance(v, str):
        return None
    v = v.strip()
    return v or None


def _lower_headers(headers: Optional[Mapping[str, str]]) -> dict:
    return {str(k).lower(): v for k, v in (headers or {}).items()}


def _json_body(body: Any) -> Any:
    if body is None:
        return None
    if isinstance(body, (bytes, bytearray, str)) and len(body) > _MAX_BODY_CHARS:
        return None
    if isinstance(body, (bytes, bytearray)):
        body = body.decode("utf-8", "replace")
    if isinstance(body, str):
        s = body.strip()
        if not s:
            return None
        try:
            return json.loads(s)
        except (ValueError, RecursionError):
            return s
    return body


def parse_challenge(status: Optional[int] = None,
                    headers: Optional[Mapping[str, str]] = None,
                    body: Any = None) -> Optional[Challenge]:
    """Classify a PEP response. Returns a :class:`Challenge`, or ``None`` if the response is not a
    challenge (a permit, a hard deny, a transport error, or something this parser does not know).

    Accepts any of the three wire forms described in the module docstring. Precedence when a
    response carries more than one signal:

    1. a JSON-RPC ``error.data.authz_challenge`` object (the structured form wins);
    2. a JSON body ``error`` code (REST) — the body is what carries ``scope``/``doctype``/``reason``;
    3. the ``WWW-Authenticate`` header's ``error`` auth-param;
    4. a JSON-RPC prose ``error.message`` in the legacy ``"<error> <key>=<value> :: <reason>"`` form;
    5. an MCP tool-result dict (``insufficient_scope`` / ``identity_proofing_required`` flags).

    A 403 with no challenge fields is a hard deny → ``None``. A 401 whose body/header carries no
    recognisable error is an ordinary "invalid token" → ``None`` (nothing an authorization ceremony
    can fix). ``status`` is advisory only; the parser never classifies on status alone.
    """
    hdrs = _lower_headers(headers)
    data = _json_body(body)
    raw = {"status": status, "headers": dict(hdrs), "body": data}

    # ---- JSON-RPC envelope ----------------------------------------------------------------------
    if isinstance(data, dict) and isinstance(data.get("error"), dict) and "code" in data["error"]:
        err = data["error"]
        # 1) structured
        d = err.get("data")
        if isinstance(d, dict):
            ac = d.get("authz_challenge") if isinstance(d.get("authz_challenge"), dict) else (
                d if d.get("type") in CHALLENGE_TYPES else None)
            if ac:
                ctype = ac.get("type")
                if ctype in CHALLENGE_TYPES:
                    return Challenge(
                        type=ctype, error=_s(ac.get("error")) or _default_error(ctype),
                        scope=_s(ac.get("scope")), doctype=_s(ac.get("doctype")),
                        acr_values=_s(ac.get("acr_values")), grant_id=_s(ac.get("grant_id")),
                        reason=_s(ac.get("reason")), pep=_s(ac.get("pep")),
                        source="jsonrpc", raw=raw)
        # 4) legacy prose
        m = _PROSE_RE.match(str(err.get("message") or ""))
        if m:
            fields: dict = {}
            if m.group("key"):
                fields[m.group("key")] = m.group("value")
            if m.group("reason"):
                fields["reason"] = m.group("reason").strip()
            return _from_error(m.group("error"), fields, source="jsonrpc", raw=raw)
        return None

    # ---- REST: JSON body error code, then WWW-Authenticate --------------------------------------
    www = parse_www_authenticate(hdrs.get("www-authenticate"))
    if isinstance(data, dict) and data.get("error"):
        merged = dict(www)
        merged.update({k: v for k, v in data.items() if v is not None})
        ch = _from_error(data.get("error"), merged, source="rest", raw=raw)
        if ch:
            return ch
    if www.get("error"):
        ch = _from_error(www.get("error"), www, source="rest", raw=raw)
        if ch:
            return ch

    # ---- MCP tool-result dict --------------------------------------------------------------------
    if isinstance(data, dict) and data.get("authorized") is False:
        if data.get("insufficient_scope"):
            return Challenge(type=RESOURCE_AUTHORISATION, error="insufficient_scope",
                             scope=_s(data.get("scope_required") or data.get("scope")),
                             reason=_s(data.get("policy_reason") or data.get("reason")),
                             pep=_s(data.get("pep")), source="tool_result", raw=raw)
        if data.get("identity_proofing_required"):
            return Challenge(type=IDENTITY_PROOFING, error="identity_verification_required",
                             doctype=_s(data.get("doctype")),
                             reason=_s(data.get("policy_reason") or data.get("reason")),
                             pep=_s(data.get("pep")), source="tool_result", raw=raw)
        if data.get("login_required") or data.get("error") == "login_required":
            return Challenge(type=AUTHN, error="login_required",
                             acr_values=_s(data.get("acr_values")),
                             reason=_s(data.get("policy_reason") or data.get("reason")),
                             pep=_s(data.get("pep")), source="tool_result", raw=raw)
    return None


def _default_error(ctype: str) -> str:
    for err, t in _ERROR_TO_TYPE.items():
        if t == ctype:
            return err
    return ctype
