"""Lightweight SPIFFE Workload API — the infrastructure-layer source of a workload's identity and
attested attributes, bridged into the OIDF client attestation.

This is a standards-shaped, dependency-free stand-in for a SPIRE **agent**'s Workload API
(``FetchJWTSVID``). It gives a workload:

* a **SPIFFE ID** — ``spiffe://<trust-domain>/<path>`` — its stable identity;
* a **JWT-SVID** — a JWT signed by the trust domain, ``sub`` = SPIFFE ID, ``aud``/``exp`` per the
  SPIFFE JWT-SVID spec (SVIDs are intentionally minimal); and
* its **attested attributes** — the selectors/metadata the agent resolved for that workload
  (region, entitlements, workload type, …), which real SVIDs keep server-side rather than in the token.

The agent attests a workload by matching the selectors it presents against registration entries — the
same model as SPIRE. The resulting SPIFFE ID + attributes become the ``workload`` claim of an OIDF
Client Attestation (``ClientAttestationBuilder.workload(...)``), so the Authorization Server discloses
**SPIFFE-attested** workload attributes rather than static federation metadata. Only the transport
(in-process here, a Unix-domain Workload API socket in real SPIRE) differs.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

import jwt

from .keys import SigningKeyPair, require_text, sign_compact

JWT_SVID_TYP = "JWT"  # SPIFFE JWT-SVID: `typ`, if present, MUST be "JWT" or "JOSE"


def parse_spiffe_id(spiffe_id: str) -> tuple[str, str]:
    """Split ``spiffe://<trust-domain>/<path>`` into ``(trust_domain, path)``. Path may be empty."""
    require_text(spiffe_id, "spiffe_id")
    if not spiffe_id.startswith("spiffe://"):
        raise ValueError(f"not a SPIFFE ID (must start with spiffe://): {spiffe_id}")
    rest = spiffe_id[len("spiffe://"):]
    domain, _, path = rest.partition("/")
    if not domain:
        raise ValueError(f"SPIFFE ID has no trust domain: {spiffe_id}")
    return domain, path


@dataclass(frozen=True)
class RegistrationEntry:
    """A workload registration: which selectors identify it, the SPIFFE ID it earns, and the attested
    attributes to attach. Mirrors a SPIRE registration entry."""

    selectors: dict
    spiffe_id: str
    attributes: dict = field(default_factory=dict)

    def matches(self, presented: dict) -> bool:
        """True when every selector required by this entry is satisfied by the workload's presented
        selectors (SPIRE semantics: entry selectors are a subset of the workload's)."""
        return all(presented.get(k) == v for k, v in self.selectors.items())


@dataclass(frozen=True)
class JwtSvid:
    """A fetched JWT-SVID: the SPIFFE ID, the signed token, the workload's attested attributes, and
    validity. ``attributes`` is the bridge payload — the workload attributes to disclose."""

    spiffe_id: str
    token: str
    attributes: dict
    audience: str
    issued_at: int
    expires_at: int

    @property
    def trust_domain(self) -> str:
        return parse_spiffe_id(self.spiffe_id)[0]


class SpiffeAgent:
    """A lightweight SPIFFE Workload API (the SPIRE-agent analogue). Attests a workload by selector match
    and issues a JWT-SVID for its SPIFFE ID, alongside its attested attributes."""

    def __init__(self, trust_domain: str, signing_key: SigningKeyPair, entries: "list[RegistrationEntry] | None" = None):
        self.trust_domain = require_text(trust_domain, "trust_domain")
        self._key = signing_key
        self._entries: list[RegistrationEntry] = list(entries or [])

    def register(self, selectors: dict, spiffe_id: str, attributes: "dict | None" = None) -> "SpiffeAgent":
        """Add a registration entry. ``spiffe_id`` may be a bare path (joined to this trust domain) or a
        full ``spiffe://`` URI (which must be in this trust domain)."""
        if not spiffe_id.startswith("spiffe://"):
            spiffe_id = f"spiffe://{self.trust_domain}/{spiffe_id.lstrip('/')}"
        elif parse_spiffe_id(spiffe_id)[0] != self.trust_domain:
            raise ValueError(f"{spiffe_id} is not in trust domain {self.trust_domain}")
        self._entries.append(RegistrationEntry(dict(selectors), spiffe_id, dict(attributes or {})))
        return self

    def fetch_jwt_svid(self, selectors: dict, audience: str, ttl: int = 300) -> JwtSvid:
        """Attest the workload presenting ``selectors`` and mint a JWT-SVID for ``audience``. Raises if no
        registration entry matches (the workload is not attested)."""
        require_text(audience, "audience")
        entry = next((e for e in self._entries if e.matches(selectors or {})), None)
        if entry is None:
            raise PermissionError(f"no SPIFFE registration entry matches selectors {selectors!r}")
        iat = int(time.time())
        exp = iat + ttl
        claims = {"sub": entry.spiffe_id, "aud": [audience], "iat": iat, "exp": exp}
        token = sign_compact(claims, self._key, JWT_SVID_TYP, embed_jwk=False)
        return JwtSvid(entry.spiffe_id, token, dict(entry.attributes), audience, iat, exp)

    def trust_bundle(self) -> dict:
        """The JWKS a verifier uses to check JWT-SVIDs from this trust domain."""
        jwk = self._key.public_jwk()
        jwk.setdefault("use", "sig")
        jwk.setdefault("alg", self._key.algorithm)
        return {"keys": [jwk]}


def verify_jwt_svid(token: str, trust_bundle: dict, audience: str, trust_domain: "str | None" = None) -> dict:
    """Verify a JWT-SVID against a trust bundle (signature, ``aud``, ``exp``, and that ``sub`` is a SPIFFE
    ID in ``trust_domain`` if given). Returns the validated claims."""
    header = jwt.get_unverified_header(token)
    kid, alg = header.get("kid"), header.get("alg")
    keys = trust_bundle.get("keys", [])
    jwk = next((k for k in keys if k.get("kid") == kid), keys[0] if keys else None)
    if jwk is None:
        raise ValueError("no key in trust bundle to verify the JWT-SVID")
    verifying_key = jwt.PyJWK.from_dict({**jwk, "alg": jwk.get("alg", alg)}).key
    claims = jwt.decode(token, verifying_key, algorithms=[alg], audience=audience,
                        options={"require": ["sub", "exp"]})
    domain, _ = parse_spiffe_id(claims["sub"])
    if trust_domain and domain != trust_domain:
        raise ValueError(f"JWT-SVID sub {claims['sub']} is not in trust domain {trust_domain}")
    return claims


def to_workload_claim(svid: JwtSvid) -> dict:
    """Build the ``workload`` claim for a Client Attestation from a JWT-SVID — the SPIFFE identity, the
    attested attributes, and the SVID itself so the AS can independently verify the SPIFFE attestation.

    Use as ``ClientAttestationBuilder(...).workload(to_workload_claim(svid))``.
    """
    return {
        "attested_by": "spiffe",
        "spiffe_id": svid.spiffe_id,
        "attributes": dict(svid.attributes),
        "svid": svid.token,
    }
