"""Pluggable sources for a workload's SPIFFE JWT-SVID — the infra-identity input to attestation
bootstrapping (:class:`~client_attestation_sdk.issuance.AttestationIssuanceClient`).

A ``SvidSource`` answers one question: *given an audience, hand me this workload's JWT-SVID.* The default
:class:`SpireWorkloadApiSvidSource` fetches it from a real SPIRE agent over the Workload API; the others
cover dev, tests, and the in-process :class:`~client_attestation_sdk.spiffe.SpiffeAgent`.
"""
from __future__ import annotations

import subprocess
from typing import Protocol, runtime_checkable

from . import _http


@runtime_checkable
class SvidSource(Protocol):
    """Anything that can produce a compact JWT-SVID for an audience."""

    def fetch(self, audience: str) -> str: ...


class StaticSvidSource:
    """A fixed, pre-fetched SVID — for tests, or when the caller already holds one."""

    def __init__(self, svid: str):
        self._svid = svid

    def fetch(self, audience: str) -> str:
        return self._svid


class HttpSvidSource:
    """GET a URL returning ``{"svid": "<jwt>"}`` — e.g. the demo harness ``/dev/svid`` endpoint.

    For development and testing only. It trusts whatever the URL returns and the endpoint has no caller
    authentication, so anyone who can reach it can obtain the workload's SVID. In production use a SPIRE,
    file or cloud source.

    **Experimental** (see docs/api.md): a development and test source with no caller authentication.
    """

    def __init__(self, url: str):
        self._url = url

    def fetch(self, audience: str) -> str:
        body = _http.json_ok(_http.request("GET", self._url, timeout=20), "SVID endpoint")
        return _http.require(body, "svid", "SVID endpoint response")


class SpireWorkloadApiSvidSource:
    """**Default source.** Fetch a JWT-SVID from a real SPIRE agent's Workload API via the ``spire-agent``
    CLI (``spire-agent api fetch jwt -audience <aud> -socketPath <sock>``). Swap for a native Workload API
    client (py-spiffe) by implementing :class:`SvidSource` if you prefer no subprocess.

    **Experimental** (see docs/api.md): it shells out to the spire-agent CLI, and its constructor will
    change when it moves to the Workload API socket.
    """

    def __init__(self, socket_path: str = "/tmp/spire-agent/public/api.sock", spire_agent: str = "spire-agent"):
        self._socket = socket_path
        self._bin = spire_agent

    def fetch(self, audience: str) -> str:
        out = subprocess.run(
            [self._bin, "api", "fetch", "jwt", "-audience", audience, "-socketPath", self._socket],
            capture_output=True, text=True, timeout=30)
        for line in out.stdout.splitlines():
            line = line.strip()
            if line.startswith("token("):          # "token(spiffe://…): eyJ…"
                return line.split("):", 1)[1].strip()
            if line.count(".") == 2:               # a bare compact JWT line
                return line
        raise RuntimeError(f"could not parse SVID from spire-agent output:\n{out.stdout}\n{out.stderr}")


class SpiffeAgentSvidSource:
    """Adapts the dependency-free in-process :class:`~client_attestation_sdk.spiffe.SpiffeAgent` (a SPIRE
    agent stand-in) as a source, attesting the given selectors.

    **Experimental** (see docs/api.md): Python only; a stand-in for tests and demos.
    """

    def __init__(self, agent, selectors: dict):
        self._agent = agent
        self._selectors = selectors

    def fetch(self, audience: str) -> str:
        return self._agent.fetch_jwt_svid(self._selectors, audience).token
