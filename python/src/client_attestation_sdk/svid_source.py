"""Pluggable sources for a workload's SPIFFE JWT-SVID — the infra-identity input to attestation
bootstrapping (:class:`~client_attestation_sdk.issuance.AttestationIssuanceClient`).

A ``SvidSource`` answers one question: *given an audience, hand me this workload's JWT-SVID.* The default
:class:`SpireWorkloadApiSvidSource` fetches it from a real SPIRE agent over the Workload API; the others
cover dev, tests, and the in-process :class:`~client_attestation_sdk.spiffe.SpiffeAgent`.
"""
from __future__ import annotations

import os
import re
import selectors
import subprocess
import threading
from typing import Protocol, runtime_checkable

from . import _http
from .token_validator import _strict


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
        """Return the first JWT-SVID the agent prints on stdout. Raises
        :class:`~client_attestation_sdk.evidence.EvidenceNotFound` if there is none. At most 1 MiB of stdout
        is read: an agent that prints more is killed and ``RuntimeError`` is raised. The agent's stderr is
        discarded, never read as output or held in memory. An agent that has not exited within 30 seconds
        is killed and :class:`subprocess.TimeoutExpired` is raised.

        The agent's exit decides the outcome, as in the other ports: once it has exited, stdout is read for
        at most 250 ms more (a helper the agent started can inherit the pipe and hold it open), then the
        pipe is closed. On exit status 0, what was read is parsed; on any other status ``RuntimeError`` is
        raised. A helper holding stdout never turns a success into a failure, and never keeps ``fetch``
        waiting longer than that."""
        args = [self._bin, "api", "fetch", "jwt", "-audience", audience, "-socketPath", self._socket]
        raw, returncode = _run_capped(args, _SPIRE_AGENT_TIMEOUT, _SPIRE_AGENT_MAX_OUTPUT)
        if raw is None:
            raise RuntimeError(f"spire-agent fetch failed: output is larger than {_SPIRE_AGENT_MAX_OUTPUT} bytes")
        if returncode != 0:
            raise RuntimeError(f"spire-agent fetch failed: exit status {returncode}")
        stdout = raw.decode("utf-8", "replace")
        svid = _parse_spire_jwt_output(stdout)
        if svid:
            return svid
        from .evidence import EvidenceNotFound  # evidence imports this module
        # The output may hold a token or bundle that failed to parse, so the error gives only its size. Lines
        # are counted by LF alone, as in the other ports (splitlines would also split on CR, VT, FF and more).
        lines = stdout.count("\n") + (1 if stdout and not stdout.endswith("\n") else 0)
        raise EvidenceNotFound(
            f"could not parse a JWT-SVID from spire-agent output ({len(stdout.encode())} bytes, "
            f"{lines} lines; not shown)")


_SPIRE_AGENT_TIMEOUT = 30
_SPIRE_AGENT_MAX_OUTPUT = 1 << 20   # the most stdout read from spire-agent, as in the other ports
# How long stdout is still read after spire-agent has exited, as in the other ports. A helper the agent
# started can inherit the pipe and hold it open; after this the pipe is closed.
_SPIRE_AGENT_STDOUT_GRACE = 0.25
_POLL_INTERVAL = 0.05   # how often the reader checks whether it should stop


def _run_capped(args: list, timeout: float, max_bytes: int) -> "tuple[bytes | None, int]":
    """Run ``args`` with stdin and stderr on the null device and return (stdout, exit status). stdout is read
    on a separate thread so a chatty agent can't block the wait; past ``max_bytes`` the process is killed and
    stdout is ``None``. A process still running after ``timeout`` seconds is killed and
    :class:`subprocess.TimeoutExpired` raised, without any of its output.

    The process's exit decides: once it has exited, stdout is read for at most ``_SPIRE_AGENT_STDOUT_GRACE``
    seconds more, then the reader stops and closes the pipe, and what was read so far is returned. A helper
    that inherited the pipe can keep it open, but never keeps this call waiting longer than that."""
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    lock = threading.Lock()   # guards kept, over and stop between the reader and this thread
    kept = bytearray()
    state = {"over": False, "stop": False}

    def keep(chunk: bytes) -> bool:
        """Add a chunk; False once the reader should stop."""
        with lock:
            if state["stop"]:
                return False
            if len(kept) + len(chunk) > max_bytes:
                state["over"] = True
                kept.clear()
                proc.kill()
                return False
            kept.extend(chunk)
            return True

    def drain():  # owns the pipe: only this thread reads or closes it
        selector = None
        try:
            fd = proc.stdout.fileno()
            if os.name == "posix":   # Windows can't select on a pipe: there, plain blocking reads
                selector = selectors.DefaultSelector()
                selector.register(fd, selectors.EVENT_READ)
            while True:
                if selector is not None and not selector.select(_POLL_INTERVAL):
                    with lock:
                        if state["stop"]:
                            return
                    continue
                chunk = os.read(fd, 65536)
                if not chunk or not keep(chunk):
                    return
        except (OSError, ValueError):
            return
        finally:
            if selector is not None:
                selector.close()
            proc.stdout.close()

    reader = threading.Thread(target=drain, name="spire-agent-output", daemon=True)
    reader.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _stop(proc, lock, state)
        raise subprocess.TimeoutExpired(args, timeout) from None
    except BaseException:   # e.g. KeyboardInterrupt: don't leave the agent running
        _stop(proc, lock, state)
        raise
    # The agent has exited. What it wrote is in the pipe; give the reader the grace period to finish, then
    # take what it has and stop it, whether or not a helper still holds the pipe open.
    reader.join(_SPIRE_AGENT_STDOUT_GRACE)
    with lock:
        state["stop"] = True
        return (None if state["over"] else bytes(kept)), proc.returncode


def _stop(proc: subprocess.Popen, lock: threading.Lock, state: dict) -> None:
    """Kill the agent, reap it, and tell the reader to close the pipe."""
    with lock:
        state["stop"] = True
    proc.kill()
    proc.wait()


_SECTION = re.compile(r"(token|hint|bundle)\(.*?\):(.*)", re.DOTALL)
_B64URL = re.compile(r"[A-Za-z0-9_-]+")
_SPACE = " \t\r"   # the only characters ignored around a line or value, in every port: not a BOM or NBSP


def _parse_spire_jwt_output(out: str) -> str | None:
    """The first JWT-SVID in the output of ``spire-agent api fetch jwt``, or ``None``.

    SPIRE prints each SVID as ``token(<spiffe id>):`` with the JWT on the next, tab-indented line, then
    ``hint(<spiffe id>):`` and ``bundle(<trust domain>):`` sections laid out the same way. The single-line
    form ``token(<spiffe id>): <jwt>`` and a bare JWT line are accepted too. Only a syntactically valid
    compact JWS is returned; the values of hint and bundle sections are skipped. A label with no value takes
    the next line as its value only if that line is not itself a label. Only ASCII space, tab and CR around a
    line or value are ignored.
    """
    lines = out.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i].strip(_SPACE)
        section = _SECTION.fullmatch(line)
        if section is None:
            if _is_compact_jws(line):        # a bare compact JWT line
                return line
        else:
            value = section.group(2).strip(_SPACE)
            if not value and i + 1 < len(lines):  # the value is on the next line, unless that is another label
                following = lines[i + 1].strip(_SPACE)
                if _SECTION.fullmatch(following) is None:
                    i += 1
                    value = following
            if section.group(1) == "token" and _is_compact_jws(value):
                return value
        i += 1
    return None


def _is_compact_jws(s: str) -> bool:
    """Three non-empty base64url segments whose first is the canonical encoding of a strict JSON object (the
    token validator's reader) with a non-empty string ``alg``. It verifies nothing; it tells a JWT from a
    version string or log line."""
    parts = s.split(".")
    if len(parts) != 3 or not all(_B64URL.fullmatch(p) for p in parts):
        return False
    try:
        header = _strict.parse_object(_strict.b64url_decode(parts[0]), "header")
    except _strict.Malformed:
        return False
    return isinstance(header.get("alg"), str) and bool(header["alg"])


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
