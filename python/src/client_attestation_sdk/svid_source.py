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
import time
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
        :class:`~client_attestation_sdk.evidence.EvidenceNotFound` if there is none. The agent's stderr is
        discarded, never read as output or held in memory. An agent that has not exited within 30 seconds is
        killed and :class:`subprocess.TimeoutExpired` is raised.

        The agent's exit decides the outcome, as in the other ports. While the agent is running, more than
        1 MiB of stdout kills it and ``RuntimeError`` is raised; that includes what it wrote just before
        exiting, which is still in the pipe when its exit is seen. Once it has exited, stdout is read for at most
        250 ms more and at most 1 MiB in all (a helper the agent started can inherit the pipe and keep writing
        to it or hold it open), then the pipe is closed. On exit status 0 what was read is parsed; on any other
        status ``RuntimeError`` is raised. So output a helper writes after the agent has exited never turns a
        success into a failure, and never keeps ``fetch`` waiting longer than that. If reading stopped at the
        1 MiB or at the end of the 250 ms, the last line may be cut off, so a token is only taken from a line
        that ends in a newline.

        On Windows a pipe can't be polled, so stdout is read with plain blocking reads: ``fetch`` still
        returns after the 250 ms, but if a helper holds the pipe open, the reading thread (a daemon) and the
        pipe stay open until the helper exits or writes again, and output the agent writes past the 1 MiB just
        before it exits may be read either side of its exit."""
        args = [self._bin, "api", "fetch", "jwt", "-audience", audience, "-socketPath", self._socket]
        raw, returncode, complete = _run_capped(args, _SPIRE_AGENT_TIMEOUT, _SPIRE_AGENT_MAX_OUTPUT)
        if raw is None:
            raise RuntimeError(f"spire-agent fetch failed: output is larger than {_SPIRE_AGENT_MAX_OUTPUT} bytes")
        if returncode != 0:
            raise RuntimeError(f"spire-agent fetch failed: exit status {returncode}")
        stdout = raw.decode("utf-8", "replace")
        svid = _parse_spire_jwt_output(_complete_lines(stdout, complete))
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
# The most stdout read from spire-agent, as in the other ports. More while the agent is running fails the
# fetch; once it has exited, reading stops there.
_SPIRE_AGENT_MAX_OUTPUT = 1 << 20
# How long stdout is still read after spire-agent has exited, as in the other ports. A helper the agent
# started can inherit the pipe and hold it open; after this the pipe is closed.
_SPIRE_AGENT_STDOUT_GRACE = 0.25
_POLL_INTERVAL = 0.05   # how often the reader checks whether it should stop
_WAIT_INTERVAL = 0.01   # how often the waiting thread checks whether the agent has exited


def _complete_lines(out: str, complete: bool) -> str:
    """``out``, or, if reading stopped before the end of stdout (at the cap or the end of the grace period),
    ``out`` up to its last newline: the line after that may have been cut off."""
    return out if complete else out[:out.rfind("\n") + 1]


def _run_capped(args: list, timeout: float, max_bytes: int) -> "tuple[bytes | None, int, bool]":
    """Run ``args`` with stdin and stderr on the null device and return (stdout, exit status, whether stdout
    was read to its end). A process still running after ``timeout`` seconds is killed and
    :class:`subprocess.TimeoutExpired` raised, without any of its output.

    stdout is read on a separate thread so a chatty agent can't block the wait. That thread only reads: it
    keeps at most ``max_bytes`` and stops when more arrives. Output counts as the running process's if it was
    read before this thread first saw the process's exit, or was in the pipe at that moment (the process
    wrote it before exiting, though it may be read after): past ``max_bytes``, that kills the process and
    stdout is ``None``. Only output that arrives after that moment is post-exit output: stdout is its first
    ``max_bytes`` and the exit status decides. Once the process has exited, stdout is read for at most
    ``_SPIRE_AGENT_STDOUT_GRACE`` seconds more, then the reader stops and closes the pipe, and what was read
    so far is returned. A helper that inherited the pipe can keep it open, but never keeps this call
    waiting longer than that."""
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    lock = threading.Lock()   # guards kept and state between the reader and this thread
    kept = bytearray()
    # over: past max_bytes while running; exited: this thread has seen the exit; closed: the reader closed
    # the pipe
    state = {"over": False, "complete": False, "stop": False, "exited": False, "closed": False}
    wake = threading.Event()   # set when the reader is done: the end of stdout, or the cap
    fd = proc.stdout.fileno()
    pollable = os.name == "posix"   # Windows can't select on a pipe: there, plain blocking reads

    def keep(chunk: bytes) -> bool:
        """Add a chunk, up to max_bytes; False once the reader should stop. Called with lock held."""
        if state["stop"]:
            return False
        if len(kept) + len(chunk) > max_bytes:
            if state["exited"]:   # output after the exit was seen: stop at the cap, the exit status decides
                kept.extend(chunk[:max_bytes - len(kept)])
            else:                 # the running process's output: this thread kills it
                state["over"] = True
            return False
        kept.extend(chunk)
        return True

    def drain():  # owns the pipe: only this thread reads or closes it
        selector = None
        try:
            if pollable:
                selector = selectors.DefaultSelector()
                selector.register(fd, selectors.EVENT_READ)
            while True:
                if selector is not None and not selector.select(_POLL_INTERVAL):
                    with lock:
                        if state["stop"]:
                            return
                    continue
                if pollable:
                    # The read doesn't block (the pipe is readable) and is kept under the lock, so what was
                    # read and what is still in the pipe are counted together when the exit is first seen.
                    with lock:
                        chunk = os.read(fd, 65536)
                        if not chunk:
                            state["complete"] = not state["stop"]
                            return
                        if not keep(chunk):
                            return
                else:
                    chunk = os.read(fd, 65536)
                    with lock:
                        if not chunk:
                            state["complete"] = not state["stop"]
                            return
                        if not keep(chunk):
                            return
        except (OSError, ValueError):
            return
        finally:
            if selector is not None:
                selector.close()
            with lock:
                state["closed"] = True
                proc.stdout.close()
            wake.set()

    reader = threading.Thread(target=drain, name="spire-agent-output", daemon=True)
    reader.start()
    try:
        deadline = time.monotonic() + timeout
        while True:
            with lock:
                over = state["over"]
            if over:   # past the cap while the agent is running: kill it (from this thread, which reaps it)
                _stop(proc, lock, state)
                return None, proc.returncode, False
            if proc.poll() is not None:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _stop(proc, lock, state)
                raise subprocess.TimeoutExpired(args, timeout)
            if wake.is_set():   # stdout ended before the agent exited: just wait for the exit
                time.sleep(min(remaining, _WAIT_INTERVAL))
            else:
                wake.wait(min(remaining, _WAIT_INTERVAL))
    except BaseException:   # e.g. KeyboardInterrupt: don't leave the agent running
        if proc.poll() is None:
            _stop(proc, lock, state)
        raise
    # The agent has exited. What it wrote before exiting has been read or is in the pipe now: past the cap
    # with what was read, it is the running agent's overflow. Only what arrives after this is post-exit output.
    with lock:
        state["exited"] = True
        if not state["over"] and not state["closed"] and len(kept) + _pipe_pending(fd) > max_bytes:
            state["over"] = True
        if state["over"]:
            state["stop"] = True
            return None, proc.returncode, False
    # Give the reader the grace period to finish (the end of stdout, or the cap: the exit status decides),
    # then take what it has and stop it, whether or not a helper still holds the pipe open.
    reader.join(_SPIRE_AGENT_STDOUT_GRACE)
    with lock:
        state["stop"] = True
        return bytes(kept), proc.returncode, state["complete"]


def _pipe_pending(fd: int) -> int:
    """How many bytes are waiting in the pipe ``fd``. On Windows, where it is not asked, 0: there, output the
    agent writes past the cap just before it exits may be read either side of its exit."""
    if os.name != "posix":
        return 0
    import fcntl
    import struct
    import termios
    try:
        return struct.unpack("i", fcntl.ioctl(fd, termios.FIONREAD, b"\0\0\0\0"))[0]
    except OSError:
        return 0


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
