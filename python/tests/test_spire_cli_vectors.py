"""The SPIRE CLI source against the shared cases (vectors/spire-cli.json): a fake spire-agent that starts a
helper holding its stdout. Every port must agree."""
import json
import os
import stat
import subprocess
import time

import pytest

from client_attestation_sdk.evidence import EvidenceNotFound
from client_attestation_sdk.svid_source import SpireWorkloadApiSvidSource

VECTORS = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "vectors"))


def _cases():
    with open(os.path.join(VECTORS, "spire-cli.json"), encoding="utf-8") as fh:
        return json.load(fh)["cases"]


@pytest.mark.skipif(os.name != "posix", reason="fake spire-agent is a shell script")
@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_vector(case, tmp_path):
    script = tmp_path / "spire-agent"
    script.write_text("#!/bin/sh\n" + case["script"])
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    source = SpireWorkloadApiSvidSource(socket_path="/s", spire_agent=str(script))
    started = time.monotonic()
    try:
        outcome = source.fetch("aud")
    except Exception as e:  # noqa: BLE001 - the case says which failure it expects
        outcome = e
    elapsed = time.monotonic() - started
    print(f"{case['name']}: {elapsed * 1000:.0f}ms")
    if "token" in case:
        assert outcome == case["token"]
    elif "error" in case:
        assert isinstance(outcome, RuntimeError) and str(outcome) == case["error"], repr(outcome)
    else:
        assert isinstance(outcome, EvidenceNotFound) and str(outcome) == case["not_found"], repr(outcome)
    assert elapsed * 1000 <= case["max_ms"]


@pytest.mark.skipif(os.name != "posix", reason="fake spire-agent is a shell script")
def test_a_hung_agent_is_killed_at_the_timeout_with_a_helper_holding_stdout(tmp_path, monkeypatch):
    # Not in spire-cli.json: it shortens the 30 s timeout.
    from client_attestation_sdk import svid_source
    monkeypatch.setattr(svid_source, "_SPIRE_AGENT_TIMEOUT", 0.3)
    script = tmp_path / "spire-agent"
    script.write_text("#!/bin/sh\nsleep 4 &\nprintf 'token(spiffe://example.org/wl): x.y.z\\n'\nexec sleep 60\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        SpireWorkloadApiSvidSource(spire_agent=str(script)).fetch("aud")
    elapsed = time.monotonic() - started
    print(f"killed at the timeout: {elapsed * 1000:.0f}ms")
    assert elapsed < 3
    assert caught.value.output is None and caught.value.stderr is None


# Not in spire-cli.json: these need a helper's output to pass the cap, or the grace period to end, after
# the agent has exited, and in Java the JDK closes the pipe as the agent exits, so a helper's later output
# never arrives there (Java tests its reader for these cases directly).
_SVID = _cases()[0]["token"]
_HEAD = "token(spiffe://example.org/wl): "
# The signature's first 10 characters: still a compact JWS, so only the newline rule keeps it out.
_CUT = _SVID[:_SVID.rindex(".") + 11]
_FILLER = (1 << 20) - 1 - len(_HEAD) - len(_CUT)


def _fetch(tmp_path, body):
    script = tmp_path / "spire-agent"
    script.write_text("#!/bin/sh\n" + body)
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    started = time.monotonic()
    try:
        outcome = SpireWorkloadApiSvidSource(socket_path="/s", spire_agent=str(script)).fetch("aud")
    except Exception as e:  # noqa: BLE001 - each test says which outcome it expects
        outcome = e
    return outcome, time.monotonic() - started


@pytest.mark.skipif(os.name != "posix", reason="fake spire-agent is a shell script")
def test_a_token_line_cut_off_at_the_cap_after_the_agent_exits_is_not_taken(tmp_path):
    outcome, elapsed = _fetch(tmp_path, (
        f"(sleep 0.1; head -c {_FILLER} /dev/zero | tr '\\0' x; printf '\\n{_HEAD}%s\\n' '{_SVID}'; "
        "head -c 2000000 /dev/zero | tr '\\0' x) &\nexit 0\n"))
    print(f"token cut off at the cap: {elapsed * 1000:.0f}ms")
    assert isinstance(outcome, EvidenceNotFound), repr(outcome)
    assert str(outcome) == "could not parse a JWT-SVID from spire-agent output (1048576 bytes, 2 lines; not shown)"
    assert elapsed < 3


@pytest.mark.skipif(os.name != "posix", reason="fake spire-agent is a shell script")
def test_a_last_line_without_a_newline_is_not_taken_when_the_grace_period_ends(tmp_path):
    outcome, elapsed = _fetch(tmp_path, f"(printf '{_HEAD}%s' '{_SVID}'; sleep 4) &\nexit 0\n")
    print(f"unterminated line, helper holds stdout: {elapsed * 1000:.0f}ms")
    assert isinstance(outcome, EvidenceNotFound), repr(outcome)
    assert str(outcome) == "could not parse a JWT-SVID from spire-agent output (267 bytes, 1 lines; not shown)"
    assert elapsed < 3


@pytest.mark.skipif(os.name != "posix", reason="fake spire-agent is a shell script")
def test_a_last_line_without_a_newline_counts_when_stdout_ends(tmp_path):
    outcome, _ = _fetch(tmp_path, f"printf '{_HEAD}%s' '{_SVID}'\nexit 0\n")
    assert outcome == _SVID


@pytest.mark.skipif(os.name != "posix", reason="fake spire-agent is a shell script")
def test_stdout_closed_before_the_agent_exits(tmp_path):
    outcome, elapsed = _fetch(tmp_path, f"printf '{_HEAD}%s\\n' '{_SVID}'\nexec >&-\nsleep 0.3\nexit 0\n")
    assert outcome == _SVID
    assert 0.3 <= elapsed < 3
