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
    script.write_text("#!/bin/sh\nsleep 60 &\nprintf 'token(spiffe://example.org/wl): x.y.z\\n'\nexec sleep 60\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        SpireWorkloadApiSvidSource(spire_agent=str(script)).fetch("aud")
    elapsed = time.monotonic() - started
    print(f"killed at the timeout: {elapsed * 1000:.0f}ms")
    assert elapsed < 3
    assert caught.value.output is None and caught.value.stderr is None
