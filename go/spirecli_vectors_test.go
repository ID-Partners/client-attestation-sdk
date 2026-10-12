package clientattestation

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestSpireCLIVectors runs the shared SPIRE CLI cases (vectors/spire-cli.json) through
// SpireWorkloadAPISvidSource: a fake spire-agent that starts a helper holding its stdout. Every port must agree.
func TestSpireCLIVectors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake spire-agent is a POSIX shell script")
	}
	raw, err := os.ReadFile(filepath.Join("..", "vectors", "spire-cli.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []struct {
			Name     string `json:"name"`
			Script   string `json:"script"`
			Token    string `json:"token"`
			Error    string `json:"error"`
			NotFound string `json:"not_found"`
			MaxMS    int    `json:"max_ms"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	for _, c := range file.Cases {
		t.Run(c.Name, func(t *testing.T) {
			bin := filepath.Join(t.TempDir(), "spire-agent")
			if err := os.WriteFile(bin, []byte("#!/bin/sh\n"+c.Script), 0o700); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			got, err := SpireWorkloadAPISvidSource{SocketPath: "/s", SpireAgentBin: bin}.Fetch("aud")
			elapsed := time.Since(started)
			t.Logf("%s: %v", c.Name, elapsed.Round(time.Millisecond))
			switch {
			case c.Token != "":
				if err != nil || got != c.Token {
					t.Errorf("svid = %.20q, err = %v; want the agent's token", got, err)
				}
			case c.Error != "":
				if err == nil || err.Error() != c.Error {
					t.Errorf("err = %v, want %q", err, c.Error)
				}
			default:
				var notFound *EvidenceNotFound
				if !errors.As(err, &notFound) || err.Error() != c.NotFound {
					t.Errorf("err = %v, want EvidenceNotFound %q", err, c.NotFound)
				}
			}
			if elapsed > time.Duration(c.MaxMS)*time.Millisecond {
				t.Errorf("took %v, want at most %dms", elapsed, c.MaxMS)
			}
		})
	}
}

// Not in spire-cli.json (it shortens the 30 s timeout): an agent that never exits is killed at the timeout,
// even with a helper holding its stdout, and Fetch fails without waiting for the helper.
func TestSpireAgentKilledAtTheTimeoutWithAHelperHoldingStdout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake spire-agent is a POSIX shell script")
	}
	orig := spireAgentTimeout
	spireAgentTimeout = 300 * time.Millisecond
	t.Cleanup(func() { spireAgentTimeout = orig })
	bin := filepath.Join(t.TempDir(), "spire-agent")
	script := "#!/bin/sh\nsleep 60 &\nprintf 'token(spiffe://example.org/wl):\\n\\t%s\\n' '" + spireTestSVID + "'\nexec sleep 60\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err := SpireWorkloadAPISvidSource{SpireAgentBin: bin}.Fetch("aud")
	elapsed := time.Since(started)
	t.Logf("killed at the timeout: %v", elapsed.Round(time.Millisecond))
	if err == nil || err.Error() != "spire-agent fetch failed: signal: killed" {
		t.Fatalf("err = %v, want the agent killed", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("took %v", elapsed)
	}
}
