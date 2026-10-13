package clientattestation

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
	script := "#!/bin/sh\nsleep 4 &\nprintf 'token(spiffe://example.org/wl):\\n\\t%s\\n' '" + spireTestSVID + "'\nexec sleep 60\n"
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

// Not in spire-cli.json: these need a helper's output to pass the cap, or the grace period to end, after the
// agent has exited, and in Java the JDK closes the pipe as the agent exits, so a helper's later output never
// arrives there (Java tests its reader for these cases directly).
func TestSpireAgentOutputCutOffAfterExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake spire-agent is a POSIX shell script")
	}
	const head = "token(spiffe://example.org/wl): "
	// The signature's first 10 characters: still a compact JWS, so only the newline rule keeps it out.
	cut := spireTestSVID[:strings.LastIndex(spireTestSVID, ".")+11]
	filler := 1<<20 - 1 - len(head) - len(cut)
	for _, c := range []struct{ name, script, notFound, token string }{
		{
			name: "a token line cut off at the cap after the agent exits is not taken",
			script: fmt.Sprintf("(sleep 0.1; head -c %d /dev/zero | tr '\\0' x; printf '\\n%s%%s\\n' '%s'; "+
				"head -c 2000000 /dev/zero | tr '\\0' x) &\nexit 0\n", filler, head, spireTestSVID),
			notFound: "could not parse a JWT-SVID from spire-agent output (1048576 bytes, 2 lines; not shown)",
		},
		{
			name:     "a last line without a newline is not taken when the grace period ends",
			script:   fmt.Sprintf("(printf '%s%%s' '%s'; sleep 4) &\nexit 0\n", head, spireTestSVID),
			notFound: "could not parse a JWT-SVID from spire-agent output (267 bytes, 1 lines; not shown)",
		},
		{
			name:   "a last line without a newline counts when stdout ends",
			script: fmt.Sprintf("printf '%s%%s' '%s'\nexit 0\n", head, spireTestSVID),
			token:  spireTestSVID,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			bin := filepath.Join(t.TempDir(), "spire-agent")
			if err := os.WriteFile(bin, []byte("#!/bin/sh\n"+c.script), 0o700); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			got, err := SpireWorkloadAPISvidSource{SpireAgentBin: bin}.Fetch("aud")
			elapsed := time.Since(started)
			t.Logf("%s: %v", c.name, elapsed.Round(time.Millisecond))
			if c.token != "" {
				if err != nil || got != c.token {
					t.Fatalf("svid = %.20q, err = %v; want the token", got, err)
				}
				return
			}
			var notFound *EvidenceNotFound
			if !errors.As(err, &notFound) || err.Error() != c.notFound {
				t.Fatalf("svid = %.20q, err = %v; want EvidenceNotFound %q", got, err, c.notFound)
			}
			if elapsed > 3*time.Second {
				t.Fatalf("took %v", elapsed)
			}
		})
	}
}
