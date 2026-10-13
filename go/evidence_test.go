package clientattestation

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// isolateEvidence clears every evidence env var and points the default token file, default SPIRE socket
// and GCP probe at nothing, so a test sees only the sources it sets up. All restored on cleanup.
func isolateEvidence(t *testing.T) {
	t.Helper()
	t.Setenv(EnvSVID, "")
	t.Setenv(EnvTokenFile, "")
	t.Setenv(EnvSpiffeSocket, "")
	origTokenFile, origSocket, origProbe, origProbeURL := defaultTokenFile, defaultSpiffeSocket, gcpMetadataProbe, gcpMetadataProbeURL
	t.Cleanup(func() {
		defaultTokenFile, defaultSpiffeSocket, gcpMetadataProbe, gcpMetadataProbeURL = origTokenFile, origSocket, origProbe, origProbeURL
	})
	missing := filepath.Join(t.TempDir(), "missing")
	defaultTokenFile = missing + "-token"
	defaultSpiffeSocket = missing + "-sock"
	gcpMetadataProbe = func() bool { return false }
	gcpMetadataProbeURL = closedPortURL(t) + "/computeMetadata/v1/"
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeMetadataServer answers the GCP metadata probe (any path) like the real server would.
func fakeMetadataServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Metadata-Flavor", "Google")
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAutoDetectEachSourcePositive(t *testing.T) {
	t.Run("env token", func(t *testing.T) {
		isolateEvidence(t)
		t.Setenv(EnvSVID, "  env-token \n")
		source, err := AutoDetectEvidence()
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := source.Fetch("aud"); got != "env-token" {
			t.Fatalf("fetch = %q", got)
		}
	})
	t.Run("token file via env", func(t *testing.T) {
		isolateEvidence(t)
		path := writeTemp(t, "tok", "env-file-token\n")
		t.Setenv(EnvTokenFile, path)
		source, err := AutoDetectEvidence()
		if err != nil {
			t.Fatal(err)
		}
		if s, ok := source.(FileTokenSvidSource); !ok || s.Path != path {
			t.Fatalf("source = %#v", source)
		}
		if got, _ := source.Fetch("aud"); got != "env-file-token" {
			t.Fatalf("fetch = %q", got)
		}
	})
	t.Run("default token file", func(t *testing.T) {
		isolateEvidence(t)
		defaultTokenFile = writeTemp(t, "attester-token", "default-file-token")
		source, err := AutoDetectEvidence()
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := source.Fetch("aud"); got != "default-file-token" {
			t.Fatalf("fetch = %q", got)
		}
	})
	t.Run("SPIRE socket via env", func(t *testing.T) {
		isolateEvidence(t)
		sock := writeTemp(t, "api.sock", "")
		t.Setenv(EnvSpiffeSocket, "unix://"+sock)
		source, err := AutoDetectEvidence()
		if err != nil {
			t.Fatal(err)
		}
		if s, ok := source.(SpireWorkloadAPISvidSource); !ok || s.SocketPath != sock {
			t.Fatalf("source = %#v", source)
		}
	})
	t.Run("default SPIRE socket", func(t *testing.T) {
		isolateEvidence(t)
		defaultSpiffeSocket = writeTemp(t, "api.sock", "")
		source, err := AutoDetectEvidence()
		if err != nil {
			t.Fatal(err)
		}
		if s, ok := source.(SpireWorkloadAPISvidSource); !ok || s.SocketPath != defaultSpiffeSocket {
			t.Fatalf("source = %#v", source)
		}
	})
	t.Run("GCP metadata via fake probe URL", func(t *testing.T) {
		isolateEvidence(t)
		gcpMetadataProbe = gcpMetadataAvailable // the real probe, aimed at a local fake
		gcpMetadataProbeURL = fakeMetadataServer(t).URL + "/computeMetadata/v1/"
		source, err := AutoDetectEvidence()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := source.(GoogleMetadataSvidSource); !ok {
			t.Fatalf("source = %T, want GoogleMetadataSvidSource", source)
		}
	})
	t.Run("GCP metadata refused port is not available", func(t *testing.T) {
		isolateEvidence(t)
		gcpMetadataProbe = gcpMetadataAvailable
		var nf *EvidenceNotFound
		if _, err := AutoDetectEvidence(); !errors.As(err, &nf) {
			t.Fatalf("err = %v, want *EvidenceNotFound", err)
		}
	})
}

func TestAutoDetectPrecedenceChain(t *testing.T) {
	isolateEvidence(t)
	// Every source present at once; peel them off one at a time and check the next one wins.
	envFile := writeTemp(t, "env-tok", "from-env-file")
	defaultTokenFile = writeTemp(t, "default-tok", "from-default-file")
	envSock := writeTemp(t, "env.sock", "")
	defaultSpiffeSocket = writeTemp(t, "default.sock", "")
	gcpMetadataProbe = gcpMetadataAvailable
	gcpMetadataProbeURL = fakeMetadataServer(t).URL + "/"
	t.Setenv(EnvSVID, "from-env")
	t.Setenv(EnvTokenFile, envFile)
	t.Setenv(EnvSpiffeSocket, envSock)

	check := func(want string) {
		t.Helper()
		source, err := AutoDetectEvidence()
		if err != nil {
			t.Fatal(err)
		}
		var got string
		switch s := source.(type) {
		case StaticSvidSource:
			got = "static:" + s.SVID
		case FileTokenSvidSource:
			got = "file:" + s.Path
		case SpireWorkloadAPISvidSource:
			got = "spire:" + s.SocketPath
		case GoogleMetadataSvidSource:
			got = "gcp"
		default:
			t.Fatalf("unexpected source %T", source)
		}
		if got != want {
			t.Fatalf("source = %s, want %s", got, want)
		}
	}

	check("static:from-env")
	t.Setenv(EnvSVID, "")
	check("file:" + envFile)
	t.Setenv(EnvTokenFile, "")
	check("file:" + defaultTokenFile)
	defaultTokenFile += "-gone"
	check("spire:" + envSock)
	t.Setenv(EnvSpiffeSocket, "")
	check("spire:" + defaultSpiffeSocket)
	defaultSpiffeSocket += "-gone"
	check("gcp")
}

func TestFileTokenSvidSourceMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope")
	if _, err := (FileTokenSvidSource{Path: path}).Fetch("aud"); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("err = %v, want one naming %s", err, path)
	}
}

// fakeSpireAgent writes an executable stand-in for the spire-agent CLI that records its arguments and
// prints output.
func fakeSpireAgent(t *testing.T, output string, exitCode int) (bin, argsFile string) {
	t.Helper()
	return fakeSpireAgentWithStderr(t, output, "", exitCode)
}

// fakeSpireAgentWithStderr is fakeSpireAgent that also writes stderr to standard error, before stdout.
func fakeSpireAgentWithStderr(t *testing.T, output, stderr string, exitCode int) (bin, argsFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake spire-agent is a POSIX shell script")
	}
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	outFile := writeTemp(t, "out", output)
	errFile := writeTemp(t, "err", stderr)
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + argsFile + "'\ncat '" + errFile + "' >&2\ncat '" + outFile +
		"'\nexit " + strconv.Itoa(exitCode) + "\n"
	bin = filepath.Join(dir, "spire-agent")
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, argsFile
}

// Two JWT-SVIDs shaped like real ones: an ES256 header with a kid, a SPIFFE sub, a 64-byte signature.
const (
	spireTestSVID      = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiSldUIn0.eyJhdWQiOlsiaHR0cHM6Ly9hdWQiXSwiZXhwIjo0MTAyNDQ0ODAwLCJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLm9yZy93bCJ9.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw"
	spireTestOtherSVID = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiSldUIn0.eyJhdWQiOlsiaHR0cHM6Ly9hdWQiXSwiZXhwIjo0MTAyNDQ0ODAwLCJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLm9yZy9vdGhlciJ9.QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-fw"
	spireTestBundle    = `{"keys":[{"kty":"EC","kid":"k1","crv":"P-256","x":"WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis","y":"y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"}]}`
)

// spireTestOutput is what `spire-agent api fetch jwt` prints for two SVIDs, one with a hint, and a bundle:
// the layout of printPrettyResult in SPIRE's cmd/spire-agent/cli/api/fetch_jwt.go (v1.5 to v1.15),
// "token(%s):\n\t%s\n", "hint(%s):\n\t%s\n" and "bundle(%s):\n\t%s\n".
const spireTestOutput = "token(spiffe://example.org/wl):\n\t" + spireTestSVID + "\n" +
	"hint(spiffe://example.org/wl):\n\texternal\n" +
	"token(spiffe://example.org/other):\n\t" + spireTestOtherSVID + "\n" +
	"bundle(spiffe://example.org):\n\t" + spireTestBundle + "\n"

func TestSpireWorkloadAPISvidSource(t *testing.T) {
	t.Run("SPIRE's two-line output", func(t *testing.T) {
		bin, argsFile := fakeSpireAgent(t, spireTestOutput, 0)
		got, err := SpireWorkloadAPISvidSource{SocketPath: "/run/spire.sock", SpireAgentBin: bin}.Fetch("https://aud")
		if err != nil {
			t.Fatal(err)
		}
		if got != spireTestSVID {
			t.Fatalf("svid = %q, want the first token", got)
		}
		args, _ := os.ReadFile(argsFile)
		want := "api\nfetch\njwt\n-audience\nhttps://aud\n-socketPath\n/run/spire.sock\n"
		if string(args) != want {
			t.Fatalf("spire-agent args = %q, want %q", args, want)
		}
	})
	t.Run("token( line with the JWT on the same line", func(t *testing.T) {
		bin, _ := fakeSpireAgent(t, "token(spiffe://example.org/wl):\t"+spireTestSVID+"\n", 0)
		got, err := SpireWorkloadAPISvidSource{SpireAgentBin: bin}.Fetch("aud")
		if err != nil || got != spireTestSVID {
			t.Fatalf("svid = %q, err = %v", got, err)
		}
	})
	t.Run("bare JWT line", func(t *testing.T) {
		bin, _ := fakeSpireAgent(t, "some banner\n  "+spireTestSVID+"  \n", 0)
		got, err := SpireWorkloadAPISvidSource{SpireAgentBin: bin}.Fetch("aud")
		if err != nil || got != spireTestSVID {
			t.Fatalf("svid = %q, err = %v", got, err)
		}
	})
	t.Run("stderr is not output", func(t *testing.T) {
		bin, _ := fakeSpireAgentWithStderr(t, spireTestOutput, "1.9.6\n", 0)
		if got, err := (SpireWorkloadAPISvidSource{SpireAgentBin: bin}).Fetch("aud"); err != nil || got != spireTestSVID {
			t.Fatalf("svid = %q, err = %v", got, err)
		}
		bin, _ = fakeSpireAgentWithStderr(t, "", "1.9.6\n", 0)
		var notFound *EvidenceNotFound
		if _, err := (SpireWorkloadAPISvidSource{SpireAgentBin: bin}).Fetch("aud"); !errors.As(err, &notFound) {
			t.Fatalf("err = %v, want *EvidenceNotFound", err)
		}
	})
	t.Run("a dotted string that is not a JWS is not a token", func(t *testing.T) {
		for _, out := range []string{
			"1.9.6\n",
			"level=info msg=starting version=v1.9.6\n",
			"a.b.c\n",
			"token(spiffe://example.org/wl):\n\t1.9.6\n",
			"eyJ0eXAiOiJKV1QifQ.e30.c2ln\n",                      // a JSON header with no alg
			"bnVsbA.e30.c2ln\n",                                  // a header of null
			"eyJhbGciOiJFUzI1NiJ9.e30.\n",                        // no signature
			"eyJhbGciOiJFUzI1NiIsfQ.e30.c2ln\n",                  // {"alg":"ES256",}: not strict JSON
			"eyJhbGciOiJFUzI1NiIsImFsZyI6IkVTMjU2In0.e30.c2ln\n", // a duplicate "alg"
			"77u_eyJhbGciOiJFUzI1NiJ9.e30.c2ln\n",                // a header with a BOM
			"\ufeff" + spireTestSVID + "\n",                      // a BOM is not whitespace
			"\u00a0" + spireTestSVID + "\u00a0\n",                // nor is an NBSP
			"token(spiffe://example.org/wl):\n\u00a0" + spireTestSVID + "\n",
			"token(spiffe://example.org/wl): \ufeff" + spireTestSVID + "\n",
			"\v" + spireTestSVID + "\f\n",
		} {
			bin, _ := fakeSpireAgent(t, out, 0)
			var notFound *EvidenceNotFound
			if got, err := (SpireWorkloadAPISvidSource{SpireAgentBin: bin}).Fetch("aud"); !errors.As(err, &notFound) {
				t.Errorf("output %q: svid = %q, err = %v, want *EvidenceNotFound", out, got, err)
			}
		}
	})
	t.Run("only ASCII space, tab and CR surround a value", func(t *testing.T) {
		bin, _ := fakeSpireAgent(t, "token(spiffe://example.org/wl):\r\n \t"+spireTestSVID+"\t \r\n", 0)
		if got, err := (SpireWorkloadAPISvidSource{SpireAgentBin: bin}).Fetch("aud"); err != nil || got != spireTestSVID {
			t.Fatalf("svid = %q, err = %v", got, err)
		}
	})
	t.Run("a label with no value does not take the next label as its value", func(t *testing.T) {
		for _, out := range []string{
			"hint(spiffe://example.org/wl):\ntoken(spiffe://example.org/wl): " + spireTestSVID + "\n",
			"token(spiffe://example.org/wl):\ntoken(spiffe://example.org/other): " + spireTestSVID + "\n",
			"bundle(spiffe://example.org):\n\ttoken(spiffe://example.org/wl): " + spireTestSVID + "\n",
		} {
			bin, _ := fakeSpireAgent(t, out, 0)
			if got, err := (SpireWorkloadAPISvidSource{SpireAgentBin: bin}).Fetch("aud"); err != nil || got != spireTestSVID {
				t.Errorf("output %q: svid = %q, err = %v", out, got, err)
			}
		}
	})
	t.Run("stdout is capped at 1 MiB", func(t *testing.T) {
		line := "token(spiffe://example.org/wl): " + spireTestSVID + "\n"
		atCap := line + strings.Repeat("x", 1<<20-len(line))
		bin, _ := fakeSpireAgent(t, atCap, 0)
		if got, err := (SpireWorkloadAPISvidSource{SpireAgentBin: bin}).Fetch("aud"); err != nil || got != spireTestSVID {
			t.Fatalf("1 MiB of output: svid = %q, err = %v", got, err)
		}
		// One byte more while the agent is still running fails the fetch.
		over := filepath.Join(t.TempDir(), "spire-agent")
		script := "#!/bin/sh\ncat '" + writeTemp(t, "over", atCap+"x") + "'\nexec sleep 5\n"
		if err := os.WriteFile(over, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
		_, err := SpireWorkloadAPISvidSource{SpireAgentBin: over}.Fetch("aud")
		if err == nil || err.Error() != "spire-agent fetch failed: output is larger than 1048576 bytes" {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("an agent that writes past the cap and exits always fails", func(t *testing.T) {
		// The agent itself writes 1 MiB + 1 byte and exits at once, so the last bytes may be read either side
		// of its exit. They were written while it ran, so the fetch fails every time, as in the other ports.
		if runtime.GOOS == "windows" {
			t.Skip("fake spire-agent is a POSIX shell script")
		}
		bin := filepath.Join(t.TempDir(), "spire-agent")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\nexec head -c 1048577 /dev/zero\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		ok := 0
		for i := 0; i < 50; i++ {
			_, err := SpireWorkloadAPISvidSource{SpireAgentBin: bin}.Fetch("aud")
			var nf *EvidenceNotFound
			if errors.As(err, &nf) || err == nil { // read as post-exit output: cut at the cap
				ok++
			} else if err.Error() != "spire-agent fetch failed: output is larger than 1048576 bytes" {
				t.Fatalf("err = %v", err)
			}
		}
		if ok != 0 {
			t.Fatalf("%d of 50 runs did not fail with the size error", ok)
		}
	})
	t.Run("a flood of stderr is discarded", func(t *testing.T) {
		bin, _ := fakeSpireAgentWithStderr(t, spireTestOutput, strings.Repeat("e", 4<<20), 0)
		if got, err := (SpireWorkloadAPISvidSource{SpireAgentBin: bin}).Fetch("aud"); err != nil || got != spireTestSVID {
			t.Fatalf("svid = %q, err = %v", got, err)
		}
	})
	t.Run("default socket path", func(t *testing.T) {
		bin, argsFile := fakeSpireAgent(t, spireTestSVID+"\n", 0)
		if _, err := (SpireWorkloadAPISvidSource{SpireAgentBin: bin}).Fetch("aud"); err != nil {
			t.Fatal(err)
		}
		if args, _ := os.ReadFile(argsFile); !strings.Contains(string(args), "/tmp/spire-agent/public/api.sock") {
			t.Fatalf("args = %q, want the default socket", args)
		}
	})
	t.Run("no token is EvidenceNotFound and the error does not show the output", func(t *testing.T) {
		out := "secret-not-a-jwt\nbundle(spiffe://example.org):\n\t" + spireTestBundle + "\n"
		bin, _ := fakeSpireAgent(t, out, 0)
		_, err := SpireWorkloadAPISvidSource{SpireAgentBin: bin}.Fetch("aud")
		var notFound *EvidenceNotFound
		if !errors.As(err, &notFound) || !strings.Contains(err.Error(), "could not parse") {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(err.Error(), "secret-not-a-jwt") || strings.Contains(err.Error(), "WKn-ZIG") {
			t.Fatalf("err shows the agent output: %v", err)
		}
		if !strings.Contains(err.Error(), strconv.Itoa(len(out))+" bytes, 3 lines") {
			t.Fatalf("err = %v, want the output size", err)
		}
	})
	t.Run("agent fails", func(t *testing.T) {
		bin, _ := fakeSpireAgentWithStderr(t, spireTestOutput, "error: "+spireTestSVID+"\n", 1)
		_, err := SpireWorkloadAPISvidSource{SpireAgentBin: bin}.Fetch("aud")
		if err == nil || !strings.Contains(err.Error(), "spire-agent fetch failed") {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(err.Error(), spireTestSVID) {
			t.Fatalf("err shows the agent output: %v", err)
		}
	})
	t.Run("agent missing", func(t *testing.T) {
		bin := filepath.Join(t.TempDir(), "no-such-spire-agent")
		if _, err := (SpireWorkloadAPISvidSource{SpireAgentBin: bin}).Fetch("aud"); err == nil {
			t.Fatal("expected an error for a missing binary")
		}
	})
}

func TestHTTPSvidSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			writeJSON(w, 200, map[string]any{"svid": "eyJ.g.h"})
		case "/empty":
			writeJSON(w, 200, map[string]any{})
		default:
			writeJSON(w, 500, map[string]any{"error": "boom"})
		}
	}))
	defer srv.Close()

	if got, err := (HTTPSvidSource{URL: srv.URL + "/ok"}).Fetch("aud"); err != nil || got != "eyJ.g.h" {
		t.Fatalf("svid = %q, err = %v", got, err)
	}
	if _, err := (HTTPSvidSource{URL: srv.URL + "/empty"}).Fetch("aud"); err == nil || !strings.Contains(err.Error(), "no svid") {
		t.Fatalf("err = %v", err)
	}
	if _, err := (HTTPSvidSource{URL: srv.URL + "/fail"}).Fetch("aud"); asSDKError(t, err).Status != 500 {
		t.Fatalf("err = %v", err)
	}
	if _, err := (HTTPSvidSource{URL: closedPortURL(t)}).Fetch("aud"); err == nil {
		t.Fatal("expected an error for a refused connection")
	}
}

func TestFileTokenSvidSourceRefusesOversizeFile(t *testing.T) {
	path := writeTemp(t, "big-token", strings.Repeat("a", maxTokenFileBytes+1))
	_, err := (FileTokenSvidSource{Path: path}).Fetch("aud")
	var nf *EvidenceNotFound
	if !errors.As(err, &nf) || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v, want *EvidenceNotFound for a file over %d bytes", err, maxTokenFileBytes)
	}
	// Exactly at the cap is fine.
	path = writeTemp(t, "max-token", strings.Repeat("b", maxTokenFileBytes))
	if got, err := (FileTokenSvidSource{Path: path}).Fetch("aud"); err != nil || len(got) != maxTokenFileBytes {
		t.Fatalf("len = %d, err = %v", len(got), err)
	}
}

func TestGCPMetadataRequiresFlavorHeaderAnd200(t *testing.T) {
	cases := map[string]struct {
		status int
		flavor string
		want   bool
	}{
		"200 with header":    {200, "Google", true},
		"200 without header": {200, "", false},
		"200 wrong header":   {200, "Other", false},
		"404 with header":    {404, "Google", false},
		"204 with header":    {204, "Google", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.flavor != "" {
					w.Header().Set("Metadata-Flavor", tc.flavor)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("id.token.jwt"))
			}))
			defer srv.Close()
			if got := metadataAnswers(srv.URL+"/computeMetadata/v1/", time.Second); got != tc.want {
				t.Fatalf("probe = %v, want %v", got, tc.want)
			}
			target, _ := url.Parse(srv.URL)
			tok, err := GoogleMetadataSvidSource{Client: &http.Client{Transport: rewriteHost{target: target}}}.Fetch("aud")
			if tc.want && (err != nil || tok != "id.token.jwt") {
				t.Fatalf("tok = %q, err = %v", tok, err)
			}
			if !tc.want && err == nil {
				t.Fatalf("tok = %q, want an error", tok)
			}
		})
	}
}

// TestGCPMetadataIgnoresHTTPProxy runs the probe in a child process with HTTP_PROXY set (the proxy
// environment is read once per process) and checks the proxy never sees the request.
func TestGCPMetadataIgnoresHTTPProxy(t *testing.T) {
	if os.Getenv("CA_METADATA_PROXY_CHILD") == "1" {
		gcpMetadataProbeURL = "http://metadata.google.internal.invalid/computeMetadata/v1/"
		_ = gcpMetadataAvailable()
		return
	}
	var hits int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Metadata-Flavor", "Google")
		_, _ = w.Write([]byte("ok"))
	}))
	defer proxy.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestGCPMetadataIgnoresHTTPProxy$")
	cmd.Env = append(os.Environ(), "CA_METADATA_PROXY_CHILD=1",
		"HTTP_PROXY="+proxy.URL, "http_proxy="+proxy.URL, "NO_PROXY=", "no_proxy=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("the metadata probe went through HTTP_PROXY (%d requests)", n)
	}
}

type wrappedTransport struct{ http.RoundTripper }

// A replaced http.DefaultTransport that is not an *http.Transport must not panic at init: the metadata
// transport falls back to a fresh direct one.
func TestMetadataTransportWithAWrappedDefaultTransport(t *testing.T) {
	got := newMetadataTransport(wrappedTransport{http.DefaultTransport})
	if got == nil || got.Proxy != nil || got.DialContext == nil {
		t.Fatalf("fallback transport = %+v", got)
	}
	base := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if clone := newMetadataTransport(base); clone == base || clone.Proxy != nil || base.Proxy == nil {
		t.Fatal("an *http.Transport is cloned without its proxy, leaving the original alone")
	}
}

// A zero or negative GoogleMetadataSvidSource.Timeout is the 5s default, not an expired deadline.
func TestGCPMetadataNonPositiveTimeoutIsTheDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Metadata-Flavor", "Google")
		_, _ = w.Write([]byte("id.token.jwt"))
	}))
	defer srv.Close()
	target, _ := url.Parse(srv.URL)
	for _, d := range []time.Duration{0, -time.Second} {
		tok, err := GoogleMetadataSvidSource{Timeout: d, Client: &http.Client{Transport: rewriteHost{target: target}}}.Fetch("aud")
		if err != nil || tok != "id.token.jwt" {
			t.Fatalf("Timeout %v: tok = %q, err = %v", d, tok, err)
		}
	}
}
