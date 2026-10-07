package clientattestation

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
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
	if runtime.GOOS == "windows" {
		t.Skip("fake spire-agent is a POSIX shell script")
	}
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	outFile := writeTemp(t, "out", output)
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + argsFile + "'\ncat '" + outFile + "'\nexit " +
		strconv.Itoa(exitCode) + "\n"
	bin = filepath.Join(dir, "spire-agent")
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, argsFile
}

func TestSpireWorkloadAPISvidSource(t *testing.T) {
	t.Run("token( line", func(t *testing.T) {
		bin, argsFile := fakeSpireAgent(t, "token(spiffe://example.org/wl):\teyJ.a.b\n", 0)
		got, err := SpireWorkloadAPISvidSource{SocketPath: "/run/spire.sock", SpireAgentBin: bin}.Fetch("https://aud")
		if err != nil {
			t.Fatal(err)
		}
		if got != "eyJ.a.b" {
			t.Fatalf("svid = %q", got)
		}
		args, _ := os.ReadFile(argsFile)
		want := "api\nfetch\njwt\n-audience\nhttps://aud\n-socketPath\n/run/spire.sock\n"
		if string(args) != want {
			t.Fatalf("spire-agent args = %q, want %q", args, want)
		}
	})
	t.Run("bare JWT line", func(t *testing.T) {
		bin, _ := fakeSpireAgent(t, "some banner\n  eyJ.c.d  \n", 0)
		got, err := SpireWorkloadAPISvidSource{SpireAgentBin: bin}.Fetch("aud")
		if err != nil || got != "eyJ.c.d" {
			t.Fatalf("svid = %q, err = %v", got, err)
		}
	})
	t.Run("default socket path", func(t *testing.T) {
		bin, argsFile := fakeSpireAgent(t, "eyJ.e.f\n", 0)
		if _, err := (SpireWorkloadAPISvidSource{SpireAgentBin: bin}).Fetch("aud"); err != nil {
			t.Fatal(err)
		}
		if args, _ := os.ReadFile(argsFile); !strings.Contains(string(args), "/tmp/spire-agent/public/api.sock") {
			t.Fatalf("args = %q, want the default socket", args)
		}
	})
	t.Run("unparseable output", func(t *testing.T) {
		bin, _ := fakeSpireAgent(t, "nothing useful\n", 0)
		if _, err := (SpireWorkloadAPISvidSource{SpireAgentBin: bin}).Fetch("aud"); err == nil || !strings.Contains(err.Error(), "could not parse") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("agent fails", func(t *testing.T) {
		bin, _ := fakeSpireAgent(t, "", 1)
		if _, err := (SpireWorkloadAPISvidSource{SpireAgentBin: bin}).Fetch("aud"); err == nil || !strings.Contains(err.Error(), "spire-agent fetch failed") {
			t.Fatalf("err = %v", err)
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
