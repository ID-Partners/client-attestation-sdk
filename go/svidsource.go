package clientattestation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/id-partners/client-attestation-sdk/go/internal/strictjson"
)

// SvidSource produces a workload's SPIFFE JWT-SVID for a given audience — the infra-identity input to
// attestation bootstrapping (AttestationIssuanceClient). The default SpireWorkloadAPISvidSource fetches
// it from a real SPIRE agent; the others cover dev and tests.
type SvidSource interface {
	Fetch(audience string) (string, error)
}

// StaticSvidSource returns a fixed, pre-fetched SVID (tests, or when the caller already holds one).
type StaticSvidSource struct{ SVID string }

func (s StaticSvidSource) Fetch(string) (string, error) { return s.SVID, nil }

// HTTPSvidSource GETs a URL returning {"svid":"<jwt>"} — e.g. the demo harness /dev/svid endpoint.
//
// For development and testing only. It trusts whatever the URL returns and the endpoint has no caller
// authentication, so anyone who can reach it can obtain the workload's SVID. In production use a SPIRE,
// file or cloud source.
//
// Experimental (see docs/api.md): a development and test source with no caller authentication.
type HTTPSvidSource struct {
	URL    string
	Client *http.Client
}

func (s HTTPSvidSource) Fetch(audience string) (string, error) {
	client := safeClient(s.Client, 20*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := doRequest(ctx, client, http.MethodGet, s.URL, map[string]string{"Accept": "application/json"}, nil, defaultMaxResponseBytes)
	if err != nil {
		return "", err
	}
	var body struct {
		SVID string `json:"svid"`
	}
	if err := decodeJSONOK(res, "GET "+s.URL, &body); err != nil {
		return "", err
	}
	if body.SVID == "" {
		return "", fmt.Errorf("no svid in response from %s", s.URL)
	}
	return body.SVID, nil
}

// SpireWorkloadAPISvidSource is the default source: it fetches a JWT-SVID from a real SPIRE agent's
// Workload API via the spire-agent CLI. Swap for a native go-spiffe workloadapi client by implementing
// SvidSource if you prefer no subprocess.
//
// Fetch returns the first JWT-SVID the agent prints on stdout, and an *EvidenceNotFound if there is none.
// It reads at most 1 MiB of stdout: an agent that prints more is killed and Fetch fails. The agent's
// stderr is discarded, never read as output or held in memory. An agent that has not exited within 30 s
// is killed and Fetch fails.
//
// The agent's exit decides the outcome, as in the other ports: once it has exited, stdout is read for at
// most 250 ms more (a helper the agent started can inherit the pipe and hold it open), then the pipe is
// closed. On exit status 0, what was read is parsed; on any other status, or if the agent was killed,
// Fetch fails. A helper holding stdout never turns a success into a failure, and never keeps Fetch
// waiting longer than that.
//
// Experimental (see docs/api.md): it shells out to the spire-agent CLI, and its constructor will change
// when it moves to the Workload API socket.
type SpireWorkloadAPISvidSource struct {
	SocketPath    string // default /tmp/spire-agent/public/api.sock
	SpireAgentBin string // default "spire-agent"
}

// spireAgentMaxOutput is the most stdout read from spire-agent; more fails the fetch (as in the other ports).
const spireAgentMaxOutput = 1 << 20

// spireAgentStdoutGrace is how long stdout is still read after spire-agent has exited (as in the other
// ports). A helper the agent started can inherit the pipe and hold it open; after this the pipe is closed.
const spireAgentStdoutGrace = 250 * time.Millisecond

// spireAgentTimeout is how long spire-agent may run before it is killed (as in the other ports). A
// variable so tests can shorten it.
var spireAgentTimeout = 30 * time.Second

// cappedBuffer keeps what is written to it up to max bytes. A write past that is refused, sets over and
// calls overflow (which kills the agent), so a runaway agent can't make Fetch hold more than max bytes.
// It is safe to read while the copying goroutine writes.
type cappedBuffer struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	max      int
	over     bool
	overflow func()
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.over || b.buf.Len()+len(p) > b.max {
		b.over = true
		b.overflow()
		return 0, errors.New("spire-agent output too large")
	}
	return b.buf.Write(p)
}

// snapshot returns a copy of what has been kept and whether a write went past max.
func (b *cappedBuffer) snapshot() ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buf.Bytes()), b.over
}

func (s SpireWorkloadAPISvidSource) Fetch(audience string) (string, error) {
	socket := s.SocketPath
	if socket == "" {
		socket = "/tmp/spire-agent/public/api.sock"
	}
	bin := s.SpireAgentBin
	if bin == "" {
		bin = "spire-agent"
	}
	ctx, cancel := context.WithTimeout(context.Background(), spireAgentTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "api", "fetch", "jwt", "-audience", audience, "-socketPath", socket)
	// stdout only, and at most spireAgentMaxOutput bytes of it: the agent's stderr goes to the null device,
	// so a log line or version string there is never parsed and a flood of it is never held in memory.
	stdout := &cappedBuffer{max: spireAgentMaxOutput, overflow: cancel}
	cmd.Stdout = stdout
	// Once the agent has exited (or been killed), stdout is read for at most the grace period more; then
	// Wait closes the pipe, so a helper that inherited it cannot hold Fetch open.
	cmd.WaitDelay = spireAgentStdoutGrace
	err := cmd.Run()
	out, over := stdout.snapshot() // Wait has returned: the copying goroutine is done
	if over {
		return "", fmt.Errorf("spire-agent fetch failed: output is larger than %d bytes", spireAgentMaxOutput)
	}
	// ErrWaitDelay alone means the agent exited with status 0 but something else still held stdout open
	// after the grace period: the agent's exit decides, so parse what was read.
	if err != nil && !(errors.Is(err, exec.ErrWaitDelay) && cmd.ProcessState != nil && cmd.ProcessState.Success()) {
		return "", fmt.Errorf("spire-agent fetch failed: %w", err)
	}
	if svid := parseSpireJWTOutput(string(out)); svid != "" {
		return svid, nil
	}
	// The output may hold a token or bundle that failed to parse, so the error gives only its size.
	lines := strings.Count(string(out), "\n")
	if len(out) > 0 && out[len(out)-1] != '\n' {
		lines++
	}
	return "", &EvidenceNotFound{msg: fmt.Sprintf(
		"could not parse a JWT-SVID from spire-agent output (%d bytes, %d lines; not shown)", len(out), lines)}
}

// parseSpireJWTOutput returns the first JWT-SVID in the output of `spire-agent api fetch jwt`, or "" if
// there is none. SPIRE prints each SVID as "token(<spiffe id>):" with the JWT on the next, tab-indented
// line, then "hint(<spiffe id>):" and "bundle(<trust domain>):" sections laid out the same way. The
// single-line form "token(<spiffe id>): <jwt>" and a bare JWT line are accepted too. Only a syntactically
// valid compact JWS is returned; the values of hint and bundle sections are skipped. A label with no value
// takes the next line as its value only if that line is not itself a label. Only ASCII space, tab and CR
// around a line or value are ignored (the same set in every port).
func parseSpireJWTOutput(out string) string {
	lines := strings.Split(out, "\n")
	for i := 0; i < len(lines); i++ {
		line := trimSpireSpace(lines[i])
		label, rest, labelled := spireSectionLabel(line)
		if !labelled {
			if isCompactJWS(line) { // a bare compact JWT line
				return line
			}
			continue
		}
		if rest == "" && i+1 < len(lines) { // the value is on the next line, unless that is another label
			if next := trimSpireSpace(lines[i+1]); !isSpireSectionLine(next) {
				i++
				rest = next
			}
		}
		if label == "token" && isCompactJWS(rest) {
			return rest
		}
	}
	return ""
}

// trimSpireSpace drops the ASCII spaces, tabs and CRs around s, and nothing else: not a BOM, an NBSP or
// other Unicode space, so every port reads the same output the same way.
func trimSpireSpace(s string) string { return strings.Trim(s, " \t\r") }

func isSpireSectionLine(line string) bool {
	_, _, ok := spireSectionLabel(line)
	return ok
}

// spireSectionLabel splits a "token(…): value", "hint(…):" or "bundle(…):" line into its label and the
// rest of the line after the first "):".
func spireSectionLabel(line string) (label, rest string, ok bool) {
	for _, l := range []string{"token", "hint", "bundle"} {
		if strings.HasPrefix(line, l+"(") {
			if _, after, found := strings.Cut(line[len(l)+1:], "):"); found {
				return l, trimSpireSpace(after), true
			}
		}
	}
	return "", "", false
}

// isCompactJWS reports whether s is three non-empty base64url segments whose first is the canonical
// encoding of a strict JSON object (the token validator's reader) with a non-empty string "alg". It does
// not verify anything; it tells a JWT from a version string or log line.
func isCompactJWS(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" || strings.Trim(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
			return false
		}
	}
	raw, err := strictjson.DecodeSegment(parts[0])
	if err != nil {
		return false
	}
	header, err := strictjson.ParseObject(raw, "header")
	if err != nil {
		return false
	}
	alg, ok := header["alg"].(string)
	return ok && alg != ""
}
