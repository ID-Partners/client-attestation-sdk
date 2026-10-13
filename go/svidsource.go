package clientattestation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
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
// The agent's stderr is discarded, never read as output or held in memory. An agent that has not exited
// within 30 s is killed and Fetch fails.
//
// The agent's exit decides the outcome, as in the other ports. While the agent is running, more than
// 1 MiB of stdout kills it and Fetch fails; that includes what it wrote just before exiting, which is still
// in the pipe when its exit is seen. Once it has exited, stdout is read for at most 250 ms more and
// at most 1 MiB in all (a helper the agent started can inherit the pipe and keep writing to it or hold it
// open), then the pipe is closed. On exit status 0 what was read is parsed; on any other status, or if the
// agent was killed, Fetch fails. So output a helper writes after the agent has exited never turns a
// success into a failure, and never keeps Fetch waiting longer than that. If reading stopped at the 1 MiB
// or at the end of the 250 ms, the last line may be cut off, so a token is only taken from a line that
// ends in a newline.
//
// Experimental (see docs/api.md): it shells out to the spire-agent CLI, and its constructor will change
// when it moves to the Workload API socket.
type SpireWorkloadAPISvidSource struct {
	SocketPath    string // default /tmp/spire-agent/public/api.sock
	SpireAgentBin string // default "spire-agent"
}

// spireAgentMaxOutput is the most stdout read from spire-agent (as in the other ports). More while the
// agent is running fails the fetch; once it has exited, reading stops there.
const spireAgentMaxOutput = 1 << 20

// spireAgentStdoutGrace is how long stdout is still read after spire-agent has exited (as in the other
// ports). A helper the agent started can inherit the pipe and hold it open; after this the pipe is closed.
const spireAgentStdoutGrace = 250 * time.Millisecond

// spireAgentTimeout is how long spire-agent may run before it is killed (as in the other ports). A
// variable so tests can shorten it.
var spireAgentTimeout = 30 * time.Second

// spireOutput is what has been read from spire-agent's stdout. One goroutine reads the pipe into it while
// Fetch waits; once the grace period is over, Fetch takes the output with finish even if that goroutine is
// still inside a Read (it is woken by closing the pipe), so the fields are guarded by mu.
type spireOutput struct {
	mu       sync.Mutex
	buf      []byte
	over     bool // more than spireAgentMaxOutput bytes were written while the agent was running
	exitSeen bool // the reader has seen the agent's exit: what it reads from now on is post-exit output
	complete bool // the reader reached the end of stdout
	done     bool // finish has been called: the reader keeps nothing more
}

// read copies the pipe into o until the end of stdout, an error (such as the pipe being closed), or the
// cap. Output counts as the running agent's if it was read before the reader first saw the agent's exit, or
// was in the pipe at that moment (the agent wrote it before exiting, though it may be read after): past the
// cap, read records over and Fetch fails. Only output that arrives after that moment is post-exit output:
// at the cap read stops, keeping exactly the first spireAgentMaxOutput bytes, and the exit status decides.
// Fetch sets a read deadline on r when the agent exits, so a Read blocked on an idle pipe wakes up to see
// the exit before any later output is read.
func (o *spireOutput) read(r *os.File, exited <-chan struct{}) {
	chunk := make([]byte, 64<<10)
	seen := false
	for {
		if !seen {
			select {
			case <-exited:
				seen = true
				_ = r.SetReadDeadline(time.Time{})
				if !o.atExit(pipePending(r)) {
					return
				}
			default:
			}
		}
		n, err := r.Read(chunk)
		if n > 0 && !o.add(chunk[:n]) {
			return
		}
		if errors.Is(err, os.ErrDeadlineExceeded) { // the wake-up at the agent's exit
			_ = r.SetReadDeadline(time.Time{})
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				o.mu.Lock()
				o.complete = !o.done
				o.mu.Unlock()
			}
			return
		}
	}
}

// atExit marks the agent's exit as seen, with pending bytes still in the pipe; false (and over) if those
// and what was read already pass the cap.
func (o *spireOutput) atExit(pending int) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.done {
		return false
	}
	o.exitSeen = true
	if len(o.buf)+pending > spireAgentMaxOutput {
		o.over = true
		o.buf = nil
		return false
	}
	return true
}

// add keeps p; false once reading should stop.
func (o *spireOutput) add(p []byte) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.done {
		return false
	}
	if room := spireAgentMaxOutput - len(o.buf); len(p) > room {
		if o.exitSeen { // output after the agent's exit: stop at the cap, and let its exit status decide
			o.buf = append(o.buf, p[:room]...)
		} else { // the running agent's output: Fetch kills it and fails
			o.over = true
			o.buf = nil
		}
		return false
	}
	o.buf = append(o.buf, p...)
	return true
}

func (o *spireOutput) overflowed() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.over
}

// finish stops the reader keeping anything more and returns what it has read, whether the agent went past
// the cap while running, and whether the reader reached the end of stdout.
func (o *spireOutput) finish() (out []byte, over, complete bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.done = true
	return o.buf, o.over, o.complete
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
	// stdout only, through a pipe this function owns: Wait neither reads it nor closes it, so the agent's
	// exit and the end of its stdout are watched separately. stdin and stderr are the null device, so a log
	// line or version string on stderr is never parsed and a flood of it is never held in memory.
	r, w, err := os.Pipe()
	if err != nil {
		return "", fmt.Errorf("spire-agent fetch failed: %w", err)
	}
	cmd := exec.Command(bin, "api", "fetch", "jwt", "-audience", audience, "-socketPath", socket)
	cmd.Stdout = w
	if err := cmd.Start(); err != nil {
		r.Close()
		w.Close()
		return "", fmt.Errorf("spire-agent fetch failed: %w", err)
	}
	w.Close() // the agent (and any helper it starts) holds the write end now
	defer r.Close()

	exited := make(chan struct{}) // closed once the agent has exited and been reaped
	var waitErr error             // set before exited is closed
	go func() {
		waitErr = cmd.Wait()
		close(exited)
		_ = r.SetReadDeadline(time.Now()) // wake the reader to see the exit (where pipes have deadlines)
	}()
	stdout := &spireOutput{}
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		stdout.read(r, exited)
	}()
	kill := func() {
		_ = cmd.Process.Kill()
		<-exited
	}
	timeout := time.NewTimer(spireAgentTimeout)
	defer timeout.Stop()
	select {
	case <-exited:
	case <-readDone: // the end of stdout, or the cap, before the agent has exited
		if stdout.overflowed() {
			kill()
			return "", fmt.Errorf("spire-agent fetch failed: output is larger than %d bytes", spireAgentMaxOutput)
		}
		select {
		case <-exited:
		case <-timeout.C:
			kill()
			return "", fmt.Errorf("spire-agent fetch failed: %w", waitErr)
		}
	case <-timeout.C:
		kill()
		return "", fmt.Errorf("spire-agent fetch failed: %w", waitErr)
	}
	// The agent has exited. What it wrote is in the pipe: give the reader the grace period to finish, then
	// close the pipe (deferred above, which also wakes a Read a helper holding the pipe has blocked) and take
	// what was read.
	grace := time.NewTimer(spireAgentStdoutGrace)
	defer grace.Stop()
	select {
	case <-readDone:
	case <-grace.C:
	}
	r.Close()
	raw, over, complete := stdout.finish()
	if over { // past the cap before the agent exited
		return "", fmt.Errorf("spire-agent fetch failed: output is larger than %d bytes", spireAgentMaxOutput)
	}
	if waitErr != nil {
		return "", fmt.Errorf("spire-agent fetch failed: %w", waitErr)
	}
	out := string(raw)
	if svid := parseSpireJWTOutput(completeSpireLines(out, complete)); svid != "" {
		return svid, nil
	}
	// The output may hold a token or bundle that failed to parse, so the error gives only its size.
	lines := strings.Count(out, "\n")
	if len(out) > 0 && out[len(out)-1] != '\n' {
		lines++
	}
	return "", &EvidenceNotFound{msg: fmt.Sprintf(
		"could not parse a JWT-SVID from spire-agent output (%d bytes, %d lines; not shown)", len(out), lines)}
}

// completeSpireLines returns out, or, if reading stopped before the end of stdout (at the cap or the end of
// the grace period), out up to its last newline: the line after that may have been cut off.
func completeSpireLines(out string, complete bool) string {
	if complete {
		return out
	}
	return out[:strings.LastIndexByte(out, '\n')+1]
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
