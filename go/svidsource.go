package clientattestation

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"
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
type SpireWorkloadAPISvidSource struct {
	SocketPath    string // default /tmp/spire-agent/public/api.sock
	SpireAgentBin string // default "spire-agent"
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "api", "fetch", "jwt", "-audience", audience, "-socketPath", socket).Output()
	if err != nil {
		return "", fmt.Errorf("spire-agent fetch failed: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "token(") { // "token(spiffe://…): eyJ…"
			if _, rest, ok := strings.Cut(line, "):"); ok {
				return strings.TrimSpace(rest), nil
			}
		}
		if strings.Count(line, ".") == 2 { // a bare compact JWT line
			return line, nil
		}
	}
	return "", fmt.Errorf("could not parse SVID from spire-agent output:\n%s", out)
}
