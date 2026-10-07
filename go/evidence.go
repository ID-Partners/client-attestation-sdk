package clientattestation

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment variables an operator can set to pin the evidence source explicitly.
const (
	// EnvSVID carries the evidence token itself (static).
	EnvSVID = "CLIENT_ATTESTATION_SVID"
	// EnvTokenFile is a path to a projected token file.
	EnvTokenFile = "CLIENT_ATTESTATION_TOKEN_FILE"
	// EnvSpiffeSocket is the SPIRE Workload API socket (standard SPIFFE var).
	EnvSpiffeSocket = "SPIFFE_ENDPOINT_SOCKET"
)

// DefaultTokenFile is the projected-token path used by the Kubernetes/GKE serviceAccountToken volume
// convention. DefaultSpiffeSocket is the default SPIRE agent socket.
const (
	DefaultTokenFile    = "/var/run/secrets/tokens/attester-token"
	DefaultSpiffeSocket = "/tmp/spire-agent/public/api.sock"
)

// The paths AutoDetectEvidence probes. Variables so tests can point them elsewhere; unexported so nothing
// outside the package can.
var (
	defaultTokenFile    = DefaultTokenFile
	defaultSpiffeSocket = DefaultSpiffeSocket
)

// gcpMetadataIdentity is the GCP metadata server identity endpoint (returns a Google-signed ID token for
// the runtime service account).
const gcpMetadataIdentity = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"

// gcpMetadataProbe is swapped by tests; it reports whether the GCP metadata server is reachable.
var gcpMetadataProbe = gcpMetadataAvailable

// EvidenceNotFound is returned when no platform identity could be detected and none was supplied.
type EvidenceNotFound struct{ msg string }

func (e *EvidenceNotFound) Error() string { return e.msg }

// FileTokenSvidSource reads the evidence token from a file on every fetch.
//
// Kubernetes and GKE mount a short-lived, auto-rotated service-account token into the pod as a file (a
// projected serviceAccountToken volume). Reading it fresh each time picks up the rotation. The file's
// audience must already be the attester's evidence audience — set it when you declare the volume.
type FileTokenSvidSource struct{ Path string }

// Fetch reads and returns the token from the file (audience is fixed when the volume is declared).
func (s FileTokenSvidSource) Fetch(string) (string, error) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return "", fmt.Errorf("unable to read token file %s: %w", s.Path, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// GoogleMetadataSvidSource fetches a Google-signed ID token for the runtime service account from the GCP
// metadata server. Works on any Google runtime that exposes the metadata server (GCE, GKE, Cloud Run,
// Vertex AI Agent Engine). The token's aud is the attester's evidence audience; sub is the service
// account. No google-auth dependency — a plain metadata call.
type GoogleMetadataSvidSource struct {
	Timeout time.Duration
	Client  *http.Client
}

// Fetch requests an identity token whose audience is the given evidence audience.
func (s GoogleMetadataSvidSource) Fetch(audience string) (string, error) {
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	client := safeClient(s.Client, timeout)
	target := gcpMetadataIdentity + "?audience=" + url.QueryEscape(audience) + "&format=full"
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	res, err := doRequest(ctx, client, http.MethodGet, target, map[string]string{"Metadata-Flavor": "Google"}, nil, defaultMaxResponseBytes)
	if err != nil {
		return "", err
	}
	if !res.ok() {
		// The body is a plain JWT on success, not JSON — so the status check is done here.
		return "", &ClientAttestationError{
			Message: "GCP metadata identity endpoint returned HTTP " + strconv.Itoa(res.Status),
			Status:  res.Status,
			Body:    truncateBody(res.Body),
		}
	}
	return strings.TrimSpace(string(res.Body)), nil
}

// gcpMetadataProbeURL is the URL gcpMetadataAvailable probes; a variable so tests can point it at a
// local fake instead of the real metadata server.
var gcpMetadataProbeURL = "http://metadata.google.internal/computeMetadata/v1/"

// gcpMetadataAvailable reports whether the GCP metadata server answers a quick probe.
func gcpMetadataAvailable() bool {
	return metadataAnswers(gcpMetadataProbeURL, 300*time.Millisecond)
}

// metadataAnswers reports whether target answers at all (any status) within timeout.
func metadataAnswers(target string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, err := doRequest(ctx, safeClient(nil, timeout), http.MethodGet, target, map[string]string{"Metadata-Flavor": "Google"}, nil, 64*1024)
	return err == nil
}

// AutoDetectEvidence returns the first evidence source that applies to this runtime, or an
// *EvidenceNotFound error with guidance.
//
// Order: explicit env token, projected token file, SPIRE socket, GCP metadata server. A token-file or
// SPIFFE socket variable that is set but points at a missing path is an *EvidenceNotFound naming the
// variable; it never falls through to the next source.
func AutoDetectEvidence() (SvidSource, error) {
	if static := strings.TrimSpace(os.Getenv(EnvSVID)); static != "" {
		return StaticSvidSource{SVID: static}, nil
	}

	// An explicitly configured source that is missing is an error, never a fall-through to the next one.
	if tokenFile := os.Getenv(EnvTokenFile); tokenFile != "" {
		if !isFile(tokenFile) {
			return nil, &EvidenceNotFound{msg: fmt.Sprintf("%s is set to %s, but no such file exists", EnvTokenFile, tokenFile)}
		}
		return FileTokenSvidSource{Path: tokenFile}, nil
	}
	if isFile(defaultTokenFile) {
		return FileTokenSvidSource{Path: defaultTokenFile}, nil
	}

	socketPath := defaultSpiffeSocket
	if socket := os.Getenv(EnvSpiffeSocket); socket != "" {
		socketPath = strings.TrimPrefix(socket, "unix://")
		if !pathExists(socketPath) {
			return nil, &EvidenceNotFound{msg: fmt.Sprintf("%s is set to %s, but no such socket exists", EnvSpiffeSocket, socket)}
		}
		return SpireWorkloadAPISvidSource{SocketPath: socketPath}, nil
	}
	if pathExists(socketPath) {
		return SpireWorkloadAPISvidSource{SocketPath: socketPath}, nil
	}

	if gcpMetadataProbe() {
		return GoogleMetadataSvidSource{}, nil
	}

	return nil, &EvidenceNotFound{msg: fmt.Sprintf(
		"could not auto-detect the workload's platform identity; set one of %s (the token), %s (a token file), "+
			"or %s (SPIRE socket), or pass an explicit evidence source with WithEvidence(...)",
		EnvSVID, EnvTokenFile, EnvSpiffeSocket)}
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
