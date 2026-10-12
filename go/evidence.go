package clientattestation

import (
	"context"
	"fmt"
	"io"
	"net"
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

// maxTokenFileBytes caps how much of a token file is read. A projected token is a few KiB; a larger file
// (or one that never ends) is a misconfiguration.
const maxTokenFileBytes = 64 * 1024

// metadataTransport carries the SDK's own GCP metadata requests. It never uses a proxy: the metadata
// server is reached directly, and the identity request is plain HTTP, so a proxy taken from HTTP_PROXY
// would see the ID token.
var metadataTransport http.RoundTripper = newMetadataTransport(http.DefaultTransport)

// newMetadataTransport clones base without its proxy, or, when something has replaced
// http.DefaultTransport with a wrapper that is not an *http.Transport, builds a fresh direct transport.
func newMetadataTransport(base http.RoundTripper) *http.Transport {
	if t, ok := base.(*http.Transport); ok {
		t = t.Clone()
		t.Proxy = nil
		return t
	}
	return &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// EvidenceNotFound is returned when no platform identity could be detected and none was supplied.
type EvidenceNotFound struct{ msg string }

func (e *EvidenceNotFound) Error() string { return e.msg }

// FileTokenSvidSource reads the evidence token from a file on every fetch.
//
// Kubernetes and GKE mount a short-lived, auto-rotated service-account token into the pod as a file (a
// projected serviceAccountToken volume). Reading it fresh each time picks up the rotation. The file's
// audience must already be the attester's evidence audience — set it when you declare the volume.
type FileTokenSvidSource struct{ Path string }

// Fetch reads and returns the token from the file (audience is fixed when the volume is declared). The
// path must be a regular file of at most 64 KiB; anything else is an *EvidenceNotFound.
func (s FileTokenSvidSource) Fetch(string) (string, error) {
	// Checked before opening: opening a FIFO blocks, and a device such as /dev/zero never ends.
	info, err := os.Stat(s.Path)
	if err != nil {
		return "", fmt.Errorf("unable to read token file %s: %w", s.Path, err)
	}
	if !info.Mode().IsRegular() {
		return "", &EvidenceNotFound{msg: fmt.Sprintf("token file %s is not a regular file", s.Path)}
	}
	f, err := os.Open(s.Path)
	if err != nil {
		return "", fmt.Errorf("unable to read token file %s: %w", s.Path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxTokenFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("unable to read token file %s: %w", s.Path, err)
	}
	if len(data) > maxTokenFileBytes {
		return "", &EvidenceNotFound{msg: fmt.Sprintf("token file %s is larger than %d bytes", s.Path, maxTokenFileBytes)}
	}
	return strings.TrimSpace(string(data)), nil
}

// GoogleMetadataSvidSource fetches a Google-signed ID token for the runtime service account from the GCP
// metadata server. Works on any Google runtime that exposes the metadata server (GCE, GKE, Cloud Run,
// Vertex AI Agent Engine). The token's aud is the attester's evidence audience; sub is the service
// account. No google-auth dependency — a plain metadata call. The answer must be HTTP 200 carrying the
// Metadata-Flavor: Google response header, as the real metadata server sends. Without a Client, the
// request goes direct, never through a proxy.
type GoogleMetadataSvidSource struct {
	Timeout time.Duration // bounds the request; zero or negative means 5s
	Client  *http.Client
}

// Fetch requests an identity token whose audience is the given evidence audience.
func (s GoogleMetadataSvidSource) Fetch(audience string) (string, error) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	client := s.Client
	if client == nil {
		client = &http.Client{Transport: metadataTransport}
	}
	client = safeClient(client, timeout)
	target := gcpMetadataIdentity + "?audience=" + url.QueryEscape(audience) + "&format=full"
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	res, err := doRequest(ctx, client, http.MethodGet, target, map[string]string{"Metadata-Flavor": "Google"}, nil, defaultMaxResponseBytes)
	if err != nil {
		return "", err
	}
	if res.Status != http.StatusOK {
		// The body is a plain JWT on success, not JSON — so the status check is done here.
		return "", &ClientAttestationError{
			Message: "GCP metadata identity endpoint returned HTTP " + strconv.Itoa(res.Status),
			Status:  res.Status,
			Body:    truncateBody(res.Body),
		}
	}
	if !fromGoogleMetadata(res) {
		return "", &ClientAttestationError{
			Message: "GCP metadata identity endpoint answered without the Metadata-Flavor: Google header",
			Status:  res.Status,
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

// metadataAnswers reports whether the GCP metadata server answers at target within timeout: HTTP 200 with
// the Metadata-Flavor: Google response header. metadata.google.internal is a DNS name, so whatever a
// search domain, LLMNR or a hostile resolver points it at could answer; the header is what google-auth
// checks too.
func metadataAnswers(target string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client := safeClient(&http.Client{Transport: metadataTransport}, timeout)
	res, err := doRequest(ctx, client, http.MethodGet, target, map[string]string{"Metadata-Flavor": "Google"}, nil, 64*1024)
	return err == nil && res.Status == http.StatusOK && fromGoogleMetadata(res)
}

// fromGoogleMetadata reports whether a response carries the header the GCP metadata server always sets.
func fromGoogleMetadata(res *httpResult) bool {
	return res.Header.Get("Metadata-Flavor") == "Google"
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
