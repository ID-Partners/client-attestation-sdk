package clientattestation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Every outbound HTTP call the SDK makes goes through doRequest so that it behaves the same way
// everywhere: it always has a timeout, never follows a redirect (requests carry credentials —
// Authorization, DPoP, OAuth-Client-Attestation, X-Vault-Token headers and SVIDs in bodies), and reads
// at most a bounded response body.

// defaultMaxResponseBytes caps every response body the SDK reads (1 MiB).
const defaultMaxResponseBytes int64 = 1 << 20

// maxErrorBodyBytes caps how much of a non-2xx response body is carried in an error.
const maxErrorBodyBytes = 512

// httpResult is a fully read (and size-capped) HTTP response.
type httpResult struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r *httpResult) ok() bool { return r.Status >= 200 && r.Status < 300 }

// refuseRedirect is the CheckRedirect the SDK installs: no redirect is ever followed, so credentials are
// never replayed to a host the caller did not name. The redirect target is not contacted.
func refuseRedirect(req *http.Request, _ []*http.Request) error {
	status := 0
	if req.Response != nil {
		status = req.Response.StatusCode
	}
	return &ClientAttestationError{
		Message: fmt.Sprintf("refusing to follow HTTP redirect to %s://%s", req.URL.Scheme, req.URL.Host),
		Status:  status,
	}
}

// safeClient returns the client to use for SDK requests. A nil client yields a fresh one with
// defaultTimeout. A caller-supplied client is copied without mutation. SDK calls always refuse
// redirects, including when the caller's client has a redirect policy that permits them.
func safeClient(client *http.Client, defaultTimeout time.Duration) *http.Client {
	if client == nil {
		return &http.Client{Timeout: defaultTimeout, CheckRedirect: refuseRedirect}
	}
	cp := *client
	cp.CheckRedirect = refuseRedirect
	if cp.Timeout <= 0 {
		cp.Timeout = defaultTimeout
	}
	return &cp
}

// doRequest performs one HTTP request and reads the response body (at most maxBytes; 0 means
// defaultMaxResponseBytes). A non-2xx status is NOT an error here — callers decide (see decodeJSONOK).
// Transport errors (including a refused redirect or a timeout) are returned as-is.
func doRequest(ctx context.Context, client *http.Client, method, target string, headers map[string]string, body []byte, maxBytes int64) (*httpResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if maxBytes <= 0 {
		maxBytes = defaultMaxResponseBytes
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, &ClientAttestationError{Message: fmt.Sprintf("reading response from %s %s: %v", method, target, err), Status: resp.StatusCode}
	}
	if int64(len(raw)) > maxBytes {
		return nil, &ClientAttestationError{
			Message: fmt.Sprintf("response from %s %s exceeds %d bytes", method, target, maxBytes),
			Status:  resp.StatusCode,
		}
	}
	return &httpResult{Status: resp.StatusCode, Header: resp.Header, Body: raw}, nil
}

// decodeJSONOK fails with a *ClientAttestationError on a non-2xx status (carrying the status and at most
// maxErrorBodyBytes of the body), otherwise decodes the body into v (skipped when v is nil). A body that
// is not valid JSON is a *ClientAttestationError too. what names the call in messages ("GET https://…").
func decodeJSONOK(res *httpResult, what string, v any) error {
	if !res.ok() {
		return &ClientAttestationError{
			Message: fmt.Sprintf("%s returned HTTP %d", what, res.Status),
			Status:  res.Status,
			Body:    truncateBody(res.Body),
		}
	}
	if v == nil {
		return nil
	}
	if err := json.Unmarshal(res.Body, v); err != nil {
		return &ClientAttestationError{Message: fmt.Sprintf("%s returned unparseable JSON: %v", what, err), Body: truncateBody(res.Body)}
	}
	return nil
}

func truncateBody(b []byte) string {
	if len(b) > maxErrorBodyBytes {
		return string(b[:maxErrorBodyBytes])
	}
	return string(b)
}
