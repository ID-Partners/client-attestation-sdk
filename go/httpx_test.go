package clientattestation

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// redirectPair starts a target server that counts hits and a front server that 302s every request to it.
func redirectPair(t *testing.T) (front *httptest.Server, targetHits *int32) {
	t.Helper()
	var hits int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		writeJSON(w, 200, map[string]any{"svid": "leaked"})
	}))
	t.Cleanup(target.Close)
	front = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(front.Close)
	return front, &hits
}

func asSDKError(t *testing.T, err error) *ClientAttestationError {
	t.Helper()
	var sdkErr *ClientAttestationError
	if !errors.As(err, &sdkErr) {
		t.Fatalf("error %v (%T) is not a *ClientAttestationError", err, err)
	}
	return sdkErr
}

func TestDoRequestRefusesRedirectWithoutContactingTarget(t *testing.T) {
	front, hits := redirectPair(t)
	_, err := doRequest(context.Background(), safeClient(nil, time.Second), http.MethodGet, front.URL+"/x",
		map[string]string{"Authorization": "Bearer secret"}, nil, 0)
	if err == nil {
		t.Fatal("redirect was followed")
	}
	if sdkErr := asSDKError(t, err); sdkErr.Status != http.StatusFound || !strings.Contains(sdkErr.Message, "redirect") {
		t.Fatalf("unexpected redirect error: %+v", sdkErr)
	}
	if n := atomic.LoadInt32(hits); n != 0 {
		t.Fatalf("redirect target contacted %d times", n)
	}
}

func TestEveryCallSiteRefusesRedirects(t *testing.T) {
	front, hits := redirectPair(t)

	ca, err := NewClientAttestation(front.URL, WithEvidenceAudience(shortAudience), WithEvidence(StaticSvidSource{SVID: "s"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Token(context.Background()); err == nil {
		t.Error("token source followed a redirect")
	}
	if _, err := (HTTPSvidSource{URL: front.URL + "/svid"}).Fetch("aud"); err == nil {
		t.Error("HTTPSvidSource followed a redirect")
	}
	ic, err := NewAttestationIssuanceClient(front.URL+"/federation/attestation", "c", "aud", StaticSvidSource{SVID: "s"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ic.Bootstrap(nil, ""); err == nil {
		t.Error("issuance client followed a redirect")
	}
	if _, err := NewOpenBaoTransitSigner(front.URL, "tok", "k"); err == nil {
		t.Error("OpenBao signer followed a redirect")
	}
	if n := atomic.LoadInt32(hits); n != 0 {
		t.Fatalf("redirect target contacted %d times", n)
	}
}

func TestInjectedClientIsNotMutated(t *testing.T) {
	front, hits := redirectPair(t)
	injected := &http.Client{}
	ca, err := NewClientAttestation(front.URL, WithEvidenceAudience(shortAudience), WithEvidence(StaticSvidSource{SVID: "s"}), WithHTTPClient(injected))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Token(context.Background()); err == nil {
		t.Fatal("redirect was followed through an injected client")
	}
	if _, err := (HTTPSvidSource{URL: front.URL, Client: injected}).Fetch("aud"); err == nil {
		t.Fatal("redirect was followed through an injected client")
	}
	if injected.CheckRedirect != nil || injected.Timeout != 0 {
		t.Fatalf("injected client was mutated: %+v", injected)
	}
	if atomic.LoadInt32(hits) != 0 {
		t.Fatal("redirect target contacted")
	}
}

func TestSafeClientOverridesCallerRedirectPolicy(t *testing.T) {
	custom := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c := &http.Client{Timeout: 3 * time.Second, CheckRedirect: custom}
	if got := safeClient(c, time.Second); got == c || got.Timeout != c.Timeout {
		t.Fatal("the client must be copied while preserving its timeout")
	}
	c2 := &http.Client{CheckRedirect: custom}
	got := safeClient(c2, time.Second)
	if got == c2 || got.Timeout != time.Second || got.CheckRedirect == nil || c2.Timeout != 0 {
		t.Fatalf("expected a copy with the default timeout, got %+v", got)
	}
	// The caller's policy cannot weaken the SDK redirect refusal.
	front, hits := redirectPair(t)
	_, err := doRequest(context.Background(), got, http.MethodGet, front.URL, nil, nil, 0)
	if err == nil || atomic.LoadInt32(hits) != 0 {
		t.Fatalf("redirect not refused: %v", err)
	}
}

func TestInjectedClientCannotAllowCredentialRedirect(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer target.Close()
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("OAuth-Client-Attestation") != "attestation" {
			t.Error("missing test credential")
		}
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer front.Close()
	var policyCalls atomic.Int32
	injected := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { policyCalls.Add(1); return nil }}
	_, err := doRequest(context.Background(), safeClient(injected, time.Second), http.MethodPost, front.URL,
		map[string]string{"OAuth-Client-Attestation": "attestation", "DPoP": "proof"}, []byte("svid=secret"), 0)
	if err == nil || hits.Load() != 0 || policyCalls.Load() != 0 {
		t.Fatalf("redirect escaped SDK policy: err=%v target=%d policy=%d", err, hits.Load(), policyCalls.Load())
	}
	if injected.CheckRedirect == nil || injected.Timeout != time.Second {
		t.Fatal("caller client was mutated")
	}
}

func TestDoRequestRefusesOversizeBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", int(defaultMaxResponseBytes)+10)))
	}))
	defer srv.Close()
	_, err := doRequest(context.Background(), safeClient(nil, 5*time.Second), http.MethodGet, srv.URL, nil, nil, 0)
	if err == nil || !strings.Contains(asSDKError(t, err).Message, "exceeds") {
		t.Fatalf("oversize body not refused: %v", err)
	}
	// Exactly at the cap is fine.
	small := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("12345"))
	}))
	defer small.Close()
	res, err := doRequest(context.Background(), safeClient(nil, time.Second), http.MethodGet, small.URL, nil, nil, 5)
	if err != nil || string(res.Body) != "12345" {
		t.Fatalf("body at the cap refused: %v", err)
	}
	if _, err := doRequest(context.Background(), safeClient(nil, time.Second), http.MethodGet, small.URL, nil, nil, 4); err == nil {
		t.Fatal("body over a custom cap not refused")
	}
}

func TestDecodeJSONOKNon2xxIsTypedAndTruncated(t *testing.T) {
	long := strings.Repeat("e", 2000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(long))
	}))
	defer srv.Close()
	res, err := doRequest(context.Background(), safeClient(nil, time.Second), http.MethodGet, srv.URL, nil, nil, 0)
	if err != nil {
		t.Fatalf("non-2xx must not error in doRequest: %v", err)
	}
	if res.Status != http.StatusServiceUnavailable || len(res.Body) != 2000 {
		t.Fatalf("unexpected result: %d / %d bytes", res.Status, len(res.Body))
	}
	sdkErr := asSDKError(t, decodeJSONOK(res, "GET x", nil))
	if sdkErr.Status != http.StatusServiceUnavailable || len(sdkErr.Body) != maxErrorBodyBytes {
		t.Fatalf("status %d, body %d bytes", sdkErr.Status, len(sdkErr.Body))
	}

	// The same through a public call site.
	_, err = (HTTPSvidSource{URL: srv.URL}).Fetch("aud")
	if asSDKError(t, err).Status != http.StatusServiceUnavailable {
		t.Fatalf("svid source: %v", err)
	}
}

func TestDecodeJSONOKMalformedJSONIsTyped(t *testing.T) {
	err := decodeJSONOK(&httpResult{Status: 200, Body: []byte("{not json")}, "GET x", &struct{}{})
	if sdkErr := asSDKError(t, err); !strings.Contains(sdkErr.Message, "unparseable JSON") || sdkErr.Body != "" {
		t.Fatalf("unexpected: %v (body %q)", sdkErr, sdkErr.Body)
	}
	if err := decodeJSONOK(&httpResult{Status: 204}, "GET x", nil); err != nil {
		t.Fatalf("2xx with nil target should pass: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>"))
	}))
	defer srv.Close()
	ic, _ := NewAttestationIssuanceClient(srv.URL, "c", "aud", StaticSvidSource{SVID: "s"})
	_, err = ic.Bootstrap(nil, "")
	asSDKError(t, err)
	ca, _ := NewClientAttestation(srv.URL)
	_, err = ca.AttesterMetadata(context.Background())
	asSDKError(t, err)
}

func TestIssuanceNon2xxStillIssuanceError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 403, map[string]any{"error": "denied"})
	}))
	defer srv.Close()
	ic, _ := NewAttestationIssuanceClient(srv.URL, "c", "aud", StaticSvidSource{SVID: "s"})
	_, err := ic.Bootstrap(nil, "")
	var issErr *IssuanceError
	if !errors.As(err, &issErr) || issErr.Status != 403 || !strings.Contains(issErr.Body, "denied") {
		t.Fatalf("want *IssuanceError 403, got %v", err)
	}
}

func TestDoRequestTimesOut(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	start := time.Now()
	_, err := doRequest(context.Background(), safeClient(nil, 100*time.Millisecond), http.MethodGet, srv.URL, nil, nil, 0)
	if err == nil {
		t.Fatal("expected a timeout")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("timeout took %v", time.Since(start))
	}
	if metadataAnswers(srv.URL, 100*time.Millisecond) {
		t.Fatal("a hanging metadata server must not count as available")
	}
}

func TestGoogleMetadataSvidSourceUsesHelper(t *testing.T) {
	var gotFlavor string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotFlavor = r.Header.Get("Metadata-Flavor")
		w.Header().Set("Metadata-Flavor", "Google")
		if r.URL.Query().Get("audience") == "bad" {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte("  id.token.jwt\n"))
	}))
	defer srv.Close()
	target, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: rewriteHost{target: target}}
	tok, err := GoogleMetadataSvidSource{Client: client}.Fetch("aud")
	if err != nil || tok != "id.token.jwt" || gotFlavor != "Google" {
		t.Fatalf("tok=%q err=%v flavor=%q", tok, err, gotFlavor)
	}
	_, err = GoogleMetadataSvidSource{Client: client}.Fetch("bad")
	if asSDKError(t, err).Status != 404 {
		t.Fatalf("unexpected: %v", err)
	}
	if !metadataAnswers(srv.URL, time.Second) {
		t.Fatal("a reachable metadata server should be available")
	}
}

// rewriteHost sends every request to target, so the fixed metadata URL can be served by httptest.
type rewriteHost struct{ target *url.URL }

func (rt rewriteHost) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme, clone.URL.Host = rt.target.Scheme, rt.target.Host
	return http.DefaultTransport.RoundTrip(clone)
}

// ── token source: ctx-aware lock and force refresh ──────────────────────────────────────────────────

// countingAttester is a minimal attester (no challenge endpoint) that counts token endpoint calls and
// can hold the token endpoint until gate is closed.
func countingAttester(t *testing.T, gate chan struct{}, entered chan struct{}) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	var once sync.Once
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/client-attester", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"attestation_endpoint": srv.URL + "/mint",
			"token_endpoint":       srv.URL + "/token",
			"evidence_audience":    shortAudience,
		})
	})
	mux.HandleFunc("/mint", func(w http.ResponseWriter, r *http.Request) {
		sub := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"c"}`))
		writeJSON(w, 200, map[string]any{"attestation": "h." + sub + ".s"})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if entered != nil {
			once.Do(func() { close(entered) })
		}
		if gate != nil {
			<-gate
		}
		writeJSON(w, 200, map[string]any{"access_token": "AT-" + string(rune('0'+n)), "expires_in": 3600})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestTokenWaiterHonorsContextCancellation(t *testing.T) {
	gate, entered := make(chan struct{}), make(chan struct{})
	srv, calls := countingAttester(t, gate, entered)
	ca, err := NewClientAttestation(srv.URL, WithEvidenceAudience(shortAudience), WithEvidence(StaticSvidSource{SVID: "s"}))
	if err != nil {
		t.Fatal(err)
	}

	type result struct {
		tok string
		err error
	}
	first := make(chan result, 1)
	go func() {
		tok, err := ca.Token(context.Background())
		first <- result{tok, err}
	}()
	<-entered // the first caller now holds the lock inside the token endpoint call

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = ca.Token(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter got %v, want context.DeadlineExceeded", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("cancelled waiter took %v", time.Since(start))
	}
	if _, err := ca.AttesterMetadata(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Discovery waiter got %v", err)
	}

	// A patient waiter queues, then gets the cached token (single-flight: no second fetch).
	second := make(chan result, 1)
	go func() {
		tok, err := ca.Token(context.Background())
		second <- result{tok, err}
	}()
	close(gate)
	r1, r2 := <-first, <-second
	if r1.err != nil || r2.err != nil || r1.tok != "AT-1" || r2.tok != "AT-1" {
		t.Fatalf("first=%+v second=%+v", r1, r2)
	}
	if n := atomic.LoadInt32(calls); n != 1 {
		t.Fatalf("token endpoint called %d times, want 1", n)
	}

	// An already-cancelled ctx fails fast even when the lock is free.
	done, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if _, err := ca.Token(done); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

func TestForceRefreshBypassesCache(t *testing.T) {
	srv, calls := countingAttester(t, nil, nil)
	ca, err := NewClientAttestation(srv.URL, WithEvidenceAudience(shortAudience), WithEvidence(StaticSvidSource{SVID: "s"}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	t1, _ := ca.Token(ctx)
	t2, _ := ca.TokenWithOptions(ctx)
	if t1 != "AT-1" || t2 != "AT-1" || atomic.LoadInt32(calls) != 1 {
		t.Fatalf("cache not used: %s %s %d", t1, t2, *calls)
	}
	t3, err := ca.TokenWithOptions(ctx, WithForceRefresh())
	if err != nil || t3 != "AT-2" || atomic.LoadInt32(calls) != 2 {
		t.Fatalf("force refresh: %s %v %d", t3, err, *calls)
	}
	// The forced token replaced the cache.
	if t4, _ := ca.Token(ctx); t4 != "AT-2" {
		t.Fatalf("cache not updated: %s", t4)
	}
	h, err := ca.AuthorizationHeaderWithOptions(ctx, WithForceRefresh())
	if err != nil || h != "Bearer AT-3" {
		t.Fatalf("header: %s %v", h, err)
	}
}

func TestTokenEndpointErrorBodyIsCapped(t *testing.T) {
	long := `{"error":"invalid_client","error_description":"` + strings.Repeat("d", 1000) + `"}`
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/client-attester", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"attestation_endpoint": srv.URL + "/mint", "token_endpoint": srv.URL + "/token", "evidence_audience": shortAudience})
	})
	mux.HandleFunc("/mint", func(w http.ResponseWriter, r *http.Request) {
		sub := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"c"}`))
		writeJSON(w, 200, map[string]any{"attestation": "h." + sub + ".s"})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(long))
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()
	ca, _ := NewClientAttestation(srv.URL, WithEvidenceAudience(shortAudience), WithEvidence(StaticSvidSource{SVID: "s"}))
	_, err := ca.Token(context.Background())
	sdkErr := asSDKError(t, err)
	if sdkErr.Status != 401 || sdkErr.Body != long[:maxErrorBodyBytes] {
		t.Fatalf("status %d, body %d bytes", sdkErr.Status, len(sdkErr.Body))
	}
}

func TestOpenBaoNon200IsTyped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
	}))
	defer srv.Close()
	_, err := NewOpenBaoTransitSigner(srv.URL, "bad", "k")
	if sdkErr := asSDKError(t, err); sdkErr.Status != http.StatusForbidden {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestDoRequestRefusesUserinfoWithoutNamingIt(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	for _, target := range []string{
		"http://alice:s3cret@" + u.Host + "/x?q=1",
		"https://alice:s3cret@example.invalid/x",
		"https://alice@example.invalid/x",
	} {
		_, err := doRequest(context.Background(), safeClient(nil, time.Second), http.MethodGet, target, nil, nil, 0)
		sdkErr := asSDKError(t, err)
		if strings.Contains(sdkErr.Message, "s3cret") || strings.Contains(sdkErr.Message, "alice") ||
			!strings.Contains(sdkErr.Message, "userinfo") {
			t.Errorf("%s: %q", target, sdkErr.Message)
		}
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("server contacted %d times", n)
	}
}

func TestDoRequestErrorsOmitTheQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	target := srv.URL + "/token?client_secret=s3cret"
	srv.Close() // connection refused
	_, err := doRequest(context.Background(), safeClient(nil, time.Second), http.MethodGet, target, nil, nil, 0)
	var ue *url.Error
	if err == nil || !errors.As(err, &ue) {
		t.Fatalf("want a *url.Error, got %v", err)
	}
	if strings.Contains(err.Error(), "s3cret") || !strings.Contains(err.Error(), "/token") {
		t.Fatalf("error = %q", err)
	}
}

func TestSafeClientUsesTheSDKProxyPolicy(t *testing.T) {
	if c := safeClient(nil, time.Second); c.Transport == nil {
		t.Fatal("SDK client falls back to http.DefaultTransport (ProxyFromEnvironment proxies plain http)")
	}
	if c := safeClient(&http.Client{}, time.Second); c.Transport == nil {
		t.Fatal("caller client without a Transport falls back to http.DefaultTransport")
	}
	own := &http.Transport{}
	if c := safeClient(&http.Client{Transport: own}, time.Second); c.Transport != own {
		t.Fatal("caller's own Transport replaced")
	}
}

// safeClient never returns a client without a timeout, whatever its caller passes.
func TestSafeClientAlwaysHasATimeout(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second} {
		if got := safeClient(nil, d); got.Timeout != fallbackTimeout {
			t.Fatalf("safeClient(nil, %v).Timeout = %v", d, got.Timeout)
		}
		if got := safeClient(&http.Client{Timeout: -time.Second}, d); got.Timeout != fallbackTimeout {
			t.Fatalf("safeClient(negative, %v).Timeout = %v", d, got.Timeout)
		}
	}
	if got := safeClient(&http.Client{Timeout: -time.Second}, 2*time.Second); got.Timeout != 2*time.Second {
		t.Fatalf("negative client timeout: got %v", got.Timeout)
	}
}
