package clientattestation

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// verifiedProof is a DPoP proof whose signature was checked against the jwk in its own header.
type verifiedProof struct {
	claims     map[string]any
	thumbprint string
}

// verifyDpopProof verifies a DPoP proof's signature with the embedded jwk header and returns its claims
// and the RFC 7638 thumbprint of that jwk.
func verifyDpopProof(proof string) (*verifiedProof, error) {
	msg, err := jws.Parse([]byte(proof))
	if err != nil || len(msg.Signatures()) != 1 {
		return nil, fmt.Errorf("parse proof: %v", err)
	}
	hdr := msg.Signatures()[0].ProtectedHeaders()
	if hdr.Type() != DpopTyp {
		return nil, fmt.Errorf("typ = %q", hdr.Type())
	}
	key := hdr.JWK()
	if key == nil {
		return nil, fmt.Errorf("proof has no jwk header")
	}
	payload, err := jws.Verify([]byte(proof), jws.WithKey(jwa.SignatureAlgorithm(hdr.Algorithm().String()), key))
	if err != nil {
		return nil, fmt.Errorf("proof signature: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	tp, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return &verifiedProof{claims: claims, thumbprint: base64.RawURLEncoding.EncodeToString(tp)}, nil
}

// dpopAS is a fake attester + AS that issues DPoP-bound tokens: it records, per issued token, the
// thumbprint of the key that signed the token-endpoint DPoP proof (the token's cnf.jkt).
type dpopAS struct {
	srv         *httptest.Server
	tokenType   string
	demandNonce string // when set, the token endpoint answers 400 use_dpop_nonce until a proof carries it

	mu          sync.Mutex
	jkt         map[string]string
	issued      int
	tokenCalls  int
	proofNonces []any
}

func newDpopAS(t *testing.T, tokenType string) *dpopAS {
	t.Helper()
	as := &dpopAS{tokenType: tokenType, jkt: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/client-attester", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"attestation_endpoint": as.srv.URL + "/federation/attestation",
			"challenge_endpoint":   as.srv.URL + "/federation/attestation-challenge",
			"token_endpoint":       as.srv.URL + "/as/token.oauth2?ignored=1",
			"evidence_audience":    "https://attester.example.com",
		})
	})
	mux.HandleFunc("/federation/attestation-challenge", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"attestation_challenge": "chal-123"})
	})
	mux.HandleFunc("/federation/attestation", func(w http.ResponseWriter, r *http.Request) {
		sub := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"demo-client"}`))
		writeJSON(w, 200, map[string]any{"attestation": "h." + sub + ".sig"})
	})
	mux.HandleFunc("/as/token.oauth2", func(w http.ResponseWriter, r *http.Request) {
		as.mu.Lock()
		defer as.mu.Unlock()
		as.tokenCalls++
		proof, err := verifyDpopProof(r.Header.Get(DpopHeader))
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": "invalid_dpop_proof", "error_description": err.Error()})
			return
		}
		as.proofNonces = append(as.proofNonces, proof.claims["nonce"])
		if proof.claims["htm"] != "POST" || proof.claims["htu"] != as.srv.URL+"/as/token.oauth2" {
			writeJSON(w, 400, map[string]any{"error": "invalid_dpop_proof", "error_description": "htm/htu"})
			return
		}
		if as.demandNonce != "" && proof.claims["nonce"] != as.demandNonce {
			w.Header().Set(DpopNonceHeader, as.demandNonce)
			writeJSON(w, 400, map[string]any{"error": "use_dpop_nonce"})
			return
		}
		as.issued++
		token := fmt.Sprintf("AT-%d", as.issued)
		as.jkt[token] = proof.thumbprint
		writeJSON(w, 200, map[string]any{"access_token": token, "expires_in": 3600, "token_type": as.tokenType})
	})
	as.srv = httptest.NewServer(mux)
	t.Cleanup(as.srv.Close)
	return as
}

func (as *dpopAS) calls() (int, []any) {
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.tokenCalls, append([]any(nil), as.proofNonces...)
}

func (as *dpopAS) jktFor(token string) string {
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.jkt[token]
}

// dpopResource is a fake resource server that checks a DPoP-bound token the way RFC 9449 §7 says:
// proof signature, cnf.jkt binding, htm, htu, ath and the server-issued nonce.
type dpopResource struct {
	srv       *httptest.Server
	nonce     string
	use400    bool // signal the nonce challenge as 400 JSON instead of 401 WWW-Authenticate
	hits      int32
	mu        sync.Mutex
	lastBody  string
	lastProof map[string]any
}

func (rs *dpopResource) proof() map[string]any {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.lastProof
}

func newDpopResource(t *testing.T, as *dpopAS) *dpopResource {
	t.Helper()
	rs := &dpopResource{nonce: "rs-nonce-1"}
	rs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&rs.hits, 1)
		rs.mu.Lock()
		defer rs.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		rs.lastBody = string(body)
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "DPoP ")
		if !ok {
			http.Error(w, "want DPoP scheme", 401)
			return
		}
		proof, err := verifyDpopProof(r.Header.Get(DpopHeader))
		if err != nil {
			http.Error(w, err.Error(), 401)
			return
		}
		rs.lastProof = proof.claims
		switch {
		case proof.thumbprint != as.jktFor(token):
			http.Error(w, "proof key does not match cnf.jkt", 401)
		case proof.claims["htm"] != r.Method:
			http.Error(w, "htm", 401)
		case proof.claims["htu"] != "http://"+r.Host+r.URL.Path:
			http.Error(w, fmt.Sprintf("htu %v", proof.claims["htu"]), 401)
		case proof.claims["ath"] != accessTokenHash(token):
			http.Error(w, "ath", 401)
		case proof.claims["nonce"] != rs.nonce:
			w.Header().Set(DpopNonceHeader, rs.nonce)
			if rs.use400 {
				writeJSON(w, 400, map[string]any{"error": "use_dpop_nonce"})
				return
			}
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce", error_description="nonce required"`)
			w.WriteHeader(401)
		default:
			w.WriteHeader(200)
			_, _ = w.Write([]byte("ok:" + rs.lastBody))
		}
	}))
	t.Cleanup(rs.srv.Close)
	return rs
}

func newDpopClient(t *testing.T, as *dpopAS) *ClientAttestation {
	t.Helper()
	ca, err := NewClientAttestation(as.srv.URL,
		WithEvidence(StaticSvidSource{SVID: "fake-svid"}),
		WithPopMethod(PopMethodDpopCombined))
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDpopRoundTripperRetriesOnceOnNonceChallenge(t *testing.T) {
	as := newDpopAS(t, "dpop") // lower-case: token_type is case-insensitive
	rs := newDpopResource(t, as)
	ca := newDpopClient(t, as)
	client := &http.Client{Transport: ca.RoundTripper()}

	resp, err := client.Get(rs.srv.URL + "/data?x=1#frag")
	if err != nil {
		t.Fatal(err)
	}
	if body := readAll(t, resp); resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if got := atomic.LoadInt32(&rs.hits); got != 2 {
		t.Fatalf("resource hits = %d, want 2 (challenge + one retry)", got)
	}
	if rs.proof()["nonce"] != "rs-nonce-1" {
		t.Fatalf("retry nonce = %v", rs.proof()["nonce"])
	}

	// The nonce is remembered for the origin: the next request succeeds first time.
	resp, err = client.Get(rs.srv.URL + "/data")
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	if resp.StatusCode != 200 || atomic.LoadInt32(&rs.hits) != 3 {
		t.Fatalf("status %d hits %d, want 200 after one more hit", resp.StatusCode, atomic.LoadInt32(&rs.hits))
	}
}

func TestDpopRoundTripperReplaysBodyOn400Challenge(t *testing.T) {
	as := newDpopAS(t, "DPoP")
	rs := newDpopResource(t, as)
	rs.use400 = true
	ca := newDpopClient(t, as)
	client := &http.Client{Transport: ca.RoundTripper()}

	resp, err := client.Post(rs.srv.URL+"/submit", "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != 200 || body != "ok:payload" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if rs.proof()["htm"] != "POST" || atomic.LoadInt32(&rs.hits) != 2 {
		t.Fatalf("htm %v hits %d", rs.proof()["htm"], atomic.LoadInt32(&rs.hits))
	}
}

func TestDpopRoundTripperDoesNotRetryUnreplayableBody(t *testing.T) {
	as := newDpopAS(t, "DPoP")
	rs := newDpopResource(t, as)
	ca := newDpopClient(t, as)
	client := &http.Client{Transport: ca.RoundTripper()}

	req, _ := http.NewRequest(http.MethodPost, rs.srv.URL+"/submit", io.NopCloser(strings.NewReader("payload")))
	req.GetBody = nil
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	if resp.StatusCode != 401 || resp.Header.Get(DpopNonceHeader) != "rs-nonce-1" {
		t.Fatalf("status %d, want the 401 challenge handed back", resp.StatusCode)
	}
	if atomic.LoadInt32(&rs.hits) != 1 {
		t.Fatalf("hits = %d, want 1 (no retry)", atomic.LoadInt32(&rs.hits))
	}
}

func TestDpopTokenEndpointNonceRetry(t *testing.T) {
	as := newDpopAS(t, "DPoP")
	as.demandNonce = "as-nonce"
	ca := newDpopClient(t, as)
	if _, err := ca.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls, nonces := as.calls()
	if calls != 2 || nonces[0] != "chal-123" || nonces[1] != "as-nonce" {
		t.Fatalf("calls %d nonces %v, want 2 [chal-123 as-nonce]", calls, nonces)
	}
}

func TestDpopTokenEndpointNonceRetryOnlyOnce(t *testing.T) {
	as := newDpopAS(t, "DPoP")
	as.demandNonce = "as-nonce"
	ca := newDpopClient(t, as)
	// Swap the demanded nonce after the first challenge so the retry is also refused.
	ca.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err == nil && strings.HasSuffix(r.URL.Path, "/as/token.oauth2") {
			as.mu.Lock()
			as.demandNonce += "x"
			as.mu.Unlock()
		}
		return resp, err
	}), CheckRedirect: refuseRedirect}
	_, err := ca.Token(context.Background())
	var caErr *ClientAttestationError
	if err == nil || !asError(err, &caErr) || caErr.Status != 400 {
		t.Fatalf("err = %v, want HTTP 400 ClientAttestationError", err)
	}
	if calls, _ := as.calls(); calls != 2 {
		t.Fatalf("token calls = %d, want 2", calls)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func asError(err error, target **ClientAttestationError) bool {
	e, ok := err.(*ClientAttestationError)
	*target = e
	return ok
}

func TestDpopKeySurvivesCacheAndChangesOnRefresh(t *testing.T) {
	as := newDpopAS(t, "DPoP")
	ca := newDpopClient(t, as)
	ctx := context.Background()

	proofKey := func(method, target string) (string, *verifiedProof) {
		h, err := ca.RequestHeaders(ctx, method, target)
		if err != nil {
			t.Fatal(err)
		}
		token, ok := strings.CutPrefix(h["Authorization"], "DPoP ")
		if !ok {
			t.Fatalf("Authorization = %q, want DPoP scheme", h["Authorization"])
		}
		p, err := verifyDpopProof(h[DpopHeader])
		if err != nil {
			t.Fatal(err)
		}
		if p.claims["ath"] != accessTokenHash(token) {
			t.Fatalf("ath mismatch")
		}
		if p.thumbprint != as.jktFor(token) {
			t.Fatalf("proof key is not the token's bound key")
		}
		return token, p
	}

	t1, p1 := proofKey("get", "HTTPS://API.Example.com:8443/r?q=1#f")
	if p1.claims["htm"] != "GET" || p1.claims["htu"] != "https://api.example.com:8443/r" {
		t.Fatalf("htm/htu = %v %v", p1.claims["htm"], p1.claims["htu"])
	}
	if _, hasNonce := p1.claims["nonce"]; hasNonce {
		t.Fatal("no nonce expected before the origin issued one")
	}
	t2, p2 := proofKey("POST", "https://api.example.com/r")
	if t1 != t2 || p1.thumbprint != p2.thumbprint || p1.claims["jti"] == p2.claims["jti"] {
		t.Fatal("cached token must keep its key, with a fresh jti per proof")
	}

	header, err := ca.AuthorizationHeader(ctx)
	if err != nil || header != "DPoP "+t1 {
		t.Fatalf("AuthorizationHeader = %q, %v", header, err)
	}

	if _, err := ca.TokenWithOptions(ctx, WithForceRefresh()); err != nil {
		t.Fatal(err)
	}
	t3, p3 := proofKey("GET", "https://api.example.com/r")
	if t3 == t1 || p3.thumbprint == p1.thumbprint {
		t.Fatal("a refreshed token must come with a new instance key")
	}
}

func TestBearerModeRequestHeadersUnchanged(t *testing.T) {
	srv, _ := fakeAttester(t)
	ca, err := NewClientAttestation(srv.URL, WithEvidence(StaticSvidSource{SVID: "fake-svid"}),
		WithPopMethod(PopMethodDpopCombined))
	if err != nil {
		t.Fatal(err)
	}
	h, err := ca.RequestHeaders(context.Background(), "GET", "https://api.example.com/x")
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 1 || h["Authorization"] != "Bearer AT-xyz" {
		t.Fatalf("headers = %v, want only the Bearer Authorization header", h)
	}

	// A Bearer-mode RoundTripper never retries, even when the server hands out a nonce.
	var hits int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.Header.Get(DpopHeader) != "" {
			t.Error("Bearer request must not carry a DPoP proof")
		}
		w.Header().Set(DpopNonceHeader, "n")
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
		w.WriteHeader(401)
	}))
	t.Cleanup(api.Close)
	resp, err := (&http.Client{Transport: ca.RoundTripper()}).Get(api.URL)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("hits = %d, want 1", got)
	}
}

func TestRequestHeadersPropagatesTokenErrors(t *testing.T) {
	ca, err := NewClientAttestation("http://127.0.0.1:1", WithEvidence(StaticSvidSource{SVID: "x"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.RequestHeaders(context.Background(), "GET", "https://api.example.com"); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := ca.AuthorizationHeader(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
	resp, err := (&http.Client{Transport: ca.RoundTripperOver(http.DefaultTransport)}).Post(
		"http://127.0.0.1:1", "text/plain", strings.NewReader("x"))
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected an error")
	}
}

func TestNormalizeHTUForm(t *testing.T) {
	cases := map[string]string{
		"https://Example.COM/a/b?x=1#f": "https://example.com/a/b",
		"HTTP://h:8080/p":               "http://h:8080/p",
		"https://h":                     "https://h",
		"/relative?q":                   "/relative",
		"no-scheme#frag":                "no-scheme",
		"plain":                         "plain",
		"https://h/a%20b?q":             "https://h/a%20b",
		"https://as.example:443/t":      "https://as.example/t",
		"http://as.example:80":          "http://as.example",
		"https://as.example:80/t":       "https://as.example:80/t",
		"https://[::1]:8443/p?q":        "https://[::1]:8443/p",
	}
	for in, want := range cases {
		if got := normalizeHTU(in); got != want {
			t.Errorf("normalizeHTU(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDpopBuilderNormalisesAndBindsAccessToken(t *testing.T) {
	key, _ := Generate("ES256")
	proof, err := NewDpopProofBuilder(key).Method("patch").URI("https://H/x?y#z").AccessToken("tok").Build()
	if err != nil {
		t.Fatal(err)
	}
	claims := decodeJWTClaims(t, proof)
	if claims["htm"] != "PATCH" || claims["htu"] != "https://h/x" {
		t.Fatalf("htm/htu = %v %v", claims["htm"], claims["htu"])
	}
	// RFC 9449 §4.2 / appendix example token "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"
	sum := accessTokenHash("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU")
	if sum != "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo" {
		t.Fatalf("ath = %s", sum)
	}
	if claims["ath"] != accessTokenHash("tok") {
		t.Fatalf("ath = %v", claims["ath"])
	}
}

func TestOriginOfSharesNonceAcrossDefaultPort(t *testing.T) {
	ca := &ClientAttestation{}
	ca.rememberNonce("https://API.example.com:443/a?x", "n1")
	if got := ca.nonceFor("https://api.example.com/b"); got != "n1" {
		t.Fatalf("nonceFor = %q, want n1", got)
	}
	if got := ca.nonceFor("https://api.example.com:8443/b"); got != "" {
		t.Fatalf("other port must not share the nonce, got %q", got)
	}
	ca.rememberNonce("https://api.example.com", "")
	if got := ca.nonceFor("https://api.example.com"); got != "n1" {
		t.Fatal("an empty nonce must not overwrite the stored one")
	}
	if originOf("http://[bad") != "http://[bad" {
		t.Fatal("unparseable URL is its own origin")
	}
}

func TestNonceChallengeDetection(t *testing.T) {
	h := http.Header{}
	if _, ok := nonceChallenge(401, h, nil); ok {
		t.Fatal("no DPoP-Nonce header: not a challenge")
	}
	h.Set(DpopNonceHeader, "n1")
	h.Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	if _, ok := nonceChallenge(401, h, nil); ok {
		t.Fatal("Bearer challenge is not a DPoP nonce challenge")
	}
	h.Add("WWW-Authenticate", `DPoP algs="ES256", error="use_dpop_nonce"`)
	if n, ok := nonceChallenge(401, h, nil); !ok || n != "n1" {
		t.Fatal("expected DPoP nonce challenge")
	}
	if _, ok := nonceChallenge(400, h, []byte(`{"error":"invalid_request"}`)); ok {
		t.Fatal("other 400 error is not a challenge")
	}
	if _, ok := nonceChallenge(500, h, nil); ok {
		t.Fatal("500 is not a challenge")
	}
}
