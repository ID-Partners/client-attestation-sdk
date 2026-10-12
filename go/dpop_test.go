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
	"os"
	"path/filepath"
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
			"evidence_audience":    fakeAudience,
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
	ca, err := NewClientAttestation(as.srv.URL, WithEvidenceAudience(fakeAudience),
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
	ca, err := NewClientAttestation(srv.URL, WithEvidenceAudience(fakeAudience), WithEvidence(StaticSvidSource{SVID: "fake-svid"}),
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
	ca, err := NewClientAttestation("http://127.0.0.1:1", WithEvidenceAudience(fakeAudience), WithEvidence(StaticSvidSource{SVID: "x"}))
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

// TestHTUVectors runs the shared htu vectors (vectors/htu.json) through the builder, normalizeHTU and the
// nonce key. Every port must agree.
func TestHTUVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "vectors", "htu.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []struct {
			Name   string `json:"name"`
			URL    string `json:"url"`
			HTU    string `json:"htu"`
			Origin string `json:"origin"`
			Error  string `json:"error"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	key, _ := Generate("ES256")
	for _, c := range file.Cases {
		t.Run(c.Name, func(t *testing.T) {
			proof, err := NewDpopProofBuilder(key).URI(c.URL).Build()
			if c.Error != "" {
				if err == nil || err.Error() != c.Error {
					t.Fatalf("Build(%q) error = %v, want %q", c.URL, err, c.Error)
				}
				if got := originOf(c.URL); got != c.URL {
					t.Fatalf("originOf(%q) = %q, want the URL itself", c.URL, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Build(%q): %v", c.URL, err)
			}
			if got := decodeJWTClaims(t, proof)["htu"]; got != c.HTU {
				t.Fatalf("htu(%q) = %v, want %q", c.URL, got, c.HTU)
			}
			if got := originOf(c.URL); got != c.Origin {
				t.Fatalf("originOf(%q) = %q, want %q", c.URL, got, c.Origin)
			}
		})
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

func TestRoundTripperRefusesToSendCredentialsOnRedirect(t *testing.T) {
	for _, tokenType := range []string{"Bearer", "DPoP"} {
		t.Run(tokenType, func(t *testing.T) {
			as := newDpopAS(t, tokenType)
			ca := newDpopClient(t, as)
			var leaked atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				leaked.Add(1)
			}))
			defer target.Close()
			var frontAuth atomic.Value
			front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				frontAuth.Store(r.Header.Get("Authorization"))
				http.Redirect(w, r, target.URL+"/steal", http.StatusFound)
			}))
			defer front.Close()

			client := &http.Client{Transport: ca.RoundTripper()}
			_, err := client.Get(front.URL + "/data")
			if err == nil || leaked.Load() != 0 {
				t.Fatalf("redirect followed with credentials: err=%v target hits=%d", err, leaked.Load())
			}
			if got := asSDKError(t, err); got.Status != http.StatusFound || !strings.Contains(got.Message, "redirect") {
				t.Fatalf("error = %+v", got)
			}
			if reason, status := transportReason(err); reason != "redirect" || status != http.StatusFound {
				t.Fatalf("transportReason = %s, %d", reason, status)
			}
			if auth, _ := frontAuth.Load().(string); auth == "" {
				t.Fatal("the first request carried no credentials")
			}

			// A client that stops at the 3xx gets it back, with nothing sent to the target.
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			resp, err := client.Get(front.URL + "/data")
			if err != nil {
				t.Fatal(err)
			}
			readAll(t, resp)
			if resp.StatusCode != http.StatusFound || leaked.Load() != 0 {
				t.Fatalf("status %d target hits %d", resp.StatusCode, leaked.Load())
			}
		})
	}
}

// A 400 + DPoP-Nonce whose body is longer than maxNonceChallengeBody is not a nonce challenge, even if it
// starts like one: the client reads no more than the cap, hands the response back and does not retry.
func TestDpopRoundTripperIgnoresOversize400Body(t *testing.T) {
	as := newDpopAS(t, "DPoP")
	var hits int32
	body := `{"error":"use_dpop_nonce"}` + strings.Repeat(" ", maxNonceChallengeBody)
	rs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set(DpopNonceHeader, "rs-nonce")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(rs.Close)
	ca := newDpopClient(t, as)
	client := &http.Client{Transport: ca.RoundTripper()}

	resp, err := client.Get(rs.URL + "/data")
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, resp); resp.StatusCode != 400 || got != body {
		t.Fatalf("status %d, body of %d bytes; want the whole 400 body handed back", resp.StatusCode, len(got))
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("resource hits = %d, want 1 (no retry)", n)
	}
}

// The nonce memory is bounded: a DPoP-Nonce over maxDpopNonceLength is ignored, and at most
// maxDpopNonceOrigins origins are kept, the one stored longest ago going first.
func TestDpopNonceMemoryIsBounded(t *testing.T) {
	ca := &ClientAttestation{}
	ca.rememberNonce("https://big.example/", strings.Repeat("n", maxDpopNonceLength+1))
	if got := ca.nonceFor("https://big.example/"); got != "" {
		t.Fatalf("over-long nonce remembered (%d bytes)", len(got))
	}
	ca.rememberNonce("https://big.example/", strings.Repeat("n", maxDpopNonceLength))
	if got := ca.nonceFor("https://big.example/"); len(got) != maxDpopNonceLength {
		t.Fatalf("nonce at the cap not remembered (%d bytes)", len(got))
	}

	ca = &ClientAttestation{}
	for i := 0; i < maxDpopNonceOrigins+44; i++ {
		ca.rememberNonce(fmt.Sprintf("https://h%d.example/p%d", i, i), fmt.Sprintf("n%d", i))
		if i == 0 {
			continue
		}
		// h1 keeps being refreshed, so it is never the oldest.
		ca.rememberNonce("https://h1.example/", "n1")
	}
	if n := len(ca.nonces); n != maxDpopNonceOrigins {
		t.Fatalf("%d origins remembered, want %d", n, maxDpopNonceOrigins)
	}
	if got := ca.nonceFor("https://h0.example/"); got != "" {
		t.Fatalf("oldest origin still remembered: %q", got)
	}
	if got := ca.nonceFor("https://h1.example/"); got != "n1" {
		t.Fatalf("refreshed origin forgotten: %q", got)
	}
	last := maxDpopNonceOrigins + 43
	if got := ca.nonceFor(fmt.Sprintf("https://h%d.example/", last)); got != fmt.Sprintf("n%d", last) {
		t.Fatalf("newest origin not remembered: %q", got)
	}

	h := http.Header{}
	h.Set(DpopNonceHeader, strings.Repeat("n", maxDpopNonceLength+1))
	h.Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
	if _, ok := nonceChallenge(401, h, nil); ok {
		t.Fatal("a challenge with an over-long nonce must not be answered")
	}
}

// A resource that challenges with an over-long nonce gets the challenge back, not a retry.
func TestDpopRoundTripperIgnoresOverlongNonce(t *testing.T) {
	as := newDpopAS(t, "DPoP")
	rs := newDpopResource(t, as)
	rs.nonce = strings.Repeat("n", maxDpopNonceLength+1)
	ca := newDpopClient(t, as)
	client := &http.Client{Transport: ca.RoundTripper()}

	resp, err := client.Get(rs.srv.URL + "/data")
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	if resp.StatusCode != 401 || atomic.LoadInt32(&rs.hits) != 1 {
		t.Fatalf("status %d hits %d, want the 401 challenge back after one hit", resp.StatusCode, atomic.LoadInt32(&rs.hits))
	}
	if got := ca.nonceFor(rs.srv.URL); got != "" {
		t.Fatalf("over-long nonce remembered (%d bytes)", len(got))
	}
}

// The retry answers the challenge it got, with that challenge's nonce, even when another response for the
// same origin stored a different nonce in between.
func TestDpopRoundTripperRetriesWithTheChallengesNonce(t *testing.T) {
	as := newDpopAS(t, "DPoP")
	ca := newDpopClient(t, as)
	const target = "https://rs.example/data"
	var proofNonces []any
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		proof, err := verifyDpopProof(r.Header.Get(DpopHeader))
		if err != nil {
			t.Fatal(err)
		}
		proofNonces = append(proofNonces, proof.claims["nonce"])
		if len(proofNonces) > 1 {
			ok := io.NopCloser(strings.NewReader("ok"))
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: ok, Request: r}, nil
		}
		header := http.Header{}
		header.Set(DpopNonceHeader, "challenge-nonce")
		// Reading the body stands in for a concurrent response to the same origin storing its own nonce.
		body := io.MultiReader(readFunc(func([]byte) (int, error) {
			ca.rememberNonce(target, "concurrent-nonce")
			return 0, io.EOF
		}), strings.NewReader(`{"error":"use_dpop_nonce"}`))
		return &http.Response{StatusCode: 400, Header: header, Body: io.NopCloser(body), Request: r}, nil
	})
	resp, err := (&http.Client{Transport: ca.RoundTripperOver(base)}).Get(target)
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	if resp.StatusCode != 200 || len(proofNonces) != 2 || proofNonces[1] != "challenge-nonce" {
		t.Fatalf("status %d, proof nonces %v; want the retry to carry challenge-nonce", resp.StatusCode, proofNonces)
	}
}

type readFunc func([]byte) (int, error)

func (f readFunc) Read(p []byte) (int, error) { return f(p) }

// RequestHeaders and DpopProofBuilder refuse a URL that parsers read differently before its query.
func TestAmbiguousURLsAreRefused(t *testing.T) {
	as := newDpopAS(t, "DPoP")
	ca := newDpopClient(t, as)
	key, _ := Generate("ES256")
	for _, bad := range []string{
		`https://evil.example\@as.example/t`,
		`https://as.example/a\b`,
		" https://as.example/t",
		"https://as.example/t ",
		"https://as.example\t/t",
		"https://as.example/t\n",
		"https://as.example/\x00t",
		"https://as.example/\x7ft",
	} {
		if _, err := ca.RequestHeaders(context.Background(), "GET", bad); err == nil {
			t.Errorf("RequestHeaders(%q) accepted", bad)
		} else {
			asSDKError(t, err)
		}
		if _, err := NewDpopProofBuilder(key).URI(bad).Build(); err == nil {
			t.Errorf("DpopProofBuilder.URI(%q) accepted", bad)
		}
	}
	// What follows the path never becomes htu, so it is left alone.
	for _, ok := range []string{`https://as.example/t?q=a\b c`, "https://as.example/t#a b"} {
		if _, err := NewDpopProofBuilder(key).URI(ok).Build(); err != nil {
			t.Errorf("DpopProofBuilder.URI(%q): %v", ok, err)
		}
	}
}

// A client configured for DPoP refuses a URL that has no htu with its own error type before it fetches
// the token: on a cold cache the AS is never called. A DPoP token the AS issues anyway is refused too.
func TestRequestHeadersRefusesAURLWithNoHTU(t *testing.T) {
	for _, tokenType := range []string{"DPoP", "Bearer"} {
		as := newDpopAS(t, tokenType)
		ca := newDpopClient(t, as)
		for _, bad := range []string{"https://bücher.example/t"} {
			_, err := ca.RequestHeaders(context.Background(), "GET", bad)
			if err == nil || !strings.HasPrefix(err.Error(), "uri (htu) ") {
				t.Errorf("%s: RequestHeaders(%q) error = %v, want an htu refusal", tokenType, bad, err)
				continue
			}
			asSDKError(t, err)
		}
		if calls, _ := as.calls(); calls != 0 {
			t.Errorf("%s: %d token requests for refused URLs, want 0", tokenType, calls)
		}
	}
}

// A client not configured for DPoP gets a Bearer header for any URL without a backslash, whitespace or
// control character: a Bearer token carries no htu.
func TestBearerClientRequestHeadersNeedNoHTU(t *testing.T) {
	srv, _ := fakeAttester(t)
	ca, err := NewClientAttestation(srv.URL, WithEvidenceAudience(fakeAudience), WithEvidence(StaticSvidSource{SVID: "fake-svid"}))
	if err != nil {
		t.Fatal(err)
	}
	for _, url := range []string{"https://bücher.example/t"} {
		h, err := ca.RequestHeaders(context.Background(), "GET", url)
		if err != nil || h["Authorization"] != "Bearer AT-xyz" {
			t.Errorf("RequestHeaders(%q) = %v, %v; want the Bearer header", url, h, err)
		}
	}
}

// The RoundTripper signs the request target it actually sends: Go sends "[" and "]" as written and
// escapes "|", and the proof's htu must equal what the resource received, or a conforming RS (RFC 9449
// section 4.3) refuses it. (net/url refuses a lone "%", so the RoundTripper never sends one.)
func TestRoundTripperHTUIsTheTargetSent(t *testing.T) {
	as := newDpopAS(t, "DPoP")
	ca := newDpopClient(t, as)
	var mu sync.Mutex
	var target, htu string
	rs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proof, err := verifyDpopProof(r.Header.Get(DpopHeader))
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			t.Errorf("proof: %v", err)
		} else {
			htu, _ = proof.claims["htu"].(string)
		}
		target = "http://" + r.Host + strings.SplitN(r.RequestURI, "?", 2)[0]
	}))
	defer rs.Close()
	for _, path := range []string{"/items[0]", "/a[b]/c|d", "/caf\u00e9[x]"} {
		resp, err := (&http.Client{Transport: ca.RoundTripper()}).Get(rs.URL + path + "?q=1")
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		readAll(t, resp)
		mu.Lock()
		if htu != target {
			t.Errorf("%s: htu %q, request target %q", path, htu, target)
		}
		mu.Unlock()
	}
}

// Not in htu.json (JSON can't carry it): a path that is not valid UTF-8 is refused, as the other ports
// refuse a lone surrogate.
func TestHTUInvalidUTF8PathIsRefused(t *testing.T) {
	if _, err := normalizeHTU("https://as.example.com/a\xff"); err == nil || err.Error() != errHTUPath {
		t.Fatalf("err = %v, want %q", err, errHTUPath)
	}
}
