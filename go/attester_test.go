package clientattestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

// profileAttester is a loopback attester + token endpoint that answers both the PingFederate protocol and
// a made-up one ("acme"), and records every request.
type profileAttester struct {
	srv    *httptest.Server
	mu     sync.Mutex
	paths  []string
	bodies map[string]map[string]any
}

var profileAttestation = "e30." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"client-1"}`)) + ".sig"

func newProfileAttester(t *testing.T) *profileAttester {
	t.Helper()
	a := &profileAttester{bodies: map[string]map[string]any{}}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		a.mu.Lock()
		a.paths = append(a.paths, r.URL.Path)
		a.bodies[r.URL.Path] = body
		a.mu.Unlock()
		base := a.srv.URL
		switch r.URL.Path {
		case "/.well-known/client-attester":
			writeJSON(w, 200, map[string]any{"evidence_audience": base, "attestation_endpoint": base + "/pf/mint",
				"token_endpoint": base + "/token"})
		case "/acme/config":
			writeJSON(w, 200, map[string]any{"audience": "acme-aud", "mint_url": base + "/acme/mint", "token_url": base + "/token"})
		case "/pf/mint":
			writeJSON(w, 200, map[string]any{"attestation": profileAttestation, "expires_in": 600})
		case "/acme/mint":
			writeJSON(w, 200, map[string]any{"client_attestation": profileAttestation, "ttl": 300})
		case "/token":
			if r.Header.Get(AttestationHeader) != profileAttestation || r.Header.Get(PopHeader) == "" {
				writeJSON(w, 401, map[string]any{"error": "invalid_client"})
				return
			}
			writeJSON(w, 200, map[string]any{"access_token": "at-1", "expires_in": 60})
		default:
			writeJSON(w, 404, map[string]any{"error": "not_found"})
		}
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *profileAttester) seen() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.paths...)
}

func (a *profileAttester) body(path string) map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.bodies[path]
}

func decodeSegments(t *testing.T, jwt string) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	var out [2]map[string]any
	for i := range out {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &out[i]); err != nil {
			t.Fatal(err)
		}
	}
	return out[0], out[1]
}

// acmeProfile is a non-PingFederate attester: its own discovery path and fields, proof typ, and mint
// request and response shapes.
type acmeProfile struct{}

func (acmeProfile) Discover(ctx context.Context, t AttesterTransport, attesterURL string) (*AttesterMetadata, error) {
	var doc struct {
		Audience string `json:"audience"`
		MintURL  string `json:"mint_url"`
		TokenURL string `json:"token_url"`
	}
	if err := t.RequestJSON(ctx, "discover", http.MethodGet, attesterURL+"/acme/config", nil, &doc); err != nil {
		return nil, err
	}
	return &AttesterMetadata{EvidenceAudience: doc.Audience, AttestationEndpoint: doc.MintURL, TokenEndpoint: doc.TokenURL}, nil
}

func (acmeProfile) Mint(ctx context.Context, t AttesterTransport, md *AttesterMetadata, req *MintRequest) (*MintResult, error) {
	pop, err := req.InstanceProof("acme-key-proof+jwt", "acme")
	if err != nil {
		return nil, err
	}
	var res struct {
		ClientAttestation string `json:"client_attestation"`
		TTL               int64  `json:"ttl"`
	}
	body := map[string]any{"evidence": req.Evidence, "key": req.InstanceKey.PublicJWK(), "pop": pop}
	if err := t.RequestJSON(ctx, "mint", http.MethodPost, md.AttestationEndpoint, body, &res); err != nil {
		return nil, err
	}
	return &MintResult{Attestation: res.ClientAttestation, ExpiresIn: res.TTL}, nil
}

func keysOf(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestDefaultProfileIsPingFederate(t *testing.T) {
	a := newProfileAttester(t)
	ca, err := NewClientAttestation(a.srv.URL, WithEvidence(StaticSvidSource{SVID: "svid"}))
	if err != nil {
		t.Fatal(err)
	}
	if tok, err := ca.Token(context.Background()); err != nil || tok != "at-1" {
		t.Fatalf("token = %q, %v", tok, err)
	}
	if got := a.seen(); !reflect.DeepEqual(got, []string{"/.well-known/client-attester", "/pf/mint", "/token"}) {
		t.Fatalf("paths = %v", got)
	}
	body := a.body("/pf/mint")
	if got := keysOf(body); !reflect.DeepEqual(got, []string{"instance_key", "proof", "svid"}) {
		t.Fatalf("mint body keys = %v", got)
	}
	header, claims := decodeSegments(t, body["proof"].(string))
	if header["typ"] != InstanceProofTyp || claims["aud"] != a.srv.URL {
		t.Fatalf("proof header %v claims %v", header, claims)
	}
}

func TestCustomProfileGetsATokenEndToEnd(t *testing.T) {
	a := newProfileAttester(t)
	ca, err := NewClientAttestation(a.srv.URL, WithEvidence(StaticSvidSource{SVID: "svid"}), WithAttesterProfile(acmeProfile{}))
	if err != nil {
		t.Fatal(err)
	}
	if tok, err := ca.Token(context.Background()); err != nil || tok != "at-1" {
		t.Fatalf("token = %q, %v", tok, err)
	}
	if got := a.seen(); !reflect.DeepEqual(got, []string{"/acme/config", "/acme/mint", "/token"}) {
		t.Fatalf("paths = %v", got)
	}
	body := a.body("/acme/mint")
	header, claims := decodeSegments(t, body["pop"].(string))
	if body["evidence"] != "svid" || header["typ"] != "acme-key-proof+jwt" || claims["aud"] != "acme" {
		t.Fatalf("body %v header %v claims %v", body, header, claims)
	}
	md, err := ca.AttesterMetadata(context.Background())
	if err != nil || md.EvidenceAudience != "acme-aud" {
		t.Fatalf("discovery = %+v, %v", md, err)
	}
}

func TestStaticMetadataSkipsDiscoveryAndMintsWithTheDefaultProtocol(t *testing.T) {
	a := newProfileAttester(t)
	ca, err := NewClientAttestation("", WithEvidence(StaticSvidSource{SVID: "svid"}), WithAttesterMetadata(AttesterMetadata{
		EvidenceAudience: "aud-1", AttestationEndpoint: a.srv.URL + "/pf/mint", TokenEndpoint: a.srv.URL + "/token",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if tok, err := ca.Token(context.Background()); err != nil || tok != "at-1" {
		t.Fatalf("token = %q, %v", tok, err)
	}
	if got := a.seen(); !reflect.DeepEqual(got, []string{"/pf/mint", "/token"}) {
		t.Fatalf("paths = %v", got)
	}
	header, claims := decodeSegments(t, a.body("/pf/mint")["proof"].(string))
	if header["typ"] != "oauth-attestation-instance-proof+jwt" || claims["aud"] != "aud-1" {
		t.Fatalf("proof header %v claims %v", header, claims)
	}
}

func TestStaticMetadataWithACustomProfileNeverDiscovers(t *testing.T) {
	a := newProfileAttester(t)
	ca, err := NewClientAttestation(a.srv.URL, WithEvidence(StaticSvidSource{SVID: "svid"}), WithAttesterProfile(acmeProfile{}),
		WithAttesterMetadata(AttesterMetadata{EvidenceAudience: "aud-1", AttestationEndpoint: a.srv.URL + "/acme/mint",
			TokenEndpoint: a.srv.URL + "/token"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := a.seen(); !reflect.DeepEqual(got, []string{"/acme/mint", "/token"}) {
		t.Fatalf("paths = %v", got)
	}
}

func TestStaticMetadataNeedsATokenEndpointAndHTTPS(t *testing.T) {
	a := newProfileAttester(t)
	ca, _ := NewClientAttestation("", WithEvidence(StaticSvidSource{SVID: "svid"}),
		WithAttesterMetadata(AttesterMetadata{EvidenceAudience: "a", AttestationEndpoint: a.srv.URL + "/pf/mint"}))
	if _, err := ca.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "no token_endpoint") {
		t.Fatalf("err = %v", err)
	}
	ca, _ = NewClientAttestation("", WithEvidence(StaticSvidSource{SVID: "svid"}),
		WithAttesterMetadata(AttesterMetadata{EvidenceAudience: "a", AttestationEndpoint: "http://attester.example/mint",
			TokenEndpoint: "https://as.example/token"}))
	if _, err := ca.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "refusing insecure URL") {
		t.Fatalf("err = %v", err)
	}
}

func TestAttesterURLIsRequiredWithoutMetadataOrProfile(t *testing.T) {
	if _, err := NewClientAttestation(""); err == nil || !strings.Contains(err.Error(), "attesterURL is required") {
		t.Fatalf("err = %v", err)
	}
	ca, err := NewClientAttestation("", WithAttesterProfile(PingFederateProfile{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.AttesterMetadata(context.Background()); err == nil || !strings.Contains(err.Error(), "attesterURL is required") {
		t.Fatalf("err = %v", err)
	}
}

type nilProfile struct{ acmeProfile }

func (nilProfile) Discover(context.Context, AttesterTransport, string) (*AttesterMetadata, error) {
	return nil, nil
}

func (nilProfile) Mint(context.Context, AttesterTransport, *AttesterMetadata, *MintRequest) (*MintResult, error) {
	return nil, nil
}

func TestProfileReturningNothingIsAnError(t *testing.T) {
	ca, _ := NewClientAttestation("https://attester.example", WithAttesterProfile(nilProfile{}))
	if _, err := ca.AttesterMetadata(context.Background()); err == nil {
		t.Fatal("want an error for nil metadata")
	}
	ca, _ = NewClientAttestation("", WithEvidence(StaticSvidSource{SVID: "svid"}), WithAttesterProfile(nilProfile{}),
		WithAttesterMetadata(AttesterMetadata{EvidenceAudience: "a", TokenEndpoint: "https://as.example/t"}))
	if _, err := ca.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "no attestation") {
		t.Fatalf("err = %v", err)
	}
}

type fixedTransport struct {
	doc map[string]any
	err error
}

func (f fixedTransport) RequestJSON(_ context.Context, _, _, _ string, _ any, out any) error {
	if f.err != nil {
		return f.err
	}
	raw, _ := json.Marshal(f.doc)
	return json.Unmarshal(raw, out)
}

func TestPingFederateProfileEdges(t *testing.T) {
	ctx := context.Background()
	doc := map[string]any{"evidence_audience": "aud", "attestation_endpoint": "https://pf.example/mint"}
	md, err := PingFederateProfile{}.Discover(ctx, fixedTransport{doc: doc}, "https://pf.example")
	if err != nil || md.TokenEndpoint != "https://pf.example/as/token.oauth2" || md.Document["evidence_audience"] != "aud" {
		t.Fatalf("md = %+v, %v", md, err)
	}
	if _, err := (PingFederateProfile{}).Discover(ctx, fixedTransport{doc: map[string]any{"evidence_audience": "aud"}},
		"https://pf.example"); err == nil || !strings.Contains(err.Error(), "attestation_endpoint") {
		t.Fatalf("discovery without attestation_endpoint: err = %v", err)
	}
	boom := errors.New("boom")
	if _, err := (PingFederateProfile{}).Discover(ctx, fixedTransport{err: boom}, "https://pf.example"); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	key, _ := Generate("ES256")
	req := &MintRequest{InstanceKey: key, Evidence: "svid", ClientID: "c", Operator: map[string]any{"sub": "op"}}
	if _, err := (PingFederateProfile{}).Mint(ctx, fixedTransport{doc: map[string]any{}}, &AttesterMetadata{}, req); err == nil {
		t.Fatal("want an error without attestation_endpoint")
	}
	md = &AttesterMetadata{AttestationEndpoint: "https://x"}
	if _, err := (PingFederateProfile{}).Mint(ctx, fixedTransport{doc: map[string]any{}}, md, req); err == nil ||
		!strings.Contains(err.Error(), "no attestation") {
		t.Fatalf("err = %v", err)
	}
	if _, err := (PingFederateProfile{}).Mint(ctx, fixedTransport{err: boom}, md, req); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if _, err := (PingFederateProfile{}).Mint(ctx, fixedTransport{}, md, &MintRequest{InstanceKey: &SigningKeyPair{}}); err == nil {
		t.Fatal("want a signing error for an empty key")
	}
}

func TestIssuanceClientTakesACustomProfile(t *testing.T) {
	a := newProfileAttester(t)
	client, err := NewAttestationIssuanceClient(a.srv.URL+"/acme/mint", "client-1", "https://attester.example", StaticSvidSource{SVID: "svid"})
	if err != nil {
		t.Fatal(err)
	}
	client.Profile = acmeProfile{}
	issued, err := client.Bootstrap(nil, "")
	if err != nil || issued.Attestation != profileAttestation || issued.ExpiresIn != 300 {
		t.Fatalf("issued = %+v, %v", issued, err)
	}
	if header, _ := decodeSegments(t, a.body("/acme/mint")["pop"].(string)); header["typ"] != "acme-key-proof+jwt" {
		t.Fatalf("header = %v", header)
	}
	// A GET with no body through the issuance transport sends no payload.
	var out map[string]any
	if err := (issuanceTransport{client: http.DefaultClient}).RequestJSON(context.Background(), "x", http.MethodGet,
		a.srv.URL+"/acme/config", nil, &out); err != nil || out["audience"] != "acme-aud" {
		t.Fatalf("out = %v, %v", out, err)
	}
	if err := (issuanceTransport{client: http.DefaultClient}).RequestJSON(context.Background(), "x", http.MethodPost,
		a.srv.URL+"/x", map[string]any{"bad": func() {}}, &out); err == nil {
		t.Fatal("want a marshal error")
	}
}

func TestIssuanceClientDefaultProfileSendsClientID(t *testing.T) {
	a := newProfileAttester(t)
	client, _ := NewAttestationIssuanceClient(a.srv.URL+"/pf/mint", "client-1", "https://attester.example", StaticSvidSource{SVID: "svid"})
	issued, err := client.Bootstrap([]map[string]any{{"type": "x"}}, "chal")
	if err != nil || issued.ExpiresIn != 600 {
		t.Fatalf("issued = %+v, %v", issued, err)
	}
	body := a.body("/pf/mint")
	if got := keysOf(body); !reflect.DeepEqual(got, []string{"authorization_details", "client_id", "instance_key", "proof", "svid"}) {
		t.Fatalf("keys = %v", got)
	}
	if _, claims := decodeSegments(t, body["proof"].(string)); claims["challenge"] != "chal" || claims["aud"] != "https://attester.example" {
		t.Fatalf("claims = %v", claims)
	}
}
