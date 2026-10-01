package clientattestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

func TestDraftRevision(t *testing.T) {
	if DraftRevision != "10" {
		t.Fatalf("DraftRevision = %q, want 10", DraftRevision)
	}
}

// wireCapture records what the client put on the wire at the mint and token endpoints.
type wireCapture struct {
	mu        sync.Mutex
	mintBody  map[string]any
	tokenForm url.Values
	pop       string
	dpop      string
}

// wireAttester is a fake attester (challenge fixed at "chal-wire") that captures the mint JSON body and
// the token-endpoint form and proof headers.
func wireAttester(t *testing.T) (*httptest.Server, *wireCapture) {
	t.Helper()
	captured := &wireCapture{}
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/client-attester", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, standardDoc(srv.URL))
	})
	mux.HandleFunc("/challenge", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"attestation_challenge": "chal-wire"})
	})
	mux.HandleFunc("/mint", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("mint body not JSON: %v", err)
		}
		captured.mu.Lock()
		captured.mintBody = body
		captured.mu.Unlock()
		sub := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"demo-client"}`))
		writeJSON(w, 200, map[string]any{"attestation": "h." + sub + ".sig"})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, err := url.ParseQuery(string(raw))
		if err != nil {
			t.Errorf("token body not a form: %v", err)
		}
		captured.mu.Lock()
		captured.tokenForm = form
		captured.pop = r.Header.Get(PopHeader)
		captured.dpop = r.Header.Get(DpopHeader)
		captured.mu.Unlock()
		writeJSON(w, 200, map[string]any{"access_token": "AT", "expires_in": 60})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, captured
}

// mintProofChallenge returns the challenge claim of the instance proof sent at mint.
func (c *wireCapture) mintProofChallenge(t *testing.T) any {
	t.Helper()
	proof, _ := c.mintBody["proof"].(string)
	return decodeJWTClaims(t, proof)["challenge"]
}

func TestOperatorSentAtMintAndTokenEndpoint(t *testing.T) {
	srv, captured := wireAttester(t)
	operator := map[string]any{
		"sub":  "ops@example.com",
		"name": "Ops <team> & co",
		"org":  map[string]any{"z": 1, "a": "b"},
	}
	if err := tokenFrom(t, srv, WithOperator(operator)); err != nil {
		t.Fatal(err)
	}

	got, ok := captured.mintBody["operator"].(map[string]any)
	if !ok || got["sub"] != "ops@example.com" || got["name"] != "Ops <team> & co" {
		t.Fatalf("mint operator = %#v", captured.mintBody["operator"])
	}
	// Compact JSON, keys sorted at every level, no HTML escaping — json.dumps(..., separators=(",", ":"),
	// sort_keys=True) in the Python reference.
	want := `{"name":"Ops <team> & co","org":{"a":"b","z":1},"sub":"ops@example.com"}`
	if form := captured.tokenForm.Get("operator"); form != want {
		t.Fatalf("token form operator = %q, want %q", form, want)
	}
	if captured.tokenForm.Get("grant_type") != "client_credentials" {
		t.Fatalf("grant_type = %q", captured.tokenForm.Get("grant_type"))
	}
}

func TestOperatorAbsentSendsNothing(t *testing.T) {
	for name, opts := range map[string][]Option{
		"unset": nil,
		"empty": {WithOperator(map[string]any{})},
	} {
		t.Run(name, func(t *testing.T) {
			srv, captured := wireAttester(t)
			if err := tokenFrom(t, srv, opts...); err != nil {
				t.Fatal(err)
			}
			if _, ok := captured.mintBody["operator"]; ok {
				t.Error("mint body must not carry operator when none is configured")
			}
			if _, ok := captured.tokenForm["operator"]; ok {
				t.Error("token form must not carry operator when none is configured")
			}
		})
	}
}

func TestOperatorNotSerialisableFails(t *testing.T) {
	if _, err := compactSortedJSON(map[string]any{"bad": make(chan int)}); err == nil {
		t.Fatal("expected an error for a non-JSON operator")
	}
}

func TestChallengeAtTokenDefaultCarriesChallengeEverywhere(t *testing.T) {
	srv, captured := wireAttester(t)
	if err := tokenFrom(t, srv); err != nil {
		t.Fatal(err)
	}
	if got := captured.mintProofChallenge(t); got != "chal-wire" {
		t.Fatalf("mint proof challenge = %v", got)
	}
	if got := decodeJWTClaims(t, captured.pop)["challenge"]; got != "chal-wire" {
		t.Fatalf("PoP challenge = %v", got)
	}
}

func TestChallengeAtTokenFalseDropsTokenEndpointCopy(t *testing.T) {
	t.Run("attestation_pop_jwt", func(t *testing.T) {
		srv, captured := wireAttester(t)
		if err := tokenFrom(t, srv, WithChallengeAtToken(false)); err != nil {
			t.Fatal(err)
		}
		if got := captured.mintProofChallenge(t); got != "chal-wire" {
			t.Fatalf("mint proof challenge = %v; the challenge must still protect the mint", got)
		}
		if captured.pop == "" {
			t.Fatal("expected a PoP header")
		}
		if _, ok := decodeJWTClaims(t, captured.pop)["challenge"]; ok {
			t.Fatal("PoP must not carry the challenge with WithChallengeAtToken(false)")
		}
	})
	t.Run("dpop_combined", func(t *testing.T) {
		srv, captured := wireAttester(t)
		if err := tokenFrom(t, srv, WithChallengeAtToken(false), WithPopMethod(PopMethodDpopCombined)); err != nil {
			t.Fatal(err)
		}
		if got := captured.mintProofChallenge(t); got != "chal-wire" {
			t.Fatalf("mint proof challenge = %v", got)
		}
		if captured.dpop == "" || captured.pop != "" {
			t.Fatalf("expected only a DPoP header (pop=%q dpop=%q)", captured.pop, captured.dpop)
		}
		if _, ok := decodeJWTClaims(t, captured.dpop)["nonce"]; ok {
			t.Fatal("DPoP proof must not carry the challenge as nonce with WithChallengeAtToken(false)")
		}
	})
	t.Run("dpop_combined default keeps nonce", func(t *testing.T) {
		srv, captured := wireAttester(t)
		if err := tokenFrom(t, srv, WithPopMethod(PopMethodDpopCombined)); err != nil {
			t.Fatal(err)
		}
		if got := decodeJWTClaims(t, captured.dpop)["nonce"]; got != "chal-wire" {
			t.Fatalf("DPoP nonce = %v, want chal-wire", got)
		}
	})
}

func TestChallengeAtTokenFalseUsesRememberedDpopNonce(t *testing.T) {
	srv, captured := wireAttester(t)
	ca, err := NewClientAttestation(srv.URL,
		WithEvidence(StaticSvidSource{SVID: "s"}),
		WithChallengeAtToken(false),
		WithPopMethod(PopMethodDpopCombined))
	if err != nil {
		t.Fatal(err)
	}
	ca.rememberNonce(srv.URL+"/token", "server-nonce")
	if _, err := ca.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := decodeJWTClaims(t, captured.dpop)["nonce"]; got != "server-nonce" {
		t.Fatalf("DPoP nonce = %v, want the AS's remembered server-nonce", got)
	}
}

func TestOperatorJSONEscapesNonASCIILikePython(t *testing.T) {
	// input: e-acute and U+1F600, written as Go escapes so the source stays ASCII
	got, err := compactSortedJSON(map[string]any{"name": "\u00e9 \U0001F600", "a": 1})
	if err != nil {
		t.Fatal(err)
	}
	// what Python json.dumps(..., separators=(",", ":"), sort_keys=True) produces for the same value
	if want := `{"a":1,"name":"\u00e9 \ud83d\ude00"}`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
