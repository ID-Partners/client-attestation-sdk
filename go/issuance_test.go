package clientattestation

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIssuedAttestationPopCarriesChallenge(t *testing.T) {
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	issued := &IssuedAttestation{Attestation: "h.p.s", InstanceKey: instance}

	pop, err := issued.Pop(testAudience, testClientID, "as-issued-challenge")
	if err != nil {
		t.Fatal(err)
	}
	hdr, claims := verify(t, pop, publicKey(t, instance))
	if hdr["typ"] != PopTyp {
		t.Fatalf("typ = %v, want %v", hdr["typ"], PopTyp)
	}
	if claims["aud"] != testAudience {
		t.Fatalf("aud = %v, want %v", claims["aud"], testAudience)
	}
	if claims["iss"] != testClientID {
		t.Fatalf("iss = %v, want %v", claims["iss"], testClientID)
	}
	if claims["challenge"] != "as-issued-challenge" {
		t.Fatalf("challenge = %v, want as-issued-challenge", claims["challenge"])
	}
}

func TestIssuedAttestationPopOmitsChallengeAndClientIDWhenBlank(t *testing.T) {
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	issued := &IssuedAttestation{Attestation: "h.p.s", InstanceKey: instance}

	pop, err := issued.Pop(testAudience, "", "")
	if err != nil {
		t.Fatal(err)
	}
	_, claims := verify(t, pop, publicKey(t, instance))
	if _, ok := claims["iss"]; ok {
		t.Error("iss must be omitted when clientID is blank")
	}
	if _, ok := claims["challenge"]; ok {
		t.Error("challenge must be omitted when blank")
	}
}

func TestIssuedAttestationPopRequiresAudience(t *testing.T) {
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	issued := &IssuedAttestation{Attestation: "h.p.s", InstanceKey: instance}
	if _, err := issued.Pop("", testClientID, ""); err == nil {
		t.Error("expected an error for a missing audience")
	}
}

func TestIssuedAttestationDpopCarriesNonceAndMethod(t *testing.T) {
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	issued := &IssuedAttestation{Attestation: "h.p.s", InstanceKey: instance}

	dpop, err := issued.Dpop("POST", tokenEndpoint, "as-issued-challenge")
	if err != nil {
		t.Fatal(err)
	}
	hdr, claims := verify(t, dpop, publicKey(t, instance))
	if hdr["typ"] != DpopTyp {
		t.Fatalf("typ = %v, want %v", hdr["typ"], DpopTyp)
	}
	if claims["htm"] != "POST" {
		t.Fatalf("htm = %v, want POST", claims["htm"])
	}
	if claims["htu"] != tokenEndpoint {
		t.Fatalf("htu = %v, want %v", claims["htu"], tokenEndpoint)
	}
	if claims["nonce"] != "as-issued-challenge" {
		t.Fatalf("nonce = %v, want as-issued-challenge", claims["nonce"])
	}
}

func TestIssuedAttestationDpopRequiresURI(t *testing.T) {
	instance, err := Generate("ES256")
	if err != nil {
		t.Fatal(err)
	}
	issued := &IssuedAttestation{Attestation: "h.p.s", InstanceKey: instance}
	if _, err := issued.Dpop("POST", "", ""); err == nil {
		t.Error("expected an error for a missing uri")
	}
}

// fakeIssuance serves the issuance endpoint, capturing the JSON body it was sent.
func fakeIssuance(t *testing.T, respond func(w http.ResponseWriter)) (*httptest.Server, *map[string]any) {
	t.Helper()
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("method=%s content-type=%q", r.Method, r.Header.Get("Content-Type"))
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("issuance body not JSON: %v", err)
		}
		respond(w)
	}))
	t.Cleanup(srv.Close)
	return srv, &body
}

func TestBootstrapSendsSvidProofAndDetails(t *testing.T) {
	srv, captured := fakeIssuance(t, func(w http.ResponseWriter) {
		writeJSON(w, 200, map[string]any{"attestation": "h.p.s", "expires_in": 600})
	})
	ic, err := NewAttestationIssuanceClient(srv.URL+"/", "demo-client", "https://attester", StaticSvidSource{SVID: "the-svid"})
	if err != nil {
		t.Fatal(err)
	}
	if ic.Endpoint != srv.URL {
		t.Fatalf("endpoint = %q, want trailing slash trimmed", ic.Endpoint)
	}
	details := []map[string]any{{"type": "payment_initiation"}}
	issued, err := ic.Bootstrap(details, "chal-1")
	if err != nil {
		t.Fatal(err)
	}
	if issued.Attestation != "h.p.s" || issued.ExpiresIn != 600 || issued.InstanceKey != ic.InstanceKey {
		t.Fatalf("issued = %#v", issued)
	}
	body := *captured
	if body["client_id"] != "demo-client" || body["svid"] != "the-svid" {
		t.Fatalf("body = %#v", body)
	}
	if jwkMap, ok := body["instance_key"].(map[string]any); !ok || jwkMap["d"] != nil || jwkMap["kty"] != "EC" {
		t.Fatalf("instance_key = %#v", body["instance_key"])
	}
	if ad, ok := body["authorization_details"].([]any); !ok || len(ad) != 1 {
		t.Fatalf("authorization_details = %#v", body["authorization_details"])
	}
	proof, _ := body["proof"].(string)
	hdr, claims := verify(t, proof, publicKey(t, ic.InstanceKey))
	if hdr["typ"] != InstanceProofTyp || claims["aud"] != "https://attester" || claims["challenge"] != "chal-1" || claims["jti"] == nil {
		t.Fatalf("proof hdr=%v claims=%v", hdr, claims)
	}
}

func TestBootstrapOmitsOptionalMembers(t *testing.T) {
	srv, captured := fakeIssuance(t, func(w http.ResponseWriter) {
		writeJSON(w, 200, map[string]any{"attestation": "h.p.s"})
	})
	ic, _ := NewAttestationIssuanceClient(srv.URL, "c", "aud", StaticSvidSource{SVID: "s"})
	if _, err := ic.Bootstrap(nil, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := (*captured)["authorization_details"]; ok {
		t.Error("authorization_details must be omitted when none are given")
	}
	proof, _ := (*captured)["proof"].(string)
	if _, ok := decodeJWTClaims(t, proof)["challenge"]; ok {
		t.Error("challenge must be omitted when blank")
	}
}

type failingSource struct{}

func (failingSource) Fetch(string) (string, error) { return "", errors.New("no svid today") }

func TestBootstrapFailures(t *testing.T) {
	t.Run("svid source fails", func(t *testing.T) {
		ic, _ := NewAttestationIssuanceClient("http://127.0.0.1:1", "c", "aud", failingSource{})
		if _, err := ic.Bootstrap(nil, ""); err == nil || !strings.Contains(err.Error(), "no svid today") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("endpoint unreachable", func(t *testing.T) {
		ic, _ := NewAttestationIssuanceClient(closedPortURL(t), "c", "aud", StaticSvidSource{SVID: "s"})
		if _, err := ic.Bootstrap(nil, ""); err == nil {
			t.Fatal("expected an error for a refused connection")
		}
	})
	t.Run("malformed 2xx body", func(t *testing.T) {
		srv, _ := fakeIssuance(t, func(w http.ResponseWriter) {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("not json"))
		})
		ic, _ := NewAttestationIssuanceClient(srv.URL, "c", "aud", StaticSvidSource{SVID: "s"})
		if _, err := ic.Bootstrap(nil, ""); err == nil {
			t.Fatal("expected an error for a malformed body")
		}
	})
	t.Run("unserialisable details", func(t *testing.T) {
		ic, _ := NewAttestationIssuanceClient("http://127.0.0.1:1", "c", "aud", StaticSvidSource{SVID: "s"})
		if _, err := ic.Bootstrap([]map[string]any{{"bad": make(chan int)}}, ""); err == nil {
			t.Fatal("expected a marshal error")
		}
	})
}

func TestIssuanceErrorMessage(t *testing.T) {
	err := &IssuanceError{Status: 403, Body: "denied"}
	if got := err.Error(); got != "attestation issuance failed: HTTP 403: denied" {
		t.Fatalf("Error() = %q", got)
	}
}
