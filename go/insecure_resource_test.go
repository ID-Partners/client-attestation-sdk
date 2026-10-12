package clientattestation

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestRequestHeadersAndRoundTripperRefuseInsecureResource(t *testing.T) {
	attester, _ := fakeAttester(t)
	ca, err := NewClientAttestation(attester.URL, WithEvidence(StaticSvidSource{SVID: "fake-svid"}), WithEvidenceAudience(fakeAudience))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.RequestHeaders(context.Background(), "GET", "http://api.example.com/thing"); err == nil {
		t.Fatal("RequestHeaders accepted an http:// resource")
	}

	sent := false
	base := roundTripFunc(func(*http.Request) (*http.Response, error) { sent = true; return nil, nil })
	_, err = (&http.Client{Transport: ca.RoundTripperOver(base)}).Get("http://api.example.com/thing")
	if err == nil || !strings.Contains(err.Error(), "https is required") {
		t.Fatalf("RoundTripper error = %v, want the https rule", err)
	}
	if sent {
		t.Fatal("the request reached the base transport")
	}

	insecure, err := NewClientAttestation(attester.URL, WithEvidence(StaticSvidSource{SVID: "fake-svid"}), WithEvidenceAudience(fakeAudience), WithAllowInsecure())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := insecure.RequestHeaders(context.Background(), "GET", "http://api.example.com/thing"); err != nil {
		t.Fatalf("WithAllowInsecure() still refused: %v", err)
	}
}
