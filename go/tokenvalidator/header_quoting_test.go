package tokenvalidator

import (
	"strings"
	"testing"
	"time"
)

func TestChallengeStripsControlCharacters(t *testing.T) {
	pr := resourceFixture(t)
	got := pr.Challenge("invalid\r\n_token", "bad\r\nX-Injected: yes\x00\x1f\x7f \"q\" \\ end")
	for _, c := range got {
		if c < 0x20 || c == 0x7f {
			t.Fatalf("challenge contains control character %#x: %q", c, got)
		}
	}
	if !strings.Contains(got, `error="invalid_token"`) {
		t.Errorf("error param not sanitised: %q", got)
	}
	if !strings.Contains(got, `error_description="badX-Injected: yes \"q\" \\ end"`) {
		t.Errorf("error_description not quoted as expected: %q", got)
	}
}

func TestQuoteAuthParamEscapesAndStrips(t *testing.T) {
	cases := map[string]string{
		"plain":       "plain",
		`a"b`:         `a\"b`,
		`a\b`:         `a\\b`,
		"a\rb\nc\td":  "abcd",
		"x\x00y\x7fz": "xyz",
	}
	for in, want := range cases {
		if got := quoteAuthParam(in); got != want {
			t.Errorf("quoteAuthParam(%q) = %q, want %q", in, got, want)
		}
	}
}

// Unverified header data (alg, kid) must never reach error_description.
func TestFailureMessagesDoNotEchoTokenHeader(t *testing.T) {
	key, jwks := newTestKey(t, "evil\r\nkid\"")
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKS: jwks, AcceptedAlgorithms: []string{"RS256"}})
	if err != nil {
		t.Fatal(err)
	}
	token := signClaims(t, key, map[string]any{"exp": time.Now().Unix() + 300})
	r := val.Validate(token, nil)
	if r.Error != ErrUnsupportedAlgorithm || r.ErrorDescription != "algorithm not accepted" {
		t.Errorf("got error=%s desc=%q", r.Error, r.ErrorDescription)
	}
	if strings.Contains(r.ErrorDescription, "ES256") {
		t.Errorf("description echoes alg: %q", r.ErrorDescription)
	}

	_, otherJWKS := newTestKey(t, "other")
	val, err = New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKS: otherJWKS})
	if err != nil {
		t.Fatal(err)
	}
	r = val.Validate(token, nil)
	if r.Error != ErrKeyNotFound || strings.Contains(r.ErrorDescription, "evil") {
		t.Errorf("got error=%s desc=%q", r.Error, r.ErrorDescription)
	}
}

func TestFailureMessagesDoNotEchoClaims(t *testing.T) {
	key, jwks := newTestKey(t, "k1")
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKS: jwks})
	if err != nil {
		t.Fatal(err)
	}
	for _, claims := range []map[string]any{
		{"iss": "https://evil-issuer.example", "exp": time.Now().Unix() + 300},
		{"aud": "https://evil-audience.example", "exp": time.Now().Unix() + 300},
	} {
		r := val.Validate(signClaims(t, key, claims), nil)
		if r.Valid || strings.Contains(r.ErrorDescription, "evil") {
			t.Errorf("got valid=%v desc=%q", r.Valid, r.ErrorDescription)
		}
	}
}
