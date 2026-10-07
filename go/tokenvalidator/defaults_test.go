package tokenvalidator

import "testing"

// The exported defaults are copies: changing them must not widen what a validator accepts.
func TestDefaultsAreCopies(t *testing.T) {
	algs, types := DefaultAlgorithms(), DefaultTokenTypes()
	if algs[0] != "ES256" || len(algs) != 9 || len(types) != 1 || types[0] != "at+jwt" {
		t.Fatalf("defaults changed: %v %v", algs, types)
	}
	algs[0], types[0] = "HS256", "JWT"
	c := &Config{}
	if got := c.acceptedAlgorithms()[0]; got != "ES256" || DefaultAlgorithms()[0] != "ES256" {
		t.Fatalf("validator default algorithms changed through a returned slice: %q", got)
	}
	if c.acceptsTokenType("JWT") || !c.acceptsTokenType("at+jwt") || DefaultTokenTypes()[0] != "at+jwt" {
		t.Fatal("validator default token types changed through a returned slice")
	}
}
