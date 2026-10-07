package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestEmitMatchesExpected runs the emitter as verify-validation.sh does and checks its output against the
// expected verdicts, so `go test` alone catches a Go verdict that would fail the cross-language gate.
func TestEmitMatchesExpected(t *testing.T) {
	main()
	dir, err := findValidationDir()
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Results       []outcome `json:"results"`
		Introspection []outcome `json:"introspection_results"`
	}
	raw, err := os.ReadFile(filepath.Join(dir, "out", "go.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	for file, rows := range map[string][]outcome{"tokens.json": out.Results, "introspection.json": out.Introspection} {
		var expected struct {
			Cases []struct {
				Name   string `json:"name"`
				Expect string `json:"expect"`
			} `json:"cases"`
		}
		load(dir, file, &expected)
		if len(rows) != len(expected.Cases) {
			t.Fatalf("%s: %d results for %d cases", file, len(rows), len(expected.Cases))
		}
		for i, c := range expected.Cases {
			got := "valid"
			if rows[i].Error != nil {
				got = *rows[i].Error
			}
			if rows[i].Name != c.Name || got != c.Expect {
				t.Errorf("%s %s: got %s (%s), want %s", file, c.Name, got, rows[i].Name, c.Expect)
			}
		}
	}
}
