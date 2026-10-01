// Command validate-emit validates the shared token vectors and writes this port's verdicts for the
// cross-language agreement check.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	tv "github.com/id-partners/client-attestation-sdk/go/tokenvalidator"
)

type vectors struct {
	Issuer             string          `json:"issuer"`
	Audience           string          `json:"audience"`
	RequiredScopes     []string        `json:"required_scopes"`
	AcceptedAlgorithms []string        `json:"accepted_algorithms"`
	JWKS               json.RawMessage `json:"jwks"`
	Cases              []struct {
		Name  string `json:"name"`
		Token string `json:"token"`
	} `json:"cases"`
}

type outcome struct {
	Name  string  `json:"name"`
	Valid bool    `json:"valid"`
	Error *string `json:"error"`
}

func findValidationDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "validation", "tokens.json")); err == nil {
			return filepath.Join(dir, "validation"), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("could not locate validation/tokens.json")
}

func main() {
	valDir, err := findValidationDir()
	if err != nil {
		panic(err)
	}
	raw, err := os.ReadFile(filepath.Join(valDir, "tokens.json"))
	if err != nil {
		panic(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		panic(err)
	}

	validator, err := tv.New(&tv.Config{
		Issuer:             v.Issuer,
		Audiences:          []string{v.Audience},
		JWKS:               v.JWKS,
		RequiredScopes:     v.RequiredScopes,
		AcceptedAlgorithms: v.AcceptedAlgorithms,
	})
	if err != nil {
		panic(err)
	}

	results := make([]outcome, 0, len(v.Cases))
	for _, c := range v.Cases {
		r := validator.Validate(c.Token, nil)
		o := outcome{Name: c.Name, Valid: r.Valid}
		if !r.Valid {
			code := r.Error
			o.Error = &code
		}
		results = append(results, o)
	}

	outDir := filepath.Join(valDir, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(err)
	}
	data, err := json.MarshalIndent(map[string]any{"language": "go", "results": results}, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "go.json"), data, 0o644); err != nil {
		panic(err)
	}
	fmt.Println("wrote validation/out/go.json")
}
