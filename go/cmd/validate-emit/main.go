// Command validate-emit validates the shared vectors (tokens.json, introspection.json) and writes this
// port's verdicts for the cross-language agreement check.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	tv "github.com/id-partners/client-attestation-sdk/go/tokenvalidator"
)

// overrides are a case's changes to the shared config. A field is a RawMessage so "absent", null and an
// empty list stay distinct.
type overrides struct {
	AcceptedAlgorithms json.RawMessage `json:"accepted_algorithms"`
	AcceptedTokenTypes json.RawMessage `json:"accepted_token_types"`
	LeewaySeconds      *int            `json:"leeway_seconds"`
}

type vectors struct {
	Issuer             string          `json:"issuer"`
	Audience           string          `json:"audience"`
	RequiredScopes     []string        `json:"required_scopes"`
	AcceptedAlgorithms []string        `json:"accepted_algorithms"`
	JWKS               json.RawMessage `json:"jwks"`
	Cases              []struct {
		Name   string     `json:"name"`
		Token  string     `json:"token"`
		Config *overrides `json:"config"`
		Now    *int64     `json:"now"`
	} `json:"cases"`
}

type introspectionVectors struct {
	Cases []struct {
		Name           string         `json:"name"`
		Response       map[string]any `json:"response"`
		TransportError bool           `json:"transport_error"`
		NoEndpoint     bool           `json:"no_endpoint"`
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

func load(dir, name string, into any) {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		panic(err)
	}
}

// configFor is the shared config with a case's overrides; an override that is present wins even when empty.
func configFor(v *vectors, o *overrides) *tv.Config {
	c := &tv.Config{
		Issuer:             v.Issuer,
		Audiences:          []string{v.Audience},
		JWKS:               v.JWKS,
		RequiredScopes:     v.RequiredScopes,
		AcceptedAlgorithms: v.AcceptedAlgorithms,
	}
	if o == nil {
		return c
	}
	if o.AcceptedAlgorithms != nil {
		c.AcceptedAlgorithms = []string{} // non-nil: an empty list accepts nothing
		if err := json.Unmarshal(o.AcceptedAlgorithms, &c.AcceptedAlgorithms); err != nil {
			panic(err)
		}
	}
	if o.AcceptedTokenTypes != nil {
		if string(o.AcceptedTokenTypes) == "null" {
			c.DisableTokenTypeCheck = true
		} else {
			c.AcceptedTokenTypes = []string{}
			if err := json.Unmarshal(o.AcceptedTokenTypes, &c.AcceptedTokenTypes); err != nil {
				panic(err)
			}
		}
	}
	if o.LeewaySeconds != nil {
		c.LeewaySeconds = *o.LeewaySeconds
		c.ZeroLeeway = *o.LeewaySeconds == 0
	}
	return c
}

func row(name string, r tv.Result) outcome {
	o := outcome{Name: name, Valid: r.Valid}
	if !r.Valid {
		code := r.Error
		o.Error = &code
	}
	return o
}

func main() {
	valDir, err := findValidationDir()
	if err != nil {
		panic(err)
	}
	var v vectors
	load(valDir, "tokens.json", &v)

	results := make([]outcome, 0, len(v.Cases))
	for _, c := range v.Cases {
		var opts []tv.Option
		if c.Now != nil {
			at := time.Unix(*c.Now, 0)
			opts = append(opts, tv.WithClock(func() time.Time { return at }))
		}
		validator, err := tv.New(configFor(&v, c.Config), opts...)
		if err != nil {
			panic(err)
		}
		results = append(results, row(c.Name, validator.Validate(c.Token, nil)))
	}

	var iv introspectionVectors
	load(valDir, "introspection.json", &iv)
	introspection := make([]outcome, 0, len(iv.Cases))
	for _, c := range iv.Cases {
		cfg := configFor(&v, nil)
		if !c.NoEndpoint {
			cfg.Introspection = &tv.IntrospectionConfig{
				Endpoint: "https://issuer.example.com/introspect", ClientID: "rs", ClientSecret: "secret",
			}
		}
		post := func(string, string, map[string]string) (map[string]any, error) {
			if c.TransportError {
				return nil, errors.New("introspection: HTTP 503")
			}
			return c.Response, nil
		}
		validator, err := tv.New(cfg, tv.WithHTTPPost(post))
		if err != nil {
			panic(err)
		}
		r, err := validator.ValidateActive("opaque-token", nil)
		if err != nil {
			raises := "raises"
			introspection = append(introspection, outcome{Name: c.Name, Error: &raises})
			continue
		}
		introspection = append(introspection, row(c.Name, r))
	}

	outDir := filepath.Join(valDir, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(err)
	}
	data, err := json.MarshalIndent(map[string]any{
		"language": "go", "results": results, "introspection_results": introspection,
	}, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "go.json"), data, 0o644); err != nil {
		panic(err)
	}
	fmt.Println("wrote validation/out/go.json")
}
