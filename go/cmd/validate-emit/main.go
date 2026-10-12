// Command validate-emit validates the shared vectors (tokens.json, introspection.json, config.json) and writes this
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
		Name           string          `json:"name"`
		Token          string          `json:"token"`
		Config         *overrides      `json:"config"`
		Now            *int64          `json:"now"`
		JWKS           json.RawMessage `json:"jwks"`
		JWKSFetchError *string         `json:"jwks_fetch_error"`
	} `json:"cases"`
}

// jwksURI is what a case with a fetch error is given instead of a static key set.
const jwksURI = "https://keys.internal.example:8443/jwks"

type introspectionVectors struct {
	Guard struct {
		Resource  string   `json:"resource"`
		Audiences []string `json:"audiences"`
	} `json:"guard"`
	Cases []struct {
		Name           string         `json:"name"`
		Response       map[string]any `json:"response"`
		TransportError bool           `json:"transport_error"`
		NoEndpoint     bool           `json:"no_endpoint"`
	} `json:"cases"`
}

type configVectors struct {
	Cases []struct {
		Name   string `json:"name"`
		Config struct {
			JWKSURI               *string `json:"jwks_uri"`
			IntrospectionEndpoint *string `json:"introspection_endpoint"`
			AllowInsecure         bool    `json:"allow_insecure"`
			LeewaySeconds         *int    `json:"leeway_seconds"`
		} `json:"config"`
	} `json:"cases"`
}

type outcome struct {
	Name        string  `json:"name"`
	Valid       bool    `json:"valid"`
	Error       *string `json:"error"`
	Description *string `json:"description,omitempty"`
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
		code, description := r.Error, r.ErrorDescription
		o.Error, o.Description = &code, &description
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
		cfg := configFor(&v, c.Config)
		if c.JWKS != nil {
			cfg.JWKS = c.JWKS
		}
		if c.JWKSFetchError != nil {
			message := *c.JWKSFetchError
			cfg.JWKS, cfg.JWKSURI = nil, jwksURI
			opts = append(opts, tv.WithHTTPGet(func(string) ([]byte, error) { return nil, errors.New(message) }))
		}
		validator, err := tv.New(cfg, opts...)
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

	guard := make([]outcome, 0, len(iv.Cases))
	for _, c := range iv.Cases {
		cfg := configFor(&v, nil)
		cfg.Audiences = iv.Guard.Audiences
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
		resource, err := tv.NewProtectedResource(iv.Guard.Resource, []string{v.Issuer}, validator, nil)
		if err != nil {
			panic(err)
		}
		decision, err := resource.AuthenticateActive("Bearer opaque-token", nil)
		if err != nil {
			raises := "raises"
			guard = append(guard, outcome{Name: c.Name, Error: &raises})
			continue
		}
		guard = append(guard, row(c.Name, decision.Result))
	}

	var cv configVectors
	load(valDir, "config.json", &cv)
	configResults := make([]outcome, 0, len(cv.Cases))
	for _, c := range cv.Cases {
		cfg := configFor(&v, &overrides{LeewaySeconds: c.Config.LeewaySeconds})
		if c.Config.JWKSURI != nil {
			cfg.JWKS, cfg.JWKSURI = nil, *c.Config.JWKSURI
		}
		if c.Config.IntrospectionEndpoint != nil {
			cfg.Introspection = &tv.IntrospectionConfig{
				Endpoint: *c.Config.IntrospectionEndpoint, ClientID: "rs", ClientSecret: "secret",
			}
		}
		cfg.AllowInsecure = c.Config.AllowInsecure
		if _, err := tv.New(cfg); err != nil {
			refused := "refused"
			configResults = append(configResults, outcome{Name: c.Name, Error: &refused})
			continue
		}
		configResults = append(configResults, outcome{Name: c.Name, Valid: true})
	}

	outDir := filepath.Join(valDir, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(err)
	}
	data, err := json.MarshalIndent(map[string]any{
		"language": "go", "results": results, "introspection_results": introspection,
		"guard_results":  guard,
		"config_results": configResults,
	}, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "go.json"), data, 0o644); err != nil {
		panic(err)
	}
	fmt.Println("wrote validation/out/go.json")
}
