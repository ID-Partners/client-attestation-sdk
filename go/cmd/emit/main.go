// Command emit produces attestation artifacts from the shared vectors, for the
// cross-language interop check. Run it from the go/ directory: `go run ./cmd/emit`.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	clientattestation "github.com/id-partners/client-attestation-sdk/go"
)

type attesterInput struct {
	Iss string         `json:"iss"`
	Alg string         `json:"alg"`
	JWK map[string]any `json:"jwk"`
}

type instanceInput struct {
	Alg string         `json:"alg"`
	JWK map[string]any `json:"jwk"`
}

type inputs struct {
	Attester              attesterInput `json:"attester"`
	Instance              instanceInput `json:"instance"`
	ClientID              string        `json:"client_id"`
	Audience              string        `json:"audience"`
	TokenEndpoint         string        `json:"token_endpoint"`
	AttestationTTLSeconds int64         `json:"attestation_ttl_seconds"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "emit:", err)
		os.Exit(1)
	}
}

func run() error {
	vectorsDir, err := findVectorsDir()
	if err != nil {
		return err
	}

	raw, err := os.ReadFile(filepath.Join(vectorsDir, "inputs.json"))
	if err != nil {
		return fmt.Errorf("read inputs.json: %w", err)
	}
	var in inputs
	if err := json.Unmarshal(raw, &in); err != nil {
		return fmt.Errorf("parse inputs.json: %w", err)
	}

	attester, err := clientattestation.FromJWK(in.Attester.JWK, in.Attester.Alg)
	if err != nil {
		return fmt.Errorf("attester key: %w", err)
	}
	instance, err := clientattestation.FromJWK(in.Instance.JWK, in.Instance.Alg)
	if err != nil {
		return fmt.Errorf("instance key: %w", err)
	}

	attestation, err := clientattestation.
		NewClientAttestationBuilder(attester, in.Attester.Iss).
		ClientID(in.ClientID).
		ConfirmationKey(instance).
		ExpiresIn(in.AttestationTTLSeconds).
		Build()
	if err != nil {
		return fmt.Errorf("build attestation: %w", err)
	}

	cred, err := clientattestation.NewClientAttestationCredential(attestation, instance)
	if err != nil {
		return fmt.Errorf("credential: %w", err)
	}
	popHeaders, err := cred.PopHeaders(in.ClientID, in.Audience, "")
	if err != nil {
		return fmt.Errorf("pop headers: %w", err)
	}
	dpopHeaders, err := cred.DpopHeaders("POST", in.TokenEndpoint, "")
	if err != nil {
		return fmt.Errorf("dpop headers: %w", err)
	}

	out := map[string]any{
		"language":      "go",
		"attestation":   attestation,
		"pop":           popHeaders[clientattestation.PopHeader],
		"dpop":          dpopHeaders[clientattestation.DpopHeader],
		"audience":      in.Audience,
		"tokenEndpoint": in.TokenEndpoint,
		"clientId":      in.ClientID,
	}

	outDir := filepath.Join(vectorsDir, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir out: %w", err)
	}
	body, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal output: %w", err)
	}
	outPath := filepath.Join(outDir, "go.json")
	if err := os.WriteFile(outPath, body, 0o644); err != nil {
		return fmt.Errorf("write go.json: %w", err)
	}
	fmt.Printf("wrote %s\n", outPath)
	return nil
}

// findVectorsDir locates the shared vectors/ directory by walking up from the
// current working directory until a vectors/inputs.json is found.
func findVectorsDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(dir, "vectors")
		if _, err := os.Stat(filepath.Join(candidate, "inputs.json")); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not locate vectors/inputs.json walking up from working directory")
		}
		dir = parent
	}
}
