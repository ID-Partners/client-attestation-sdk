package clientattestation

import (
	"context"
	"testing"
)

func TestDefaultEvidencePathsAreConstants(t *testing.T) {
	const tokenFile, socket = DefaultTokenFile, DefaultSpiffeSocket // compiles only while these are constants
	if tokenFile != "/var/run/secrets/tokens/attester-token" || socket != "/tmp/spire-agent/public/api.sock" {
		t.Fatalf("default evidence paths changed: %q %q", tokenFile, socket)
	}
}

func TestAttesterMetadataReturnsStaticMetadata(t *testing.T) {
	md := AttesterMetadata{EvidenceAudience: "https://attester.example",
		AttestationEndpoint: "https://attester.example/mint", TokenEndpoint: "https://as.example/token"}
	ca, err := NewClientAttestation("", WithAttesterMetadata(md))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ca.AttesterMetadata(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.TokenEndpoint != md.TokenEndpoint || got.AttestationEndpoint != md.AttestationEndpoint {
		t.Fatalf("AttesterMetadata %+v", got)
	}
}
