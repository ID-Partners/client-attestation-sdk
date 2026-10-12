package clientattestation

import (
	"net/http"
	"testing"
	"time"
)

// WithTimeout of zero or a negative duration means the 20s default, never an unbounded client.
func TestNonPositiveTimeoutMeansTheDefault(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second} {
		ca, err := NewClientAttestation("https://attester.example.com", WithTimeout(d))
		if err != nil || ca.httpClient.Timeout != 20*time.Second {
			t.Fatalf("WithTimeout(%v): err = %v, timeout = %v, want the 20s default", d, err, ca.httpClient.Timeout)
		}
	}
	ca, err := NewClientAttestation("https://attester.example.com", WithTimeout(3*time.Second))
	if err != nil || ca.httpClient.Timeout != 3*time.Second {
		t.Fatalf("WithTimeout(3s): err = %v", err)
	}
}

// A supplied client with no positive Timeout gets the configured timeout (20s by default), never 0.
func TestSuppliedClientWithoutTimeoutGetsTheConfiguredOne(t *testing.T) {
	for _, tc := range []struct {
		name   string
		opts   []Option
		client time.Duration
		want   time.Duration
	}{
		{"zero, default", nil, 0, 20 * time.Second},
		{"negative, default", nil, -time.Second, 20 * time.Second},
		{"zero, configured", []Option{WithTimeout(4 * time.Second)}, 0, 4 * time.Second},
		{"positive is kept", []Option{WithTimeout(4 * time.Second)}, 7 * time.Second, 7 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			supplied := &http.Client{Timeout: tc.client}
			ca, err := NewClientAttestation("https://attester.example.com", append(tc.opts, WithHTTPClient(supplied))...)
			if err != nil {
				t.Fatal(err)
			}
			if ca.httpClient.Timeout != tc.want || supplied.Timeout != tc.client {
				t.Fatalf("timeout = %v (supplied now %v), want %v", ca.httpClient.Timeout, supplied.Timeout, tc.want)
			}
		})
	}
}
