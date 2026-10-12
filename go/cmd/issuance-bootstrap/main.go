// Bootstrap a Client Attestation from a workload's SPIFFE identity, then use it to get a token.
//
//	ISSUER=http://localhost:9031 USE_DEV_SVID=1 go run ./cmd/issuance-bootstrap
//
// Plain http is refused for anything but loopback unless you also set ALLOW_INSECURE=1.
// In production use clientattestation.SpireWorkloadAPISvidSource{} (the default) against a real agent.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	ca "github.com/id-partners/client-attestation-sdk/go"
)

const maxResponseBytes = 1 << 20

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	issuer := strings.TrimRight(env("ISSUER", "https://pf.example.com"), "/")
	clientID := env("CLIENT_ID", "https://payment-agent.banking.demo")
	attester := env("ATTESTER_ISSUER", "https://attester.banking.demo")
	opIssuer := env("OP_ISSUER", "https://as.banking.demo")
	must(requireSecure(issuer))

	var source ca.SvidSource
	switch {
	case os.Getenv("SVID_JWT") != "":
		source = ca.StaticSvidSource{SVID: os.Getenv("SVID_JWT")}
	case os.Getenv("USE_DEV_SVID") == "1":
		source = ca.HTTPSvidSource{URL: issuer + "/dev/svid"}
	default:
		source = ca.SpireWorkloadAPISvidSource{}
	}

	var opts []ca.IssuanceOption
	if os.Getenv("ALLOW_INSECURE") == "1" {
		opts = append(opts, ca.WithIssuanceAllowInsecure()) // requireSecure has already vetted the URL
	}
	client, err := ca.NewAttestationIssuanceClient(issuer+"/federation/attestation", clientID, attester, source, opts...)
	must(err)
	issued, err := client.Bootstrap([]map[string]any{{"type": "sales_agent", "sales_regions": []string{"EMEA"}}}, "")
	must(err)
	fmt.Printf("minted attestation: %.48s…  expires_in=%d\n", issued.Attestation, issued.ExpiresIn)
	fmt.Printf("instance cnf kid  : %s\n", client.InstanceKey.KeyID())

	pop, err := issued.Pop(opIssuer, clientID, "")
	must(err)
	req, _ := http.NewRequest(http.MethodPost, issuer+"/as/token.oauth2", strings.NewReader("grant_type=client_credentials"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("OAuth-Client-Attestation", issued.Attestation)
	req.Header.Set("OAuth-Client-Attestation-PoP", pop)
	httpClient := &http.Client{
		Timeout: 20 * time.Second,
		// The request carries the attestation and PoP: never replay them to wherever a 3xx points.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := httpClient.Do(req)
	must(err)
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		must(fmt.Errorf("token endpoint answered HTTP %d (redirect, not followed)", resp.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	must(err)
	if len(body) > maxResponseBytes {
		must(fmt.Errorf("token endpoint response is larger than %d bytes", maxResponseBytes))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	_ = json.Unmarshal(body, &tok)
	if resp.StatusCode != 200 || tok.AccessToken == "" {
		fmt.Printf("token endpoint    : HTTP %d  error=%q\n", resp.StatusCode, tok.Error)
		os.Exit(1)
	}
	sum := sha256.Sum256([]byte(tok.AccessToken))
	fmt.Printf("token endpoint    : HTTP %d  access_token=%d chars, sha256 %.6x\n", resp.StatusCode, len(tok.AccessToken), sum[:])
	fmt.Println("BOOTSTRAP OK")
}

// requireSecure refuses a plain-http ISSUER for anything but loopback, unless ALLOW_INSECURE=1: the SVID,
// attestation and PoP all travel to it.
func requireSecure(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil {
		return err
	}
	if u.Scheme == "https" || os.Getenv("ALLOW_INSECURE") == "1" {
		return nil
	}
	switch strings.ToLower(u.Hostname()) {
	case "localhost", "127.0.0.1", "::1":
		if u.Scheme == "http" {
			return nil
		}
	}
	return fmt.Errorf("ISSUER must use https: %s (plain http is allowed for loopback, or set ALLOW_INSECURE=1)", issuer)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
