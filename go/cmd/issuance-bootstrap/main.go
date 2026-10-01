// Bootstrap a Client Attestation from a workload's SPIFFE identity, then use it to get a token.
//
//	ISSUER=http://localhost:9031 USE_DEV_SVID=1 go run ./cmd/issuance-bootstrap
//
// In production use clientattestation.SpireWorkloadAPISvidSource{} (the default) against a real agent.
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	ca "github.com/id-partners/client-attestation-sdk/go"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	issuer := strings.TrimRight(env("ISSUER", "http://localhost:9031"), "/")
	clientID := env("CLIENT_ID", "https://payment-agent.banking.demo")
	attester := env("ATTESTER_ISSUER", "https://attester.banking.demo")
	opIssuer := env("OP_ISSUER", "https://as.banking.demo")

	var source ca.SvidSource
	switch {
	case os.Getenv("SVID_JWT") != "":
		source = ca.StaticSvidSource{SVID: os.Getenv("SVID_JWT")}
	case os.Getenv("USE_DEV_SVID") == "1":
		source = ca.HTTPSvidSource{URL: issuer + "/dev/svid"}
	default:
		source = ca.SpireWorkloadAPISvidSource{}
	}

	client, err := ca.NewAttestationIssuanceClient(issuer+"/federation/attestation", clientID, attester, source)
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
	resp, err := http.DefaultClient.Do(req)
	must(err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("token endpoint    : HTTP %d  %.80s\n", resp.StatusCode, string(body))
	if resp.StatusCode != 200 {
		os.Exit(1)
	}
	fmt.Println("BOOTSTRAP OK")
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
