// Command protected-resource is a dependency-free OAuth-protected resource server (MCP-style) built with
// tokenvalidator.ProtectedResource. The same shape serves an MCP server or an A2A agent — only the audience
// (this resource's canonical URI) and the authorization server change.
//
//	go run ./examples/protected-resource
//	curl -s  localhost:8770/.well-known/oauth-protected-resource        # RFC 9728 metadata
//	curl -i  localhost:8770/mcp                                         # 401 + WWW-Authenticate
//	curl -i  -H 'Authorization: Bearer <token>' localhost:8770/mcp      # 200 when valid for this resource
package main

import (
	"encoding/json"
	"log"
	"net/http"

	tv "github.com/id-partners/client-attestation-sdk/go/tokenvalidator"
)

const (
	resourceURI = "http://localhost:8770" // this server's canonical URI (RFC 8707) — the token audience
	issuer      = "https://issuer.example.com"
)

func main() {
	validator, err := tv.New(&tv.Config{
		Issuer:         issuer,
		Audiences:      []string{resourceURI}, // reject tokens minted for a different service (RFC 8707)
		JWKSURI:        issuer + "/jwks",
		RequiredScopes: []string{"mcp:call"},
	})
	if err != nil {
		log.Fatal(err)
	}
	resource, err := tv.NewProtectedResource(resourceURI, []string{issuer}, validator, []string{"mcp:call"})
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == resource.MetadataPath() {
			writeJSON(w, http.StatusOK, resource.Metadata())
			return
		}
		d := resource.Authenticate(r.Header.Get("Authorization"), nil)
		if !d.Authorized {
			w.Header().Set("WWW-Authenticate", d.WWWAuthenticate)
			writeJSON(w, d.Status, map[string]string{"error": orDefault(d.Error, "unauthorized")})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sub": d.Result.Subject, "scopes": d.Result.Scopes})
	})

	log.Println("protected resource on", resourceURI)
	log.Fatal(http.ListenAndServe(":8770", nil))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
