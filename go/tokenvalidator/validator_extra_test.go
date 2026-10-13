package tokenvalidator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

const (
	testIssuer   = "https://issuer.test"
	testAudience = "https://api.test"
)

// newTestKey generates a P-256 signing key (with kid when non-empty) and the
// matching public JWKS document.
func newTestKey(t *testing.T, kid string) (jwk.Key, json.RawMessage) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key, err := jwk.FromRaw(priv)
	if err != nil {
		t.Fatalf("import key: %v", err)
	}
	if kid != "" {
		if err := key.Set(jwk.KeyIDKey, kid); err != nil {
			t.Fatalf("set kid: %v", err)
		}
	}
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	pubJSON, err := json.Marshal(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return key, json.RawMessage(`{"keys":[` + string(pubJSON) + `]}`)
}

// signPayload signs raw payload bytes with the key (ES256), carrying the key's
// kid in the protected header when present.
func signPayload(t *testing.T, key jwk.Key, payload []byte) string {
	t.Helper()
	hdrs := jws.NewHeaders()
	if kid := key.KeyID(); kid != "" {
		if err := hdrs.Set(jws.KeyIDKey, kid); err != nil {
			t.Fatalf("set kid header: %v", err)
		}
	}
	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256, key, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return string(signed)
}

// signClaims signs claims, defaulting iss and aud to the test issuer and audience when absent.
func signClaims(t *testing.T, key jwk.Key, claims map[string]any) string {
	t.Helper()
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = testIssuer
	}
	if _, ok := claims["aud"]; !ok {
		claims["aud"] = testAudience
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return signPayload(t, key, payload)
}

func TestNewRejectsInvalidStaticJWKS(t *testing.T) {
	if _, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKS: json.RawMessage(`{`)}); err == nil {
		t.Error("expected an error for invalid JWKS JSON")
	}
}

func TestJWKSURIRefreshResolvesUnknownKid(t *testing.T) {
	key, jwks := newTestKey(t, "k1")
	calls := 0
	val, err := New(&Config{Audiences: []string{testAudience}, Issuer: testIssuer, JWKSURI: "https://as.test/jwks"},
		WithHTTPGet(func(url string) ([]byte, error) {
			calls++
			if url != "https://as.test/jwks" {
				t.Errorf("fetched %q", url)
			}
			return []byte(jwks), nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	token := signClaims(t, key, map[string]any{
		"iss": testIssuer, "sub": "agent-1", "exp": time.Now().Unix() + 300,
	})
	r := val.Validate(token, nil)
	if !r.Valid {
		t.Fatalf("expected valid, got %s: %s", r.Error, r.ErrorDescription)
	}
	if calls != 1 {
		t.Errorf("jwks fetched %d times, want 1", calls)
	}
}

func TestJWKSURIFetchFailure(t *testing.T) {
	key, _ := newTestKey(t, "k1")
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKSURI: "https://as.test/jwks"},
		WithHTTPGet(func(string) ([]byte, error) {
			return nil, errors.New("dial tcp keys.internal:8443: connection refused")
		}))
	if err != nil {
		t.Fatal(err)
	}
	token := signClaims(t, key, map[string]any{"exp": time.Now().Unix() + 300})
	r := val.Validate(token, nil)
	// the description reaches WWW-Authenticate: the fetch failure's detail stays in the log
	if r.Valid || r.Error != ErrKeyNotFound || r.ErrorDescription != "signing keys unavailable" {
		t.Errorf("got valid=%v error=%s desc=%s", r.Valid, r.Error, r.ErrorDescription)
	}
}

func TestJWKSURIUnparseableDocument(t *testing.T) {
	key, _ := newTestKey(t, "k1")
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKSURI: "https://as.test/jwks"},
		WithHTTPGet(func(string) ([]byte, error) { return []byte("not json"), nil }))
	if err != nil {
		t.Fatal(err)
	}
	token := signClaims(t, key, map[string]any{"exp": time.Now().Unix() + 300})
	r := val.Validate(token, nil)
	if r.Valid || r.Error != ErrKeyNotFound || r.ErrorDescription != "signing keys unavailable" {
		t.Errorf("got valid=%v error=%s desc=%s", r.Valid, r.Error, r.ErrorDescription)
	}
}

func TestJWKSURIRefreshStillMissingKid(t *testing.T) {
	key, _ := newTestKey(t, "k1")
	_, otherJWKS := newTestKey(t, "other")
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKSURI: "https://as.test/jwks"},
		WithHTTPGet(func(string) ([]byte, error) { return []byte(otherJWKS), nil }))
	if err != nil {
		t.Fatal(err)
	}
	token := signClaims(t, key, map[string]any{"exp": time.Now().Unix() + 300})
	r := val.Validate(token, nil)
	if r.Valid || r.Error != ErrKeyNotFound || !strings.Contains(r.ErrorDescription, "no signing key") {
		t.Errorf("got valid=%v error=%s desc=%s", r.Valid, r.Error, r.ErrorDescription)
	}
}

func TestNoKeySourceConfigured(t *testing.T) {
	key, _ := newTestKey(t, "k1")
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}})
	if err != nil {
		t.Fatal(err)
	}
	token := signClaims(t, key, map[string]any{"exp": time.Now().Unix() + 300})
	r := val.Validate(token, nil)
	if r.Valid || r.Error != ErrKeyNotFound {
		t.Errorf("got valid=%v error=%s", r.Valid, r.Error)
	}
}

func TestDefaultHTTPGetFetchesJWKS(t *testing.T) {
	key, jwks := newTestKey(t, "k1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwks))
	}))
	val, err := New(&Config{Audiences: []string{testAudience}, Issuer: testIssuer, JWKSURI: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	token := signClaims(t, key, map[string]any{
		"iss": testIssuer, "exp": time.Now().Unix() + 300,
	})
	if r := val.Validate(token, nil); !r.Valid {
		t.Fatalf("expected valid, got %s: %s", r.Error, r.ErrorDescription)
	}
	// A dead endpoint must fail closed through the same default transport.
	srv.Close()
	val2, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKSURI: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if r := val2.Validate(token, nil); r.Valid || r.Error != ErrKeyNotFound {
		t.Errorf("dead jwks endpoint: got valid=%v error=%s", r.Valid, r.Error)
	}
}

func TestSingleKeySetMatchesTokenWithoutKid(t *testing.T) {
	key, jwks := newTestKey(t, "")
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKS: jwks})
	if err != nil {
		t.Fatal(err)
	}
	token := signClaims(t, key, map[string]any{"exp": time.Now().Unix() + 300})
	if r := val.Validate(token, nil); !r.Valid {
		t.Fatalf("expected valid, got %s: %s", r.Error, r.ErrorDescription)
	}
}

func TestMultiKeySetRejectsTokenWithoutKid(t *testing.T) {
	key, jwks1 := newTestKey(t, "")
	_, jwks2 := newTestKey(t, "k2")
	var a, b struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(jwks1, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(jwks2, &b); err != nil {
		t.Fatal(err)
	}
	merged, err := json.Marshal(map[string]any{"keys": append(a.Keys, b.Keys...)})
	if err != nil {
		t.Fatal(err)
	}
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKS: merged})
	if err != nil {
		t.Fatal(err)
	}
	token := signClaims(t, key, map[string]any{"exp": time.Now().Unix() + 300})
	if r := val.Validate(token, nil); r.Valid || r.Error != ErrKeyNotFound {
		t.Errorf("got valid=%v error=%s", r.Valid, r.Error)
	}
}

func TestNotYetValidToken(t *testing.T) {
	key, jwks := newTestKey(t, "k1")
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKS: jwks})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	token := signClaims(t, key, map[string]any{"exp": now + 7200, "nbf": now + 3600})
	if r := val.Validate(token, nil); r.Valid || r.Error != ErrNotYetValid {
		t.Errorf("got valid=%v error=%s", r.Valid, r.Error)
	}
}

func TestCustomLeewayAllowsRecentlyExpiredToken(t *testing.T) {
	key, jwks := newTestKey(t, "k1")
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKS: jwks, LeewaySeconds: 300})
	if err != nil {
		t.Fatal(err)
	}
	token := signClaims(t, key, map[string]any{"exp": time.Now().Unix() - 60})
	if r := val.Validate(token, nil); !r.Valid {
		t.Errorf("expected valid within leeway, got %s", r.Error)
	}
}

func TestMalformedClaimsPayload(t *testing.T) {
	key, jwks := newTestKey(t, "k1")
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKS: jwks})
	if err != nil {
		t.Fatal(err)
	}
	token := signPayload(t, key, []byte("not-json"))
	r := val.Validate(token, nil)
	if r.Valid || r.Error != ErrInvalidToken || !strings.Contains(r.ErrorDescription, "payload is not JSON") {
		t.Errorf("got valid=%v error=%s desc=%s", r.Valid, r.Error, r.ErrorDescription)
	}
}

func TestGarbageTokenIsInvalid(t *testing.T) {
	_, jwks := newTestKey(t, "k1")
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKS: jwks})
	if err != nil {
		t.Fatal(err)
	}
	if r := val.Validate("garbage", nil); r.Valid || r.Error != ErrInvalidToken {
		t.Errorf("got valid=%v error=%s", r.Valid, r.Error)
	}
}

func TestAlgorithmNotAccepted(t *testing.T) {
	key, jwks := newTestKey(t, "k1")
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKS: jwks, AcceptedAlgorithms: []string{"RS256"}})
	if err != nil {
		t.Fatal(err)
	}
	token := signClaims(t, key, map[string]any{"exp": time.Now().Unix() + 300})
	if r := val.Validate(token, nil); r.Valid || r.Error != ErrUnsupportedAlgorithm {
		t.Errorf("got valid=%v error=%s", r.Valid, r.Error)
	}
}

func TestIntrospectWithoutConfiguration(t *testing.T) {
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := val.Introspect("tok"); err == nil {
		t.Error("expected an error with no introspection endpoint")
	}
	if _, err := val.ValidateActive("tok", nil); err == nil {
		t.Error("ValidateActive with no introspection endpoint: expected an error, not a verdict")
	}
}

func TestIntrospectionClientSecretPost(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"active":true,"scp":["read"],"aud":["https://rs.test"]}`)
	}))
	defer srv.Close()

	val, err := New(&Config{Issuer: testIssuer,
		Audiences: []string{"https://rs.test"},
		Introspection: &IntrospectionConfig{
			Endpoint: srv.URL, ClientID: "rs-1", ClientSecret: "s3cret",
			AuthMethod: "client_secret_post",
		},
	}, WithHTTPPost(nil)) // nil forces the defaultHTTPPost fallback inside Introspect
	if err != nil {
		t.Fatal(err)
	}
	r, err := val.ValidateActive("opaque", []string{"read"})
	if err != nil || !r.Valid {
		t.Fatalf("expected valid, got %s: %s", r.Error, r.ErrorDescription)
	}
	if gotAuth != "" {
		t.Errorf("Authorization = %q, want none for client_secret_post", gotAuth)
	}
	if !strings.Contains(gotBody, "client_id=rs-1") || !strings.Contains(gotBody, "client_secret=s3cret") {
		t.Errorf("body = %q", gotBody)
	}
	if len(r.Scopes) != 1 || r.Scopes[0] != "read" {
		t.Errorf("scopes = %v", r.Scopes)
	}
	if len(r.Audience) != 1 || r.Audience[0] != "https://rs.test" {
		t.Errorf("audience = %v", r.Audience)
	}
}

func TestValidateActiveInsufficientScopeViaConfig(t *testing.T) {
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience},
		RequiredScopes: []string{"admin"},
		Introspection:  &IntrospectionConfig{Endpoint: "https://as.test/introspect", ClientID: "rs", ClientSecret: "secret"},
	}, WithHTTPPost(func(endpoint, body string, headers map[string]string) (map[string]any, error) {
		return map[string]any{"active": true, "scope": "read"}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	r, err := val.ValidateActive("opaque", nil)
	if err != nil || r.Valid || r.Error != ErrInsufficientScope {
		t.Errorf("got valid=%v error=%s", r.Valid, r.Error)
	}
}

func TestValidateActiveWrongAudience(t *testing.T) {
	val, err := New(&Config{Issuer: testIssuer,
		Audiences:     []string{"https://rs.test"},
		Introspection: &IntrospectionConfig{Endpoint: "https://as.test/introspect", ClientID: "rs", ClientSecret: "secret"},
	}, WithHTTPPost(func(endpoint, body string, headers map[string]string) (map[string]any, error) {
		return map[string]any{"active": true, "aud": "https://other.test"}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	r, err := val.ValidateActive("opaque", nil)
	if err != nil || r.Valid || r.Error != ErrInvalidAudience {
		t.Errorf("got valid=%v error=%s", r.Valid, r.Error)
	}
}

func TestDefaultHTTPPostErrors(t *testing.T) {
	newVal := func(endpoint string) *AccessTokenValidator {
		val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, Introspection: &IntrospectionConfig{Endpoint: endpoint, ClientID: "rs", ClientSecret: "secret"},
			AllowInsecure: true}) // so "://bad" reaches the transport
		if err != nil {
			t.Fatal(err)
		}
		return val
	}
	if _, err := newVal("://bad").Introspect("tok"); err == nil {
		t.Error("invalid endpoint URL: expected an error")
	}

	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	dead.Close()
	if _, err := newVal(dead.URL).Introspect("tok"); err == nil {
		t.Error("unreachable endpoint: expected an error")
	}

	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "not json")
	}))
	defer badJSON.Close()
	if _, err := newVal(badJSON.URL).Introspect("tok"); err == nil {
		t.Error("unparseable response: expected an error")
	}

	truncated := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		io.WriteString(w, "short")
	}))
	defer truncated.Close()
	if _, err := newVal(truncated.URL).Introspect("tok"); err == nil {
		t.Error("truncated response body: expected an error")
	}
}

func TestClaimHelperTypeBranches(t *testing.T) {
	if got, err := scopesOf(map[string]any{}); err != nil || len(got) != 0 {
		t.Errorf("scopesOf(missing) = %v, %v", got, err)
	}
	if _, err := audienceOf(map[string]any{"aud": 42}); err == nil {
		t.Error("audienceOf(number) must fail")
	}
	if got := stringClaim(map[string]any{"sub": 5}, "sub"); got != "" {
		t.Errorf("stringClaim(non-string) = %q", got)
	}
	if got := intClaim(map[string]any{"exp": "soon"}, "exp"); got != 0 {
		t.Errorf("intClaim(non-number) = %d", got)
	}
}

func TestMetadataPathsForUnparseableResource(t *testing.T) {
	pr := &ProtectedResource{Resource: "://bad"}
	if pr.MetadataPath() != wellKnownProtectedResource {
		t.Errorf("MetadataPath = %q", pr.MetadataPath())
	}
	if pr.MetadataURL() != wellKnownProtectedResource {
		t.Errorf("MetadataURL = %q", pr.MetadataURL())
	}
}

// signClaimsTyp signs claims (with the signClaims defaults) carrying the given typ header.
func signClaimsTyp(t *testing.T, key jwk.Key, claims map[string]any, typ string) string {
	t.Helper()
	claims["iss"], claims["aud"] = testIssuer, testAudience
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, key.KeyID())
	_ = hdrs.Set(jws.TypeKey, typ)
	signed, err := jws.Sign(payload, jws.WithKey(jwa.ES256, key, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func TestNewRequiresIssuerAndAudience(t *testing.T) {
	_, jwks := newTestKey(t, "k1")
	if _, err := New(&Config{Audiences: []string{testAudience}, JWKS: jwks}); err == nil {
		t.Error("expected an error without an issuer")
	}
	if _, err := New(&Config{Issuer: testIssuer, JWKS: jwks}); err == nil {
		t.Error("expected an error without an audience")
	}
}

func TestTokenTypeComparisonFollowsRFC7515(t *testing.T) {
	key, jwks := newTestKey(t, "k1")
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKS: jwks})
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Unix() + 300
	for typ, want := range map[string]string{"application/at+jwt": ErrValid, "AT+JWT": ErrValid, "JWT": ErrInvalidTokenType} {
		r := val.Validate(signClaimsTyp(t, key, map[string]any{"exp": exp}, typ), nil)
		got := ErrValid
		if !r.Valid {
			got = r.Error
		}
		if got != want {
			t.Errorf("typ %q: got %s, want %s", typ, got, want)
		}
	}
}

func TestTokenTypeCheckCanBeTurnedOff(t *testing.T) {
	key, jwks := newTestKey(t, "k1")
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKS: jwks, DisableTokenTypeCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	if r := val.Validate(signClaimsTyp(t, key, map[string]any{"exp": time.Now().Unix() + 300}, "JWT"), nil); !r.Valid {
		t.Errorf("expected valid with the typ check off, got %s", r.Error)
	}
}

func TestNonNumericExpIsMalformed(t *testing.T) {
	key, jwks := newTestKey(t, "k1")
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKS: jwks})
	if err != nil {
		t.Fatal(err)
	}
	for _, exp := range []any{"4102444800", true} {
		if r := val.Validate(signClaims(t, key, map[string]any{"exp": exp}), nil); r.Error != ErrInvalidToken {
			t.Errorf("exp %v: got %s, want %s", exp, r.Error, ErrInvalidToken)
		}
	}
}

func TestIatWithinLeewayIsAccepted(t *testing.T) {
	key, jwks := newTestKey(t, "k1")
	val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKS: jwks})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if r := val.Validate(signClaims(t, key, map[string]any{"exp": now + 300, "iat": now + 30}), nil); !r.Valid {
		t.Errorf("expected valid, got %s", r.Error)
	}
}

func TestJWKDeclaredAlgBindsTheKey(t *testing.T) {
	// the same EC key published as ES384-only: an ES256 token signed with it must not resolve
	key, _ := newTestKey(t, "k1")
	pub, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Set(jwk.AlgorithmKey, jwa.ES384); err != nil {
		t.Fatal(err)
	}
	pubJSON, _ := json.Marshal(pub)
	val, err := New(&Config{
		Issuer: testIssuer, Audiences: []string{testAudience},
		JWKS: json.RawMessage(`{"keys":[` + string(pubJSON) + `]}`), AcceptedAlgorithms: []string{"ES256", "ES384"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := val.Validate(signClaims(t, key, map[string]any{"exp": time.Now().Unix() + 300}), nil); r.Error != ErrKeyNotFound {
		t.Errorf("got %s, want %s", r.Error, ErrKeyNotFound)
	}
}

// F6: client_secret_basic form-urlencodes the client id and the secret before joining them (RFC 6749 section
// 2.3.1). The same fixture and header are in every port's tests and in validation/introspection.json.
func TestIntrospectBasicAuthFormEncodesCredentials(t *testing.T) {
	var gotAuth, gotBody string
	post := func(_ string, body string, headers map[string]string) (map[string]any, error) {
		gotAuth, gotBody = headers["Authorization"], body
		return map[string]any{"active": true}, nil
	}
	for _, method := range []string{"", "client_secret_basic"} {
		val, err := New(&Config{Issuer: testIssuer, Audiences: []string{testAudience},
			Introspection: &IntrospectionConfig{Endpoint: "https://issuer.example.com/introspect",
				ClientID: "rs:1 a+b%c", ClientSecret: "s3cr*t~-._!'()/?#&=\u00e9\U0001F600", AuthMethod: method},
		}, WithHTTPPost(post))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := val.Introspect("opaque"); err != nil {
			t.Fatal(err)
		}
		want := "Basic cnMlM0ExK2ElMkJiJTI1YzpzM2NyJTJBdH4tLl8lMjElMjclMjglMjklMkYlM0YlMjMlMjYlM0QlQzMlQTklRjAlOUYlOTglODA="
		if gotAuth != want {
			t.Errorf("AuthMethod %q: Authorization = %q, want %q", method, gotAuth, want)
		}
		if strings.Contains(gotBody, "client_id") || strings.Contains(gotBody, "client_secret") {
			t.Errorf("AuthMethod %q: body carries credentials: %q", method, gotBody)
		}
	}
	if got := basicAuthorization("rs", "secret"); got != "Basic cnM6c2VjcmV0" {
		t.Errorf("plain credentials: %q", got)
	}
}
