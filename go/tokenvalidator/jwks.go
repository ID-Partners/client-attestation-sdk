package tokenvalidator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/id-partners/client-attestation-sdk/go/internal/netpolicy"
	"github.com/id-partners/client-attestation-sdk/go/internal/sdklog"
)

// MaxJWKSBytes caps the size of a fetched JWKS document.
const MaxJWKSBytes = 512 * 1024

// Defaults for a jwks URI provider's refresh policy.
const (
	DefaultJWKSMinRefresh = 30 * time.Second
	DefaultJWKSMaxAge     = time.Hour
)

// HTTPGetFunc fetches the body at url, for WithHTTPGet (JWKS fetches). The default uses net/http with
// the SDK's timeout, no redirects and a response size cap.
type HTTPGetFunc func(url string) ([]byte, error)

// jwksProvider resolves issuer signing keys — from a static JWKS or a jwksURI
// (fetched and cached, refreshed on an unknown kid and when the cached set
// grows old).
//
// A jwksURI provider never fetches more than once per minRefresh, however many
// unknown kid values it is shown, and concurrent misses share one fetch.
// Without that, a stream of tokens with made-up kid values turns every request
// into a request to the issuer.
type jwksProvider struct {
	static     bool
	jwksURI    string
	get        HTTPGetFunc
	minRefresh time.Duration
	maxAge     time.Duration
	now        func() time.Time // time.Now, whose monotonic reading ages the set; not the validator's WithClock
	logger     *slog.Logger

	refreshMu sync.Mutex // one fetch at a time

	mu          sync.Mutex // guards the fields below
	set         jwk.Set
	loadedAt    time.Time
	lastAttempt time.Time
	lastErr     error
}

// newJWKSProvider builds a provider from either static raw JWKS JSON or a
// jwksURI. The httpGet func is used for URI fetches; when nil a default
// net/http client with a timeout is used.
func newJWKSProvider(raw json.RawMessage, jwksURI string, httpGet HTTPGetFunc) (*jwksProvider, error) {
	get := httpGet
	if get == nil {
		get = defaultHTTPGet
	}
	p := &jwksProvider{
		jwksURI: jwksURI, get: get,
		minRefresh: DefaultJWKSMinRefresh, maxAge: DefaultJWKSMaxAge, now: time.Now,
	}
	if len(raw) > 0 {
		set, err := parseSigningKeys(raw)
		if err != nil {
			return nil, fmt.Errorf("parse jwks: %w", err)
		}
		p.static = true
		p.set = set
	}
	return p, nil
}

// privateMembers are the JWK members that only a private or symmetric key carries (RFC 7518 section 6).
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "k"}

// parseSigningKeys parses a JWKS, keeping only the keys that may verify a signature: a JWK whose "use" is
// present and not "sig", whose "key_ops" is present and lacks "verify", or that carries private members is
// dropped, as if it were not in the set. So is an entry that can't be read (not a JSON object, an unknown
// "kty", a member of the wrong type, a key missing a parameter): the rest of the set still counts. Only a
// document that isn't a JSON object with a "keys" array is an error.
func parseSigningKeys(raw []byte) (jwk.Set, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	set := jwk.NewSet()
	for _, entry := range doc.Keys {
		var members map[string]json.RawMessage
		if json.Unmarshal(entry, &members) != nil || members == nil || !verifiesSignatures(members) {
			continue
		}
		key, err := jwk.ParseKey(entry)
		if err != nil {
			continue // an unreadable key is left out, the rest still count
		}
		if err := set.AddKey(key); err != nil {
			return nil, err
		}
	}
	return set, nil
}

func verifiesSignatures(k map[string]json.RawMessage) bool {
	if raw, ok := k["use"]; ok {
		var use any
		if json.Unmarshal(raw, &use) != nil || use != "sig" {
			return false
		}
	}
	if raw, ok := k["key_ops"]; ok {
		var ops []any
		if json.Unmarshal(raw, &ops) != nil || !containsAny(ops, "verify") {
			return false
		}
	}
	for _, m := range privateMembers {
		if _, ok := k[m]; ok {
			return false
		}
	}
	return true
}

func containsAny(list []any, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// resolve returns the signing key for kid and alg. When kid is empty and the set holds
// exactly one key, that key is returned. A key whose JWK declares an "alg" is
// only returned for that alg. Returns (nil, err) when a fetch failed and no
// key is held, (nil, nil) when no matching key can be found.
func (p *jwksProvider) resolve(kid, alg string) (jwk.Key, error) {
	if !p.static && p.jwksURI != "" {
		if _, ok := p.lookup(kid, alg); !ok || p.stale() {
			p.refresh(kid, alg, ok)
		}
	}
	key, ok := p.lookup(kid, alg)
	if !ok {
		p.mu.Lock()
		err := p.lastErr
		p.mu.Unlock()
		return nil, err
	}
	return key, nil
}

// lookup checks the currently loaded set without any network access: for kid, the first key in document
// order with that kid that may be used for alg; for an empty kid, the sole key when the set holds exactly
// one (and it may be used for alg).
func (p *jwksProvider) lookup(kid, alg string) (jwk.Key, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.set == nil {
		return nil, false
	}
	if kid == "" {
		if p.set.Len() != 1 {
			return nil, false
		}
		key, _ := p.set.Key(0)
		return key, allowsAlgorithm(key, alg)
	}
	for i := 0; i < p.set.Len(); i++ {
		if key, _ := p.set.Key(i); key.KeyID() == kid && allowsAlgorithm(key, alg) {
			return key, true
		}
	}
	return nil, false
}

// allowsAlgorithm reports whether key may be used for alg: a JWK that declares an "alg" only for that one.
func allowsAlgorithm(key jwk.Key, alg string) bool {
	declared := key.Algorithm().String()
	return declared == "" || alg == "" || declared == alg
}

func (p *jwksProvider) stale() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.loadedAt.IsZero() || p.now().Sub(p.loadedAt) >= p.maxAge
}

// refresh re-fetches the key set from the jwks URI, unless another caller just
// did or the cooldown since the last attempt has not passed. A failed fetch
// keeps the keys already held.
//
// A caller that already holds a usable (if stale) key never waits for another
// goroutine's fetch: it goes on with the key it has. One without a key waits
// for a fetch in flight, which may bring its key.
func (p *jwksProvider) refresh(kid, alg string, haveKey bool) {
	if haveKey {
		if !p.refreshMu.TryLock() {
			return
		}
	} else {
		p.refreshMu.Lock()
	}
	defer p.refreshMu.Unlock()
	if _, ok := p.lookup(kid, alg); ok && !p.stale() {
		return // refreshed while this caller waited
	}
	p.mu.Lock()
	now := p.now()
	if !p.lastAttempt.IsZero() && now.Sub(p.lastAttempt) < p.minRefresh {
		p.mu.Unlock()
		p.log(slog.LevelDebug, "jwks.refetch_throttled", "host", sdklog.Host(p.jwksURI))
		return
	}
	p.lastAttempt = now
	p.mu.Unlock()

	set, reason, err := p.fetch()
	if err != nil {
		status := 0
		var se *statusError
		if errors.As(err, &se) {
			status = se.status
		}
		p.log(slog.LevelWarn, "jwks.fetch_failed", "host", sdklog.Host(p.jwksURI), "reason", reason,
			"status", sdklog.NonZero(int64(status)))
	} else {
		p.log(slog.LevelDebug, "jwks.fetched", "host", sdklog.Host(p.jwksURI), "keys", set.Len())
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.lastErr = err
		return
	}
	p.set, p.loadedAt, p.lastErr = set, p.now(), nil
}

func (p *jwksProvider) log(level slog.Level, event string, kv ...any) {
	sdklog.Log(context.Background(), p.logger, level, event, kv...)
}

// fetch gets and parses the key set; on failure reason classifies it for jwks.fetch_failed.
func (p *jwksProvider) fetch() (set jwk.Set, reason string, err error) {
	body, err := p.get(p.jwksURI)
	if err != nil {
		reason, _ = failureReason(err)
		return nil, reason, fmt.Errorf("fetch jwks: %w", err)
	}
	if len(body) > MaxJWKSBytes {
		return nil, "too_large", fmt.Errorf("fetch jwks: larger than %d bytes", MaxJWKSBytes)
	}
	set, err = parseSigningKeys(body)
	if err != nil {
		return nil, "malformed", fmt.Errorf("parse jwks: %w", err)
	}
	return set, "", nil
}

var jwksHTTPClient = &http.Client{
	Timeout:   10 * time.Second,
	Transport: netpolicy.Transport, // an environment proxy only for https to a remote host
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("jwks: redirects are not followed")
	},
}

func defaultHTTPGet(url string) ([]byte, error) {
	shown := netpolicy.Display(url)
	if netpolicy.HasUserinfo(url) {
		return nil, fmt.Errorf("GET %s: %w", shown, netpolicy.ErrUserinfo)
	}
	resp, err := jwksHTTPClient.Get(url) //nolint:gosec // url is operator-configured
	if err != nil {
		return nil, netpolicy.RedactError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &statusError{what: "GET " + shown, status: resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxJWKSBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxJWKSBytes {
		return nil, &tooLargeError{msg: fmt.Sprintf("GET %s: larger than %d bytes", shown, MaxJWKSBytes)}
	}
	return body, nil
}
