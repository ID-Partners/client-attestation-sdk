package tokenvalidator

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// MaxJWKSBytes caps the size of a fetched JWKS document.
const MaxJWKSBytes = 512 * 1024

// Defaults for a jwks URI provider's refresh policy.
const (
	DefaultJWKSMinRefresh = 30 * time.Second
	DefaultJWKSMaxAge     = time.Hour
)

// httpGetFunc fetches the body at url. Injectable so tests can avoid real HTTP.
type httpGetFunc func(url string) ([]byte, error)

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
	get        httpGetFunc
	minRefresh time.Duration
	maxAge     time.Duration
	now        func() time.Time

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
func newJWKSProvider(raw json.RawMessage, jwksURI string, httpGet httpGetFunc) (*jwksProvider, error) {
	get := httpGet
	if get == nil {
		get = defaultHTTPGet
	}
	p := &jwksProvider{
		jwksURI: jwksURI, get: get,
		minRefresh: DefaultJWKSMinRefresh, maxAge: DefaultJWKSMaxAge, now: time.Now,
	}
	if len(raw) > 0 {
		set, err := jwk.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("parse jwks: %w", err)
		}
		p.static = true
		p.set = set
	}
	return p, nil
}

// resolve returns the signing key for kid. When kid is empty and the set holds
// exactly one key, that key is returned. A key whose JWK declares an "alg" is
// only returned for that alg. Returns (nil, err) when a fetch failed and no
// key is held, (nil, nil) when no matching key can be found.
func (p *jwksProvider) resolve(kid, alg string) (jwk.Key, error) {
	if !p.static && p.jwksURI != "" {
		if _, ok := p.lookup(kid); !ok || p.stale() {
			p.refresh(kid)
		}
	}
	key, ok := p.lookup(kid)
	if !ok {
		p.mu.Lock()
		err := p.lastErr
		p.mu.Unlock()
		return nil, err
	}
	if declared := key.Algorithm().String(); declared != "" && alg != "" && declared != alg {
		return nil, nil
	}
	return key, nil
}

// lookup checks the currently loaded set for kid (or the sole key when kid is
// empty) without any network access.
func (p *jwksProvider) lookup(kid string) (jwk.Key, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.set == nil {
		return nil, false
	}
	if kid != "" {
		return p.set.LookupKeyID(kid)
	}
	if p.set.Len() == 1 {
		return p.set.Key(0)
	}
	return nil, false
}

func (p *jwksProvider) stale() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.loadedAt.IsZero() || p.now().Sub(p.loadedAt) >= p.maxAge
}

// refresh re-fetches the key set from the jwks URI, unless another caller just
// did or the cooldown since the last attempt has not passed. A failed fetch
// keeps the keys already held.
func (p *jwksProvider) refresh(kid string) {
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()
	if _, ok := p.lookup(kid); ok && !p.stale() {
		return // refreshed while this caller waited
	}
	p.mu.Lock()
	now := p.now()
	if !p.lastAttempt.IsZero() && now.Sub(p.lastAttempt) < p.minRefresh {
		p.mu.Unlock()
		return
	}
	p.lastAttempt = now
	p.mu.Unlock()

	set, err := p.fetch()
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.lastErr = err
		return
	}
	p.set, p.loadedAt, p.lastErr = set, p.now(), nil
}

func (p *jwksProvider) fetch() (jwk.Set, error) {
	body, err := p.get(p.jwksURI)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	if len(body) > MaxJWKSBytes {
		return nil, fmt.Errorf("fetch jwks: larger than %d bytes", MaxJWKSBytes)
	}
	set, err := jwk.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	return set, nil
}

var jwksHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("jwks: redirects are not followed")
	},
}

func defaultHTTPGet(url string) ([]byte, error) {
	resp, err := jwksHTTPClient.Get(url) //nolint:gosec // url is operator-configured
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxJWKSBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxJWKSBytes {
		return nil, fmt.Errorf("GET %s: larger than %d bytes", url, MaxJWKSBytes)
	}
	return body, nil
}
