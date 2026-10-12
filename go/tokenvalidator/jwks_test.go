package tokenvalidator

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func uriProvider(t *testing.T, get HTTPGetFunc) (*jwksProvider, *fakeClock) {
	t.Helper()
	p, err := newJWKSProvider(nil, "https://as.test/jwks", get)
	if err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	p.now = clock.now
	return p, clock
}

func TestUnknownKidsCannotForceAFetchPerRequest(t *testing.T) {
	_, jwks := newTestKey(t, "real")
	var calls int32
	p, clock := uriProvider(t, func(string) ([]byte, error) { atomic.AddInt32(&calls, 1); return jwks, nil })
	if k, _ := p.resolve("real", ""); k == nil {
		t.Fatal("expected the real key")
	}
	for i := 0; i < 100; i++ {
		if k, _ := p.resolve("made-up", ""); k != nil {
			t.Fatal("made-up kid resolved")
		}
	}
	if calls != 1 {
		t.Fatalf("fetched %d times inside the cooldown, want 1", calls)
	}
	clock.t = clock.t.Add(DefaultJWKSMinRefresh)
	p.resolve("made-up", "")
	if calls != 2 {
		t.Fatalf("fetched %d times after the cooldown, want 2", calls)
	}
}

func TestConcurrentMissesShareOneFetch(t *testing.T) {
	_, jwks := newTestKey(t, "k")
	var calls int32
	release := make(chan struct{})
	p, _ := uriProvider(t, func(string) ([]byte, error) {
		atomic.AddInt32(&calls, 1)
		<-release
		return jwks, nil
	})
	var wg sync.WaitGroup
	var found int32
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if k, _ := p.resolve("k", ""); k != nil {
				atomic.AddInt32(&found, 1)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if calls != 1 || found != 10 {
		t.Fatalf("calls=%d found=%d, want 1 and 10", calls, found)
	}
}

func TestACallerHoldingAStaleKeyNeverWaitsForAFetch(t *testing.T) {
	_, jwks := newTestKey(t, "k")
	var slow atomic.Bool
	started := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	p, clock := uriProvider(t, func(string) ([]byte, error) {
		if slow.Load() {
			close(started)
			<-release
		}
		return jwks, nil
	})
	if k, _ := p.resolve("k", ""); k == nil {
		t.Fatal("expected the key")
	}
	slow.Store(true)
	clock.t = clock.t.Add(DefaultJWKSMaxAge) // stale: the next caller refetches, and the fetch hangs
	fetcher := make(chan bool, 1)
	go func() { k, _ := p.resolve("k", ""); fetcher <- k != nil }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the stale set was not refetched")
	}
	holder := make(chan bool, 1)
	go func() { k, _ := p.resolve("k", ""); holder <- k != nil }()
	select {
	case got := <-holder:
		if !got {
			t.Error("the stale key was not used")
		}
	case <-time.After(2 * time.Second):
		t.Error("a caller with a usable stale key waited for another caller's fetch")
	}
	// a caller without the key waits for the fetch in flight, which may bring it
	misser := make(chan bool, 1)
	go func() { k, _ := p.resolve("other", ""); misser <- k != nil }()
	select {
	case <-misser:
		t.Error("a caller without its key did not wait for the fetch in flight")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	if !<-fetcher {
		t.Error("the fetching caller lost its key")
	}
	if <-misser {
		t.Error("an unknown kid resolved")
	}
}

func TestOldKeysAreRefreshedAndKeptWhenTheRefreshFails(t *testing.T) {
	_, oldSet := newTestKey(t, "old")
	_, newSet := newTestKey(t, "new")
	served, fail := oldSet, false
	p, clock := uriProvider(t, func(string) ([]byte, error) {
		if fail {
			return nil, errors.New("issuer down")
		}
		return served, nil
	})
	p.maxAge = 10 * time.Minute
	if k, _ := p.resolve("old", ""); k == nil {
		t.Fatal("expected old key")
	}
	served = newSet
	clock.t = clock.t.Add(10 * time.Minute)
	if k, _ := p.resolve("new", ""); k == nil {
		t.Fatal("expected the rotated key after max age")
	}
	fail = true
	clock.t = clock.t.Add(10 * time.Minute)
	if k, _ := p.resolve("new", ""); k == nil {
		t.Fatal("a failed refresh must keep the keys already held")
	}
	if _, err := p.resolve("unknown", ""); err == nil || !strings.Contains(err.Error(), "issuer down") {
		t.Fatalf("want the fetch error for an unknown kid, got %v", err)
	}
}

func TestFetchedSetKeepsOnlySigningKeys(t *testing.T) {
	// the shared vectors pin this for a static set; a fetched set goes through the same filter
	key, _ := newTestKey(t, "")
	pub, _ := key.PublicKey()
	member, _ := json.Marshal(pub)
	private, _ := json.Marshal(key)
	jwks := fmt.Sprintf(`{"keys":[%s,%s,%s,%s]}`,
		strings.Replace(string(member), "{", `{"kid":"enc","use":"enc",`, 1),
		strings.Replace(string(member), "{", `{"kid":"wrap","key_ops":["wrapKey"],`, 1),
		strings.Replace(string(private), "{", `{"kid":"private",`, 1),
		strings.Replace(string(member), "{", `{"kid":"sig","use":"sig","key_ops":["verify"],`, 1))
	p, _ := uriProvider(t, func(string) ([]byte, error) { return []byte(jwks), nil })
	if k, _ := p.resolve("sig", ""); k == nil {
		t.Fatal("the signing key was dropped")
	}
	for _, kid := range []string{"enc", "wrap", "private"} {
		if k, _ := p.lookup(kid, ""); k != nil {
			t.Errorf("%s: a key that may not verify signatures was kept", kid)
		}
	}
	// the sole usable key answers a token without a kid
	if k, _ := p.lookup("", "ES256"); k == nil {
		t.Error("the sole signing key should match a token without a kid")
	}
}

func TestUnreadableKeysAreLeftOutAndTheRestCount(t *testing.T) {
	// SEMANTICS.md section 3: a JWK the port can't read is left out of the set; it neither fails the whole
	// set nor counts towards "exactly one key"
	key, _ := newTestKey(t, "")
	pub, _ := key.PublicKey()
	member, _ := json.Marshal(pub)
	good := strings.Replace(string(member), "{", `{"kid":"good",`, 1)
	unreadable := []string{
		`{"kty":"foo","kid":"good"}`,            // unknown key type, ahead of the good key with its kid
		`{"kty":"EC","kid":7,"crv":"P-256"}`,    // a kid that isn't a string
		`{"kty":"RSA","kid":"good","n":"AQAB"}`, // RSA without "e"
		`"not a jwk"`, `42`, `null`, `["kty"]`,  // entries that aren't JSON objects
	}
	jwks := fmt.Sprintf(`{"keys":[%s,%s]}`, strings.Join(unreadable, ","), good)
	static, err := newJWKSProvider(json.RawMessage(jwks), "", nil)
	if err != nil {
		t.Fatalf("one unreadable key must not fail the whole set: %v", err)
	}
	fetched, _ := uriProvider(t, func(string) ([]byte, error) { return []byte(jwks), nil })
	for name, p := range map[string]*jwksProvider{"static": static, "fetched": fetched} {
		if k, err := p.resolve("good", "ES256"); k == nil || err != nil {
			t.Errorf("%s: the readable key was dropped (err %v)", name, err)
		}
		if k, _ := p.lookup("", "ES256"); k == nil {
			t.Errorf("%s: the sole readable key should match a token without a kid", name)
		}
	}
	// a document that isn't a key set is still an error
	if _, err := newJWKSProvider(json.RawMessage(`{"keys":"nope"}`), "", nil); err == nil {
		t.Error("a keys member that isn't an array must fail")
	}
}

func TestOversizedJWKSIsRefused(t *testing.T) {
	big, _ := json.Marshal(map[string]any{"keys": []any{}, "padding": strings.Repeat("x", MaxJWKSBytes)})
	p, _ := uriProvider(t, func(string) ([]byte, error) { return big, nil })
	if _, err := p.resolve("any", ""); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("got %v", err)
	}
}

func TestDefaultHTTPGetRefusesErrorsRedirectsAndBigBodies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/500":
			w.WriteHeader(http.StatusInternalServerError)
		case "/redirect":
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		case "/big":
			_, _ = w.Write([]byte(strings.Repeat("x", MaxJWKSBytes+1)))
		}
	}))
	defer srv.Close()
	for _, path := range []string{"/500", "/redirect", "/big"} {
		if _, err := defaultHTTPGet(srv.URL + path); err == nil {
			t.Errorf("%s: expected an error", path)
		}
	}
}

func TestDefaultHTTPPostRefusesErrorsAndRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	for _, path := range []string{"/401", "/redirect"} {
		if _, err := defaultHTTPPost(srv.URL+path, "token=t", map[string]string{"Authorization": "Basic x"}); err == nil {
			t.Errorf("%s: expected an error", path)
		}
	}
}

func TestDefaultHTTPCallsRefuseUserinfoAndOmitTheQuery(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	withUser := strings.Replace(srv.URL, "://", "://alice:s3cret@", 1) + "/jwks"
	_, getErr := defaultHTTPGet(withUser)
	_, postErr := defaultHTTPPost(withUser, "token=t", nil)
	_, statusErr := defaultHTTPGet(srv.URL + "/jwks?key=s3cret")
	for _, err := range []error{getErr, postErr, statusErr} {
		if err == nil || strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "alice") {
			t.Errorf("error = %v", err)
		}
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("server contacted %d times, want 1 (only the URL without userinfo)", n)
	}
}
