package tokenvalidator

import (
	"encoding/json"
	"errors"
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

func uriProvider(t *testing.T, get httpGetFunc) (*jwksProvider, *fakeClock) {
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
