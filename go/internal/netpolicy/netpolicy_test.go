package netpolicy

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestNeverProxied(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1": true, "127.8.0.1": true, "::1": true, "localhost": true, "LocalHost.": true,
		"vault.localhost": true, "::ffff:127.0.0.1": true, "0.0.0.0": true, "169.254.169.254": true,
		"fe80::1": true, "fe80::1%en0": true, "fd00:ec2::254": true, "metadata.google.internal": true,
		"metadata":       true,
		"as.example.com": false, "10.0.0.1": false, "8.8.8.8": false, "2001:db8::1": false, "": false,
	}
	for host, want := range cases {
		if got := NeverProxied(host); got != want {
			t.Errorf("NeverProxied(%q) = %v, want %v", host, got, want)
		}
	}
}

// One test sets the environment: http.ProxyFromEnvironment reads it once per process.
func TestProxyOnlyForHTTPSToRemoteHosts(t *testing.T) {
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(name, "http://proxy.example:3128")
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	cases := map[string]bool{
		"https://as.example.com/token":            true,
		"http://vault.example.com/v1/transit/x":   false, // plain http: a vault token in cleartext
		"http://metadata.google.internal/x":       false,
		"https://169.254.169.254/x":               false,
		"https://127.0.0.1:8443/x":                false,
		"https://[fe80::1]/x":                     false,
		"HTTPS://AS.EXAMPLE.COM/token":            true,
		"https://metadata.google.internal./token": false,
	}
	for target, want := range cases {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		proxy, err := Proxy(req)
		if err != nil {
			t.Fatal(err)
		}
		if (proxy != nil) != want {
			t.Errorf("Proxy(%s) = %v, want proxied=%v", target, proxy, want)
		}
	}
	tr, ok := Transport.(*http.Transport)
	if !ok || tr.Proxy == nil {
		t.Fatalf("Transport has no SDK proxy function: %#v", Transport)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://vault.example.com/", nil)
	if p, _ := tr.Proxy(req); p != nil {
		t.Errorf("Transport proxies plain http: %v", p)
	}
	if fresh := newTransport(roundTripperFunc(nil)); fresh.Proxy == nil {
		t.Error("a transport built without an *http.Transport base has no SDK proxy function")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDisplayAndUserinfo(t *testing.T) {
	cases := map[string]string{
		"https://alice:s3cret@as.example.com:8443/token?code=x#f": "https://as.example.com:8443/token",
		"https://alice@as.example.com/token":                      "https://as.example.com/token",
		"http://as.example.com/a%2Fb?q=1":                         "http://as.example.com/a%2Fb",
		"https://as.example.com":                                  "https://as.example.com",
		"://bad":                                                  "(unparseable URL)",
	}
	for in, want := range cases {
		if got := Display(in); got != want {
			t.Errorf("Display(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]bool{
		"https://alice:s3cret@as.example.com/x": true,
		"https://alice@as.example.com":          true,
		"https://as.example.com/x?u=a@b":        false,
		"https://as.example.com/a@b":            false,
		"https://a:b@[::1/x":                    true, // unparseable, still caught
		"https://as.example.com/x":              false,
	} {
		if got := HasUserinfo(in); got != want {
			t.Errorf("HasUserinfo(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestRedactError(t *testing.T) {
	inner := errors.New("dial tcp: refused")
	err := RedactError(&url.Error{Op: "Get", URL: "https://as.example.com/x?client_secret=s3cret", Err: inner})
	var ue *url.Error
	if !errors.As(err, &ue) || !errors.Is(err, inner) {
		t.Fatalf("lost the error's type or cause: %v", err)
	}
	if strings.Contains(err.Error(), "s3cret") || !strings.Contains(err.Error(), "https://as.example.com/x") {
		t.Errorf("RedactError = %q", err)
	}
	if RedactError(inner) != inner || RedactError(nil) != nil {
		t.Error("RedactError changed an error that is not a *url.Error")
	}
}
