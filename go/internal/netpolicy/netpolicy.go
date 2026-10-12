// Package netpolicy holds the rules every SDK HTTP client shares, in every port: which requests may go
// through a proxy from the environment, and how a URL is shown in an error.
//
// Proxy policy: a request goes through a proxy only when it is https to a host that is not loopback,
// link-local or a cloud metadata server, and the environment names one (HTTPS_PROXY, honouring NO_PROXY).
// It then goes through a CONNECT tunnel, so TLS stays end to end. Plain http never goes through a proxy:
// an OpenBao X-Vault-Token or a metadata identity token would cross it in cleartext.
package netpolicy

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// metadataHosts are cloud metadata servers that aren't link-local addresses (169.254.169.254 is caught as
// link-local).
var metadataHosts = map[string]bool{"metadata.google.internal": true, "metadata": true, "fd00:ec2::254": true}

// NeverProxied reports whether host is loopback, link-local or a cloud metadata server: the SDK sends
// those hosts tokens it must not route anywhere else.
func NeverProxied(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || metadataHosts[host] {
		return true
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// Proxy is the http.Transport Proxy function for SDK clients: http.ProxyFromEnvironment, but only for
// https to a host NeverProxied allows.
func Proxy(req *http.Request) (*url.URL, error) {
	if !strings.EqualFold(req.URL.Scheme, "https") || NeverProxied(req.URL.Hostname()) {
		return nil, nil
	}
	return http.ProxyFromEnvironment(req)
}

// Transport is the RoundTripper SDK clients use when the caller didn't supply one: http.DefaultTransport's
// settings with the SDK's Proxy.
var Transport http.RoundTripper = newTransport(http.DefaultTransport)

func newTransport(base http.RoundTripper) *http.Transport {
	if t, ok := base.(*http.Transport); ok {
		t = t.Clone()
		t.Proxy = Proxy
		return t
	}
	return &http.Transport{
		Proxy:                 Proxy,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// ErrUserinfo is returned for a URL that carries userinfo (user:password@). Credentials belong in a
// header; in a URL they end up in logs, errors and, through a proxy, a CONNECT line.
var ErrUserinfo = errors.New("URLs with userinfo (user:password@) are not supported")

// HasUserinfo reports whether target carries userinfo.
func HasUserinfo(target string) bool {
	u, err := url.Parse(target)
	if err != nil {
		// unparseable: look at the authority by hand, so a malformed URL can't slip through
		rest := target
		if i := strings.Index(rest, "://"); i >= 0 {
			rest = rest[i+3:]
		}
		if i := strings.IndexAny(rest, "/?#"); i >= 0 {
			rest = rest[:i]
		}
		return strings.Contains(rest, "@")
	}
	return u.User != nil
}

// Display is target without its userinfo, query or fragment, for error messages: a query can carry a
// secret, and userinfo is one.
func Display(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return "(unparseable URL)"
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path, RawPath: u.RawPath}).String()
}

// RedactError rewrites the URL a *url.Error carries with Display, in place, so err keeps its type for
// errors.As and Timeout checks. Other errors are returned unchanged.
func RedactError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		ue.URL = Display(ue.URL)
	}
	return err
}
