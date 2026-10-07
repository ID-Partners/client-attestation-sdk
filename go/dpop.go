package clientattestation

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/id-partners/client-attestation-sdk/go/internal/sdklog"
)

// DpopNonceHeader is the response header a server uses to hand the client a DPoP nonce (RFC 9449 §8).
const DpopNonceHeader = "DPoP-Nonce"

// errUseDpopNonce is the RFC 9449 error code a server returns when it demands a (new) DPoP nonce.
const errUseDpopNonce = "use_dpop_nonce"

// maxNonceChallengeBody caps how much of a 400 body is read to look for error="use_dpop_nonce".
const maxNonceChallengeBody = 64 * 1024

// dpopNonceChallenge matches a WWW-Authenticate value carrying a DPoP challenge with error="use_dpop_nonce".
var dpopNonceChallenge = regexp.MustCompile(`(?i)(^|[\s,])DPoP\b.*\berror\s*=\s*"?use_dpop_nonce\b`)

// normalizeHTU returns the "htu" form of a request URL per RFC 9449 §4.2: the URL without its query and
// fragment, with the scheme and host lower-cased and a default port (443 for https, 80 for http)
// dropped. A bare origin gets no trailing "/". A value that does not parse as an absolute URL is only
// stripped of anything from the first '?' or '#'.
func normalizeHTU(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		if i := strings.IndexAny(target, "?#"); i >= 0 {
			return target[:i]
		}
		return target
	}
	return normalizedOrigin(u) + u.EscapedPath()
}

// normalizedOrigin is scheme://host[:port], lower-cased, without a default port.
func normalizedOrigin(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]" // IPv6 literal
	}
	if port := u.Port(); port != "" && !(scheme == "https" && port == "443") && !(scheme == "http" && port == "80") {
		host += ":" + port
	}
	return scheme + "://" + host
}

// accessTokenHash is the DPoP "ath" claim: base64url(SHA-256(ASCII access token)) (RFC 9449 §4.2).
func accessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// originOf is the nonce-cache key for a URL: lower-cased scheme://host[:port], default port dropped.
func originOf(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	return normalizedOrigin(u)
}

// nonceChallenge reports the server's DPoP nonce when a response is a use_dpop_nonce challenge: a 401
// whose WWW-Authenticate carries the DPoP scheme with error="use_dpop_nonce", or a 400 whose JSON body
// has error "use_dpop_nonce" — in both cases together with a DPoP-Nonce header.
func nonceChallenge(status int, header http.Header, body []byte) (string, bool) {
	nonce := header.Get(DpopNonceHeader)
	if nonce == "" {
		return "", false
	}
	switch status {
	case http.StatusUnauthorized:
		for _, v := range header.Values("WWW-Authenticate") {
			if dpopNonceChallenge.MatchString(v) {
				return nonce, true
			}
		}
	case http.StatusBadRequest:
		var parsed struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &parsed) == nil && parsed.Error == errUseDpopNonce {
			return nonce, true
		}
	}
	return "", false
}

// rememberNonce records the latest DPoP nonce an origin handed out.
func (c *ClientAttestation) rememberNonce(target, nonce string) {
	if nonce == "" {
		return
	}
	c.nonceMu.Lock()
	defer c.nonceMu.Unlock()
	if c.nonces == nil {
		c.nonces = map[string]string{}
	}
	c.nonces[originOf(target)] = nonce
}

// nonceFor returns the last DPoP nonce the target's origin handed out, or "".
func (c *ClientAttestation) nonceFor(target string) string {
	c.nonceMu.Lock()
	defer c.nonceMu.Unlock()
	return c.nonces[originOf(target)]
}

// authRoundTripper attaches the access token (Bearer, or DPoP plus a fresh proof) to every request and,
// for DPoP-bound tokens, retries once on a use_dpop_nonce challenge.
type authRoundTripper struct {
	source *ClientAttestation
	base   http.RoundTripper
}

func (rt *authRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	base := rt.base
	if base == nil {
		base = http.DefaultTransport
	}
	target := req.URL.String()
	headers, dpop, err := rt.source.requestHeaders(req.Context(), req.Method, target)
	if err != nil {
		closeBody(req)
		return nil, err
	}
	first := req.Clone(req.Context())
	applyHeaders(first, headers)
	resp, err := base.RoundTrip(first)
	if err != nil || !dpop {
		return resp, err
	}

	// A server may hand out a fresh nonce on any response; keep the latest for the origin.
	nonce := resp.Header.Get(DpopNonceHeader)
	if nonce == "" {
		return resp, nil
	}
	rt.source.rememberNonce(target, nonce)
	var peeked []byte
	if resp.StatusCode == http.StatusBadRequest {
		peeked = peekBody(resp)
	}
	if _, challenged := nonceChallenge(resp.StatusCode, resp.Header, peeked); !challenged {
		return resp, nil
	}

	retry := req.Clone(req.Context())
	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody == nil {
			return resp, nil // the body cannot be replayed: hand back the challenge
		}
		body, err := req.GetBody()
		if err != nil {
			return resp, nil
		}
		retry.Body = body
	}
	headers, _, err = rt.source.requestHeaders(req.Context(), req.Method, target)
	if err != nil {
		return resp, nil
	}
	rt.source.log(req.Context(), slog.LevelInfo, "dpop.nonce_retry",
		"host", sdklog.Host(target), "status", resp.StatusCode, "at", "resource")
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxNonceChallengeBody))
	_ = resp.Body.Close()
	applyHeaders(retry, headers)
	return base.RoundTrip(retry)
}

func applyHeaders(req *http.Request, headers map[string]string) {
	for k, v := range headers {
		req.Header.Set(k, v)
	}
}

func closeBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}

// peekBody reads up to maxNonceChallengeBody bytes of resp.Body and puts them back in front of the rest,
// so the caller still sees the whole body.
func peekBody(resp *http.Response) []byte {
	if resp.Body == nil {
		return nil
	}
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, maxNonceChallengeBody))
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(buf), resp.Body), resp.Body}
	return buf
}
