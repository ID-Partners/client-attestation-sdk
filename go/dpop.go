package clientattestation

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/id-partners/client-attestation-sdk/go/internal/sdklog"
)

// DpopNonceHeader is the response header a server uses to hand the client a DPoP nonce (RFC 9449 §8).
const DpopNonceHeader = "DPoP-Nonce"

// errUseDpopNonce is the RFC 9449 error code a server returns when it demands a (new) DPoP nonce.
const errUseDpopNonce = "use_dpop_nonce"

// maxNonceChallengeBody caps how much of a 400 body is read to look for error="use_dpop_nonce". A longer
// body is not a nonce challenge.
const maxNonceChallengeBody = 64 * 1024

// maxDpopNonceLength caps a DPoP-Nonce the client remembers or answers. RFC 9449 nonces are short opaque
// strings; a longer value is ignored, as if the response had no DPoP-Nonce.
const maxDpopNonceLength = 1024

// maxDpopNonceOrigins caps how many origins' nonces are remembered. When a new origin would go over it,
// the origin whose nonce was stored longest ago is forgotten (it costs that origin one challenge).
const maxDpopNonceOrigins = 256

// dpopNonceChallenge matches a WWW-Authenticate value carrying a DPoP challenge with error="use_dpop_nonce".
var dpopNonceChallenge = regexp.MustCompile(`(?i)(^|[\s,])DPoP\b.*\berror\s*=\s*"?use_dpop_nonce\b`)

// checkHTU refuses a URL whose part before any query or fragment (the part that becomes htu) contains a
// backslash, ASCII whitespace or a control character. URL parsers disagree on where such a URL goes (some
// read "https://evil.example\@as.example/t" as a request to evil.example), so a proof's htu could name a
// different server from the one the request reaches.
func checkHTU(target string) error {
	for i := 0; i < len(target) && target[i] != '?' && target[i] != '#'; i++ {
		if c := target[i]; c <= ' ' || c == 0x7f || c == '\\' {
			return errors.New("uri (htu) must not contain a backslash, whitespace or control character")
		}
	}
	return nil
}

// The messages a URL with no htu is refused with; every port uses the same ones (vectors/htu.json).
const (
	errHTUNotAbsolute = "uri (htu) must be an absolute http or https URL with a host"
	errHTUHost        = "uri (htu) has an invalid host"
	errHTUPort        = "uri (htu) has an invalid port"
	errHTUPath        = "uri (htu) has an invalid path"
)

// htuDefaultPorts are the schemes an htu may have, with their default ports.
var htuDefaultPorts = map[string]string{"http": "80", "https": "443"}

// htuParts splits a request URL into the origin and path of its htu, by the rule in vectors/README.md that
// every port applies alike: an absolute http(s) URL with a host; scheme and host lower-cased (ASCII only,
// an IPv6 literal as written); no userinfo; the port as a plain number and dropped when it is the
// scheme's default; the path as written with non-ASCII characters percent-encoded (UTF-8);
// no query or fragment. Anything else is an error.
func htuParts(target string) (origin, path string, err error) {
	if err := checkHTU(target); err != nil {
		return "", "", err
	}
	bare := target
	if i := strings.IndexAny(bare, "?#"); i >= 0 {
		bare = bare[:i]
	}
	scheme, rest, ok := strings.Cut(bare, "://")
	scheme = strings.ToLower(scheme)
	if _, known := htuDefaultPorts[scheme]; !ok || !known {
		return "", "", errors.New(errHTUNotAbsolute)
	}
	authority := rest
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		authority, path = rest[:i], rest[i:]
	}
	hostport := authority[strings.LastIndexByte(authority, '@')+1:]
	var host, port string
	if strings.HasPrefix(hostport, "[") {
		literal, after, closed := strings.Cut(hostport[1:], "]")
		if !closed || !strings.Contains(literal, ":") || !onlyBytes(literal, isIPv6Byte) ||
			(after != "" && after[0] != ':') {
			return "", "", errors.New(errHTUHost)
		}
		host = "[" + strings.ToLower(literal) + "]"
		if after != "" {
			port = after[1:]
		}
	} else {
		host, port, _ = strings.Cut(hostport, ":")
		if host == "" {
			return "", "", errors.New(errHTUNotAbsolute)
		}
		if !onlyBytes(host, isHostByte) {
			return "", "", errors.New(errHTUHost)
		}
		host = strings.ToLower(host)
	}
	if port != "" {
		digits := strings.TrimLeft(port, "0")
		if !onlyBytes(port, isDigitByte) || len(digits) > 5 {
			return "", "", errors.New(errHTUPort)
		}
		n, _ := strconv.Atoi("0" + digits)
		if n > 65535 {
			return "", "", errors.New(errHTUPort)
		}
		if strconv.Itoa(n) != htuDefaultPorts[scheme] {
			host += ":" + strconv.Itoa(n)
		}
	}
	if path, err = encodeHTUPath(path); err != nil {
		return "", "", err
	}
	return scheme + "://" + host, path, nil
}

// encodeHTUPath percent-encodes (as UTF-8, upper-case hex) every non-ASCII character of path and keeps
// every ASCII character as written, "%XX" escapes, a lone "%" and characters outside RFC 3986 pchar
// included: those are what the HTTP client sends, and a server compares htu after RFC 3986 section 6.2.2
// normalisation, which decodes only unreserved characters. (checkHTU has already refused controls,
// whitespace and backslash.) A path that is not valid UTF-8 is refused.
func encodeHTUPath(path string) (string, error) {
	if !utf8.ValidString(path) {
		return "", errors.New(errHTUPath)
	}
	var out strings.Builder
	for i := 0; i < len(path); i++ {
		if c := path[i]; c < utf8.RuneSelf {
			out.WriteByte(c)
		} else {
			fmt.Fprintf(&out, "%%%02X", c)
		}
	}
	return out.String(), nil
}

func onlyBytes(s string, ok func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if !ok(s[i]) {
			return false
		}
	}
	return true
}

func isDigitByte(c byte) bool { return '0' <= c && c <= '9' }

func isHexByte(c byte) bool {
	return isDigitByte(c) || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

func isIPv6Byte(c byte) bool { return isHexByte(c) || c == ':' || c == '.' }

// isHostByte reports whether c is an RFC 3986 unreserved character, the only ones a host name may have.
func isHostByte(c byte) bool {
	return isDigitByte(c) || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || strings.IndexByte("-._~", c) >= 0
}

// normalizeHTU returns the "htu" form of a request URL (RFC 9449 §4.2): the origin and path htuParts
// gives. A bare origin gets no trailing "/".
func normalizeHTU(target string) (string, error) {
	origin, path, err := htuParts(target)
	if err != nil {
		return "", err
	}
	return origin + path, nil
}

// accessTokenHash is the DPoP "ath" claim: base64url(SHA-256(ASCII access token)) (RFC 9449 §4.2).
func accessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// originOf is the nonce-cache key for a URL: the origin part of htuParts (scheme://host[:port]). A URL
// htuParts refuses is its own key.
func originOf(target string) string {
	origin, _, err := htuParts(target)
	if err != nil {
		return target
	}
	return origin
}

// nonceChallenge reports the server's DPoP nonce when a response is a use_dpop_nonce challenge: a 401
// whose WWW-Authenticate carries the DPoP scheme with error="use_dpop_nonce", or a 400 whose JSON body
// has error "use_dpop_nonce" — in both cases together with a DPoP-Nonce header of at most
// maxDpopNonceLength bytes.
func nonceChallenge(status int, header http.Header, body []byte) (string, bool) {
	nonce := header.Get(DpopNonceHeader)
	if nonce == "" || len(nonce) > maxDpopNonceLength {
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

// rememberedNonce is an origin's last DPoP nonce and when it was stored (an increasing sequence number).
type rememberedNonce struct {
	value string
	seq   uint64
}

// rememberNonce records the latest DPoP nonce an origin handed out. An empty nonce, or one longer than
// maxDpopNonceLength, is ignored. At most maxDpopNonceOrigins origins are kept: a new origin over the cap
// replaces the one stored longest ago.
func (c *ClientAttestation) rememberNonce(target, nonce string) {
	if nonce == "" || len(nonce) > maxDpopNonceLength {
		return
	}
	key := originOf(target)
	c.nonceMu.Lock()
	defer c.nonceMu.Unlock()
	if c.nonces == nil {
		c.nonces = map[string]rememberedNonce{}
	}
	if _, known := c.nonces[key]; !known && len(c.nonces) >= maxDpopNonceOrigins {
		oldest, oldestSeq := "", uint64(0)
		for k, v := range c.nonces {
			if oldest == "" || v.seq < oldestSeq {
				oldest, oldestSeq = k, v.seq
			}
		}
		delete(c.nonces, oldest)
	}
	c.nonceSeq++
	c.nonces[key] = rememberedNonce{value: nonce, seq: c.nonceSeq}
}

// nonceFor returns the last DPoP nonce the target's origin handed out, or "".
func (c *ClientAttestation) nonceFor(target string) string {
	c.nonceMu.Lock()
	defer c.nonceMu.Unlock()
	return c.nonces[originOf(target)].value
}

// authRoundTripper attaches the access token (Bearer, or DPoP plus a fresh proof) to every request and,
// for DPoP-bound tokens, retries once on a use_dpop_nonce challenge. It never attaches credentials to a
// request an http.Client built to follow a redirect: the hop fails instead.
type authRoundTripper struct {
	source *ClientAttestation
	base   http.RoundTripper
}

func (rt *authRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	base := rt.base
	if base == nil {
		base = http.DefaultTransport
	}
	// http.Client calls RoundTrip again for every redirect hop it follows, with req.Response set to the
	// 3xx that caused it. Re-attaching here would send the token to wherever Location points, scheme and
	// host included, so refuse the hop without contacting the target. This is the same error the SDK's own
	// requests return for a redirect, so transportReason classifies it as "redirect".
	if req.Response != nil {
		closeBody(req)
		return nil, refuseRedirect(req, nil)
	}
	target := req.URL.String()
	headers, dpop, err := rt.source.requestHeaders(req.Context(), req.Method, target, nil)
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
		if peeked = peekBody(resp); len(peeked) > maxNonceChallengeBody {
			peeked = nil
		}
	}
	challengeNonce, challenged := nonceChallenge(resp.StatusCode, resp.Header, peeked)
	if !challenged {
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
	// Answer this challenge with its own nonce, not whatever a concurrent response left for the origin.
	headers, _, err = rt.source.requestHeaders(req.Context(), req.Method, target, &challengeNonce)
	if err != nil {
		return resp, nil
	}
	rt.source.log(req.Context(), slog.LevelInfo, "dpop.nonce_retry",
		"host", sdklog.Host(target), "status", resp.StatusCode, "at", "resource")
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxNonceChallengeBody+1))
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

// peekBody reads up to maxNonceChallengeBody+1 bytes of resp.Body (so a longer body shows as one) and
// puts them back in front of the rest, so the caller still sees the whole body.
func peekBody(resp *http.Response) []byte {
	if resp.Body == nil {
		return nil
	}
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, maxNonceChallengeBody+1))
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(buf), resp.Body), resp.Body}
	return buf
}
