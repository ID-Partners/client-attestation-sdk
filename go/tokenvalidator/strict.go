package tokenvalidator

// The strict parsing every port applies to a token before trusting any of it (validation/SEMANTICS.md):
// compact serialisation, strict JSON objects, NumericDates and claim types. Errors are generic and never
// quote token bytes.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxJSONDepth is the deepest object/array nesting a header, payload or introspection response may have.
const MaxJSONDepth = 64

const maxSafeInteger = 1<<53 - 1

var errMalformedToken = errors.New("malformed token")

type compactParts struct {
	header       map[string]any
	signingInput []byte
	payload      []byte
	signature    []byte
}

func decodeSegment(segment string) ([]byte, error) {
	if len(segment)%4 == 1 {
		return nil, errMalformedToken
	}
	for i := 0; i < len(segment); i++ {
		c := segment[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return nil, errMalformedToken
		}
	}
	// Strict: non-zero padding bits are not the canonical encoding
	return base64.RawURLEncoding.Strict().DecodeString(segment)
}

// splitCompact returns the header object, signing input, undecoded payload and signature of a compact JWS.
// The payload is only parsed once the signature over it verifies.
func splitCompact(token string) (*compactParts, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errMalformedToken
	}
	decoded := make([][]byte, 3)
	for i, p := range parts {
		b, err := decodeSegment(p)
		if err != nil {
			return nil, errMalformedToken
		}
		decoded[i] = b
	}
	header, err := parseObject(decoded[0], "header")
	if err != nil {
		return nil, err
	}
	if _, ok := header["crit"]; ok {
		// we implement no JWS extension, so RFC 7515 section 4.1.11 says reject any crit
		return nil, errors.New("header has crit")
	}
	return &compactParts{
		header:       header,
		signingInput: []byte(parts[0] + "." + parts[1]),
		payload:      decoded[1],
		signature:    decoded[2],
	}, nil
}

// parseObject parses data as a strict RFC 8259 JSON object: UTF-8 without a BOM, no duplicate member names
// at any depth, at most MaxJSONDepth levels deep, nothing after it. Numbers become float64 (one too large
// for a float64 becomes ±Inf, as in the other ports).
func parseObject(data []byte, what string) (map[string]any, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%s is not UTF-8", what)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("%s is not JSON", what)
	}
	if tok != json.Delim('{') {
		// still has to be JSON, so the caller's error is the same whatever the non-object is
		return nil, fmt.Errorf("%s is not a JSON object", what)
	}
	obj, err := readObject(dec, 1)
	if err != nil {
		return nil, fmt.Errorf("%s is not a strict JSON object (%w)", what, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%s has data after the JSON object", what)
	}
	return obj, nil
}

var (
	errDuplicateName = errors.New("duplicate member name")
	errTooDeep       = errors.New("nested too deeply")
)

// readObject reads an object's members after its opening brace.
func readObject(dec *json.Decoder, depth int) (map[string]any, error) {
	if depth > MaxJSONDepth {
		return nil, errTooDeep
	}
	out := map[string]any{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if tok == json.Delim('}') {
			return out, nil
		}
		name := tok.(string) // the decoder only yields a string or '}' here
		if _, dup := out[name]; dup {
			return nil, errDuplicateName
		}
		value, err := readValue(dec, depth)
		if err != nil {
			return nil, err
		}
		out[name] = value
	}
}

// readArray reads an array's elements after its opening bracket.
func readArray(dec *json.Decoder, depth int) ([]any, error) {
	if depth > MaxJSONDepth {
		return nil, errTooDeep
	}
	out := []any{}
	for {
		if !dec.More() {
			if _, err := dec.Token(); err != nil { // the closing bracket
				return nil, err
			}
			return out, nil
		}
		value, err := readValue(dec, depth)
		if err != nil {
			return nil, err
		}
		out = append(out, value)
	}
}

func readValue(dec *json.Decoder, depth int) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim: // the decoder only yields an opening one where a value starts
		if t == '{' {
			return readObject(dec, depth+1)
		}
		return readArray(dec, depth+1)
	case json.Number:
		// the decoder has checked the syntax, so the only error is ErrRange: then f is ±Inf (or 0 for an
		// underflow), as a float64 reader gives in the other ports
		f, _ := strconv.ParseFloat(string(t), 64)
		return f, nil
	default:
		return t, nil // string, bool or nil
	}
}

// numericDate reads a NumericDate claim (fractions truncate toward zero). ok is false when the claim is
// absent or null; anything but a finite JSON number within ±(2^53 − 1) is an error.
func numericDate(claims map[string]any, key string) (value int64, ok bool, err error) {
	raw, present := claims[key]
	if !present || raw == nil {
		return 0, false, nil
	}
	f, isNumber := raw.(float64)
	if !isNumber || math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, false, fmt.Errorf("%s is not a NumericDate", key)
	}
	if math.Abs(f) > maxSafeInteger {
		return 0, false, fmt.Errorf("%s is out of range", key)
	}
	return int64(f), true, nil
}

func stringArray(v any) ([]string, bool) {
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// audienceOf reads "aud": absent or null is empty, a string is one entry, an array must hold only strings.
func audienceOf(claims map[string]any) ([]string, error) {
	switch a := claims["aud"].(type) {
	case nil:
		return nil, nil
	case string:
		return []string{a}, nil
	}
	if out, ok := stringArray(claims["aud"]); ok {
		return out, nil
	}
	return nil, errors.New("aud is not a string or an array of strings")
}

// splitScopes splits on U+0020 only, as RFC 6749 section 3.3 says; runs of spaces make no empty scopes.
func splitScopes(text string) []string {
	out := []string{}
	for _, s := range strings.Split(text, " ") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// scopesOf reads the granted scopes: from "scope" (a space-delimited string) when present, else "scp" (a
// space-delimited string, as Microsoft Entra ID issues it, or an array of strings). Either one present with
// any other shape is an error.
func scopesOf(claims map[string]any) ([]string, error) {
	scope, hasScope := claims["scope"]
	scp, hasScp := claims["scp"]
	hasScope = hasScope && scope != nil
	hasScp = hasScp && scp != nil
	scopeText, scopeOK := scope.(string)
	if hasScope && !scopeOK {
		return nil, errors.New("scope is not a string")
	}
	scpText, scpIsString := scp.(string)
	scpList, scpIsList := stringArray(scp)
	if hasScp && !scpIsString && !scpIsList {
		return nil, errors.New("scp is not a string or an array of strings")
	}
	if hasScope {
		return splitScopes(scopeText), nil
	}
	if scpIsString {
		return splitScopes(scpText), nil
	}
	return scpList, nil
}

// checkSubject refuses a "sub" that is present, not null and not a string.
func checkSubject(claims map[string]any) error {
	if sub, ok := claims["sub"]; ok && sub != nil {
		if _, isString := sub.(string); !isString {
			return errors.New("sub is not a string")
		}
	}
	return nil
}

// isForbiddenAlgorithm reports whether alg is refused whatever AcceptedAlgorithms says: "none" (in any
// case), because an unsigned token proves nothing, and the HMAC algorithms, because an HMAC "signature"
// checked against an issuer's public key is forgeable by anyone who has that key.
func isForbiddenAlgorithm(alg string) bool {
	lowered := strings.ToLower(alg)
	return lowered == "none" || strings.HasPrefix(lowered, "hs")
}
