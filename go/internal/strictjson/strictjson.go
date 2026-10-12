// Package strictjson is the strict reading every port applies to a token before trusting any of it
// (validation/SEMANTICS.md): canonical base64url segments and strict RFC 8259 JSON objects. The token
// validator and the client's JWT-SVID check share it, so they agree on what is JSON. Errors are generic and
// never quote the input.
package strictjson

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

// MaxDepth is the deepest object/array nesting a header, payload or introspection response may have.
const MaxDepth = 64

// ErrMalformed is the error for a segment that is not canonical base64url.
var ErrMalformed = errors.New("malformed token")

// DecodeSegment decodes one segment of a compact JWS: unpadded base64url in its canonical form (no
// non-zero padding bits). Any other input is ErrMalformed.
func DecodeSegment(segment string) ([]byte, error) {
	if len(segment)%4 == 1 {
		return nil, ErrMalformed
	}
	for i := 0; i < len(segment); i++ {
		c := segment[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return nil, ErrMalformed
		}
	}
	// Strict: non-zero padding bits are not the canonical encoding
	return base64.RawURLEncoding.Strict().DecodeString(segment)
}

// ParseObject parses data as a strict RFC 8259 JSON object: UTF-8 without a BOM, no duplicate member names
// at any depth, at most MaxDepth levels deep, nothing after it. Numbers become float64 (one too large
// for a float64 becomes ±Inf, as in the other ports).
func ParseObject(data []byte, what string) (map[string]any, error) {
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
	if depth > MaxDepth {
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
	if depth > MaxDepth {
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
