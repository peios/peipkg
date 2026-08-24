// Package jsonguard enforces the §5.9 parser-hardening rules on the JSON
// documents §5 defines: the manifest, the files manifest, the signature
// envelope, the repository descriptor, and both indexes.
//
// Go's encoding/json satisfies none of the three rules this package
// implements. It takes duplicate keys last-wins silently, it allows
// nesting far past the specified cap, and it replaces an unpaired
// surrogate escape with U+FFFD rather than rejecting it. Each has to be
// added deliberately, and none can be expressed as a struct tag: they
// are properties of the token stream, not of the target type. So a
// document is checked here first and unmarshalled afterwards.
package jsonguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// MaxDepth is the §5.A nesting-depth cap. A document whose objects and
// arrays nest more deeply than this is rejected.
//
// Depth counts containers: a top-level object sits at depth 1.
const MaxDepth = 64

// Check reports whether data satisfies the §5.9 hardening rules. It
// returns nil for a document that does, and an error naming the specific
// violation for one that does not.
//
// Check does not validate the document against any schema; it is a
// precondition for unmarshalling, not a replacement for it.
func Check(data []byte) error {
	if err := checkStructure(data); err != nil {
		return err
	}
	// checkStructure has established that data is well-formed JSON, so
	// the escape scan can identify string literals by quote-tracking
	// alone.
	return checkEscapes(data)
}

// Unmarshal checks data against the §5.9 rules and then unmarshals it
// into v, ignoring unknown fields per §5.9's forward-compatibility rule.
func Unmarshal(data []byte, v any) error {
	if err := Check(data); err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// UnmarshalStrict is [Unmarshal] for the signature envelope (§5.28),
// the one document §5.9 exempts from unknown-field tolerance: an
// unrecognised field is an error rather than something to ignore.
func UnmarshalStrict(data []byte, v any) error {
	if err := Check(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	// Reject trailing content: a second document after the first would
	// otherwise be silently ignored.
	if dec.More() {
		return fmt.Errorf("peipkg/jsonguard: trailing data after the JSON document")
	}
	return nil
}

// frame is one open container in the token walk.
type frame struct {
	object bool
	// keys are the member names already seen in this object, for the
	// duplicate-key rule. Nil for an array.
	keys map[string]struct{}
	// wantKey is true when the next scalar token in an object is a
	// member name rather than a value.
	wantKey bool
}

// checkStructure walks the token stream, enforcing the duplicate-key and
// nesting-depth rules. Walking tokens rather than unmarshalling is what
// makes duplicate keys visible at all: by the time a document has been
// decoded into a struct or a map, the losing member is gone.
func checkStructure(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var stack []*frame
	sawToken := false

	// consumeValue records that a value slot has been filled, so that an
	// enclosing object expects a member name next.
	consumeValue := func() {
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].wantKey = true
		}
	}

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("peipkg/jsonguard: invalid JSON: %w", err)
		}
		sawToken = true

		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{', '[':
				consumeValue()
				if len(stack)+1 > MaxDepth {
					return fmt.Errorf(
						"peipkg/jsonguard: nesting deeper than the %d-level limit", MaxDepth)
				}
				f := &frame{object: delim == '{'}
				if f.object {
					f.keys = make(map[string]struct{})
					f.wantKey = true
				}
				stack = append(stack, f)
			case '}', ']':
				if len(stack) == 0 {
					return fmt.Errorf("peipkg/jsonguard: unbalanced %q", delim)
				}
				stack = stack[:len(stack)-1]
			}
			continue
		}

		// A scalar. Inside an object it is either a member name or a
		// value, and the two alternate.
		if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].wantKey {
			name, ok := tok.(string)
			if !ok {
				// Unreachable for well-formed JSON; the decoder rejects
				// a non-string member name before it reaches here.
				return fmt.Errorf("peipkg/jsonguard: object member name is not a string")
			}
			if _, dup := stack[n-1].keys[name]; dup {
				return fmt.Errorf("peipkg/jsonguard: duplicate object member %q", name)
			}
			stack[n-1].keys[name] = struct{}{}
			stack[n-1].wantKey = false
			continue
		}
		consumeValue()
	}

	// Token reports io.EOF for a document that simply stops — an empty
	// input, or a container left open — rather than an error, so both
	// have to be caught here.
	if !sawToken {
		return fmt.Errorf("peipkg/jsonguard: empty document")
	}
	if len(stack) != 0 {
		return fmt.Errorf("peipkg/jsonguard: %d unterminated container(s)", len(stack))
	}
	return nil
}

// checkEscapes rejects a \u escape that does not resolve to a valid code
// point (§5.9, RFC 8259 §7) — in practice an unpaired surrogate.
//
// encoding/json substitutes U+FFFD for one instead of failing, which
// turns a machine-resolvable field into a different string than the
// producer wrote while every signature over the bytes still verifies.
func checkEscapes(data []byte) error {
	inString := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			if i+1 >= len(data) {
				return fmt.Errorf("peipkg/jsonguard: truncated escape sequence")
			}
			if data[i+1] != 'u' {
				i++ // an ordinary two-character escape
				continue
			}
			r, ok := hex4(data, i+2)
			if !ok {
				return fmt.Errorf("peipkg/jsonguard: malformed \\u escape")
			}
			switch {
			case isHighSurrogate(r):
				lo, ok := hex4(data, i+8)
				if i+7 >= len(data) || data[i+6] != '\\' || data[i+7] != 'u' ||
					!ok || !isLowSurrogate(lo) {
					return fmt.Errorf(
						"peipkg/jsonguard: high surrogate \\u%04X is not followed by a low surrogate", r)
				}
				i += 11
			case isLowSurrogate(r):
				return fmt.Errorf(
					"peipkg/jsonguard: low surrogate \\u%04X is not preceded by a high surrogate", r)
			default:
				i += 5
			}
		}
	}
	return nil
}

// hex4 reads the four hex digits of a \u escape starting at off.
func hex4(data []byte, off int) (rune, bool) {
	if off+4 > len(data) {
		return 0, false
	}
	var r rune
	for _, c := range data[off : off+4] {
		var v rune
		switch {
		case c >= '0' && c <= '9':
			v = rune(c - '0')
		case c >= 'a' && c <= 'f':
			v = rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v = rune(c-'A') + 10
		default:
			return 0, false
		}
		r = r<<4 | v
	}
	return r, true
}

func isHighSurrogate(r rune) bool { return r >= 0xD800 && r <= 0xDBFF }
func isLowSurrogate(r rune) bool  { return r >= 0xDC00 && r <= 0xDFFF }
