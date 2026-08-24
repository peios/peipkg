package jsonguard_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/jsonguard"
)

// PSPU §5.9: "Duplicate keys in any object MUST cause the document to be
// rejected. A parser that silently takes first-wins or last-wins is not
// conformant."
//
// This is the load-bearing rule of the hardening list. Go's
// encoding/json takes last-wins, so a document reads one way to a
// scanner, an auditor or a third-party validator and another way to
// peipkg — while every signature over the bytes still verifies.
func TestDuplicateKeysAreRejected(t *testing.T) {
	cases := map[string]string{
		"top level":            `{"name":"nginx","name":"evil"}`,
		"three occurrences":    `{"a":1,"a":2,"a":3}`,
		"separated by others":  `{"name":"nginx","version":"1.0-1","name":"evil"}`,
		"nested object":        `{"build":{"farm_id":"a","farm_id":"b"}}`,
		"inside an array":      `[{"a":1},{"b":2,"b":3}]`,
		"deeply nested":        `{"a":{"b":{"c":{"d":1,"d":2}}}}`,
		"differing values":     `{"size_installed":0,"size_installed":999999}`,
		"empty-string key":     `{"":1,"":2}`,
		"key needing escapes":  `{"a\nb":1,"a\nb":2}`,
		"escaped vs literal":   `{"ab":1,"\u0061b":2}`,
		"duplicate after list": `{"deps":[1,2,3],"deps":[]}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := jsonguard.Check([]byte(doc)); err == nil {
				t.Errorf("Check(%s) = nil, want a duplicate-key rejection", doc)
			}
		})
	}
}

// Distinct keys must not be mistaken for duplicates — including the
// cases where a naive implementation loses track of which tokens are
// member names.
func TestDistinctKeysAreAccepted(t *testing.T) {
	cases := map[string]string{
		"plain object":                `{"a":1,"b":2}`,
		"same name in sibling objs":   `{"x":{"n":1},"y":{"n":2}}`,
		"same name at two depths":     `{"n":1,"c":{"n":2}}`,
		"array of like objects":       `[{"n":1},{"n":2},{"n":3}]`,
		"string values equal to keys": `{"a":"b","b":"a"}`,
		"value that looks like a key": `{"a":"a"}`,
		"nested arrays and objects":   `{"a":[{"b":[{"c":1}]}],"d":2}`,
		"empty object":                `{}`,
		"empty array":                 `[]`,
		"scalar document":             `42`,
		"null value":                  `{"a":null,"b":null}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := jsonguard.Check([]byte(doc)); err != nil {
				t.Errorf("Check(%s) = %v, want nil", doc, err)
			}
		})
	}
}

// §5.A caps JSON nesting depth at 64. Go's encoding/json has an internal
// limit of 10,000, so the practical ceiling was roughly 156x the
// specified one — and it is reachable inside a field the parser is
// *required* to ignore, so a manifest can carry it and still decode.
func TestNestingDepthIsCappedAt64(t *testing.T) {
	nest := func(depth int, open, close string) string {
		return strings.Repeat(open, depth) + strings.Repeat(close, depth)
	}
	for _, tc := range []struct {
		name  string
		doc   string
		valid bool
	}{
		{"63 arrays", nest(63, "[", "]"), true},
		{"64 arrays", nest(64, "[", "]"), true},
		{"65 arrays", nest(65, "[", "]"), false},
		{"5000 arrays", nest(5000, "[", "]"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := jsonguard.Check([]byte(tc.doc))
			if tc.valid && err != nil {
				t.Errorf("Check: got %v, want nil", err)
			}
			if !tc.valid && err == nil {
				t.Errorf("Check: got nil, want a depth rejection")
			}
		})
	}
}

// Depth must be counted through objects and mixed containers too, and
// must be measured as maximum depth rather than total container count —
// a wide document is not a deep one.
func TestDepthCountsContainersNotSiblings(t *testing.T) {
	// 64 nested objects, each wrapping the next under key "a".
	deep := strings.Repeat(`{"a":`, 64) + "1" + strings.Repeat("}", 64)
	if err := jsonguard.Check([]byte(deep)); err != nil {
		t.Errorf("64 nested objects: got %v, want nil", err)
	}
	tooDeep := strings.Repeat(`{"a":`, 65) + "1" + strings.Repeat("}", 65)
	if err := jsonguard.Check([]byte(tooDeep)); err == nil {
		t.Error("65 nested objects: got nil, want a depth rejection")
	}

	// 1,000 siblings, each only two levels deep.
	var b strings.Builder
	b.WriteString(`{"list":[`)
	for i := range 1000 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"n":%d}`, i)
	}
	b.WriteString("]}")
	if err := jsonguard.Check([]byte(b.String())); err != nil {
		t.Errorf("1000 shallow siblings: got %v, want nil", err)
	}

	// Alternating containers must be counted the same way.
	alt := strings.Repeat(`{"a":[`, 33) + "1" + strings.Repeat("]}", 33)
	if err := jsonguard.Check([]byte(alt)); err == nil {
		t.Error("66 alternating containers: got nil, want a depth rejection")
	}
}

// §5.9: "A Unicode escape within a string MUST resolve to a valid code
// point per RFC 8259 §7." encoding/json silently substitutes U+FFFD for
// an unpaired surrogate, so `"source_ref": "a\ud800b"` decoded to a
// replacement character in a field that is supposed to be
// machine-resolvable.
func TestUnpairedSurrogatesAreRejected(t *testing.T) {
	for name, doc := range map[string]string{
		"lone high":            `{"a":"x\ud800y"}`,
		"lone low":             `{"a":"x\udc00y"}`,
		"high at end":          `{"a":"x\ud800"}`,
		"low first":            `{"a":"\udc00\ud800"}`,
		"high then non-escape": `{"a":"\ud800\u0041"}`,
		"high then backslash":  `{"a":"\ud800\\"}`,
		"in a member name":     `{"\ud800":1}`,
		"uppercase hex":        `{"a":"\uD800"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := jsonguard.Check([]byte(doc)); err == nil {
				t.Errorf("Check(%s) = nil, want a surrogate rejection", doc)
			}
		})
	}
}

func TestValidEscapesAreAccepted(t *testing.T) {
	for name, doc := range map[string]string{
		"proper surrogate pair": `{"a":"\ud83c\udf89"}`,
		"uppercase pair":        `{"a":"\uD83C\uDF89"}`,
		"bmp escape":            `{"a":"caf\u00e9"}`,
		"escaped quote":         `{"a":"say \"hi\""}`,
		"escaped backslash":     `{"a":"c:\\path"}`,
		// A backslash-escaped backslash must not make the following
		// \ud800 look like part of an escape sequence, nor hide it.
		"backslash then pair": `{"a":"\\\ud83c\udf89"}`,
		"brace inside string": `{"a":"{\"not\":\"json\"}"}`,
		"quote-like content":  `{"a":"[{}]"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := jsonguard.Check([]byte(doc)); err != nil {
				t.Errorf("Check(%s) = %v, want nil", doc, err)
			}
		})
	}
}

// A brace or quote inside a string literal must not be read as
// structure, or the duplicate-key and depth walks would both be
// confusable by ordinary field content.
func TestStructureIsNotConfusedByStringContents(t *testing.T) {
	doc := `{"desc":"a { b } c \" d","desc2":"[[[[","n":1}`
	if err := jsonguard.Check([]byte(doc)); err != nil {
		t.Errorf("Check: got %v, want nil", err)
	}
	// The same content, but now genuinely duplicated.
	dup := `{"desc":"a { b }","desc":"other"}`
	if err := jsonguard.Check([]byte(dup)); err == nil {
		t.Error("a duplicate key alongside brace-bearing strings was accepted")
	}
}

func TestUnmarshalRejectsBeforeDecoding(t *testing.T) {
	var v struct {
		Name string `json:"name"`
	}
	if err := jsonguard.Unmarshal([]byte(`{"name":"nginx","name":"evil"}`), &v); err == nil {
		t.Fatal("Unmarshal accepted a duplicate key")
	}
	if v.Name != "" {
		t.Errorf("Unmarshal wrote %q into the target despite rejecting the document", v.Name)
	}
	if err := jsonguard.Unmarshal([]byte(`{"name":"nginx"}`), &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if v.Name != "nginx" {
		t.Errorf("Name: got %q, want %q", v.Name, "nginx")
	}
}

// The signature envelope is §5.9's one exception to unknown-field
// tolerance, and must still get the hardening rules.
func TestUnmarshalStrict(t *testing.T) {
	var v struct {
		Algorithm string `json:"algorithm"`
	}
	if err := jsonguard.UnmarshalStrict([]byte(`{"algorithm":"ed25519","extra":1}`), &v); err == nil {
		t.Error("UnmarshalStrict accepted an unknown field")
	}
	if err := jsonguard.UnmarshalStrict([]byte(`{"algorithm":"a","algorithm":"b"}`), &v); err == nil {
		t.Error("UnmarshalStrict accepted a duplicate key")
	}
	if err := jsonguard.UnmarshalStrict([]byte(`{"algorithm":"ed25519"} {"algorithm":"x"}`), &v); err == nil {
		t.Error("UnmarshalStrict accepted trailing data")
	}
	if err := jsonguard.UnmarshalStrict([]byte(`{"algorithm":"ed25519"}`), &v); err != nil {
		t.Fatalf("UnmarshalStrict: %v", err)
	}
}

func TestMalformedJSONIsRejected(t *testing.T) {
	for _, doc := range []string{`{`, `{"a"}`, `{"a":}`, `[1,]`, `{"a":1,}`, ``} {
		if err := jsonguard.Check([]byte(doc)); err == nil {
			t.Errorf("Check(%q) = nil, want a parse error", doc)
		}
	}
}
