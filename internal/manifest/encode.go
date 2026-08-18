package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/peios/peipkg/internal/version"
)

// The encoders below are the exact inverse of the Decode*Array functions
// in decode.go, and exist for one caller: the repository publisher,
// which re-serialises dependency metadata into a repository index
// (PSD-009 §6.2.3).
//
// Keeping them here, beside the decoders and sharing the same wire
// structs, is deliberate. The index's derivation rule (§6.2.5) requires
// every index field to match the package manifest exactly, and the only
// durable way to hold a producer and a consumer to one wire shape is to
// give them one definition of it. A second set of structs in the
// publisher would be free to drift, and the drift would surface as a
// consumer rejecting a repository that its own publisher produced.
//
// Each encoder returns nil for an empty array rather than `[]`, so the
// caller can omit the field entirely. An absent array and an empty one
// decode identically (Decode*Array returns nil for both), so omitting
// is the smaller, and therefore canonical, rendering.
//
// The dependency-family and provides/replaces encoders SORT by name.
// §4.1.6 makes lexicographic order part of the wire format, and the
// decoder enforces it — so an encoder that emitted a caller's order
// verbatim would produce documents this very package rejects. Ordering
// belongs to the format, not to the caller, exactly as it does for the
// package array of an index.
//
// side_effects is deliberately NOT sorted. §4.3 requires its entries to
// be unique but says nothing about order, because the array is a
// sequence of operations to run rather than a set to look things up in.
// Sorting it would silently reorder work.

// wireDependencyOut is the encoding-side mirror of [wireDependency].
// It differs in exactly two ways, both required for a canonical
// rendering: `name` is a plain string (encoding never has the absent
// case a decoder must detect), and every optional field carries
// omitempty so a default-valued field is left out rather than written
// as an empty string.
type wireDependencyOut struct {
	Name       string                      `json:"name"`
	Constraint string                      `json:"constraint,omitempty"`
	Root       string                      `json:"root,omitempty"`
	Claims     map[string]wireClaimSlotOut `json:"claims,omitempty"`
}

type wireProvidesOut struct {
	Name    string                      `json:"name"`
	Version string                      `json:"version,omitempty"`
	Claims  map[string]wireClaimSlotOut `json:"claims,omitempty"`
}

type wireClaimSlotOut struct {
	Path   string `json:"path,omitempty"`
	Target string `json:"target,omitempty"`
}

type wireReplacesOut struct {
	Name       string `json:"name"`
	Constraint string `json:"constraint,omitempty"`
}

// EncodeDependencyArray renders a dependency, optional_dependency, or
// conflicts array as JSON (§4.1.1, §4.1.2), returning nil when the
// array is empty.
func EncodeDependencyArray(deps []Dependency) (json.RawMessage, error) {
	if len(deps) == 0 {
		return nil, nil
	}
	wires := make([]wireDependencyOut, len(deps))
	for i, dep := range deps {
		wires[i] = wireDependencyOut{
			Name:       dep.Name,
			Constraint: encodeConstraint(dep.Constraint),
			Root:       dep.Root,
			Claims:     encodeClaims(dep.Claims),
		}
	}
	sort.Slice(wires, func(i, j int) bool { return wires[i].Name < wires[j].Name })
	return marshalCompact(wires, "dependencies")
}

// EncodeProvidesArray renders a provides array as JSON (§4.1.4),
// returning nil when the array is empty.
func EncodeProvidesArray(provides []Provides) (json.RawMessage, error) {
	if len(provides) == 0 {
		return nil, nil
	}
	wires := make([]wireProvidesOut, len(provides))
	for i, p := range provides {
		w := wireProvidesOut{Name: p.Name, Claims: encodeClaims(p.Claims)}
		// A nil Version means the entry provides any version, which the
		// decoder signals by the field's absence — not by an empty
		// string, which would fail to parse on the way back in.
		if p.Version != nil {
			w.Version = p.Version.String()
		}
		wires[i] = w
	}
	sort.Slice(wires, func(i, j int) bool { return wires[i].Name < wires[j].Name })
	return marshalCompact(wires, "provides")
}

// EncodeReplacesArray renders a replaces array as JSON (§4.1.5),
// returning nil when the array is empty.
func EncodeReplacesArray(replaces []Replaces) (json.RawMessage, error) {
	if len(replaces) == 0 {
		return nil, nil
	}
	wires := make([]wireReplacesOut, len(replaces))
	for i, r := range replaces {
		wires[i] = wireReplacesOut{Name: r.Name, Constraint: encodeConstraint(r.Constraint)}
	}
	sort.Slice(wires, func(i, j int) bool { return wires[i].Name < wires[j].Name })
	return marshalCompact(wires, "replaces")
}

// EncodeSideEffectArray renders a side_effects array as JSON (§4.3),
// returning nil when the array is empty.
func EncodeSideEffectArray(effects []SideEffect) (json.RawMessage, error) {
	if len(effects) == 0 {
		return nil, nil
	}
	raw := make([]string, len(effects))
	for i, e := range effects {
		raw[i] = string(e)
	}
	return marshalCompact(raw, "side_effects")
}

// encodeConstraint renders a constraint for the wire, mapping the zero
// constraint to the empty string so the field is omitted.
//
// This is NOT [version.Constraint.String], which renders the zero
// constraint as the human-facing word "any". Writing "any" here would
// produce a document that no longer round-trips: ParseConstraint has no
// such operator, so the next reader of this index would reject an entry
// that was written from a perfectly valid manifest.
func encodeConstraint(c version.Constraint) string {
	if c.Any() {
		return ""
	}
	return c.String()
}

// encodeClaims renders a claims map (§4.4.2), returning nil for an
// empty one. Go marshals map keys in sorted order, so the rendering is
// deterministic without the caller sorting slot names.
func encodeClaims(claims map[string]ClaimSlot) map[string]wireClaimSlotOut {
	if len(claims) == 0 {
		return nil
	}
	out := make(map[string]wireClaimSlotOut, len(claims))
	for name, slot := range claims {
		out[name] = wireClaimSlotOut{Path: slot.Path, Target: slot.Target}
	}
	return out
}

// marshalCompact renders v as JSON with HTML escaping disabled.
//
// Escaping matters here: encoding/json rewrites <, > and & as < and
// friends by default, a defence for JSON embedded in HTML that this
// never is. Left on, a claim path or constraint containing one of those
// characters would be written in an escaped form that differs
// byte-for-byte from the manifest it was derived from — technically
// equivalent JSON, but a needless divergence in a document whose whole
// contract (§6.2.5) is that it matches the manifest.
func marshalCompact(v any, field string) (json.RawMessage, error) {
	data, err := jsonMarshalNoEscape(v)
	if err != nil {
		return nil, fmt.Errorf("peipkg/manifest: encoding %s: %w", field, err)
	}
	return data, nil
}

// jsonMarshalNoEscape marshals v with HTML escaping disabled and no
// trailing newline (encoding/json's Encoder always appends one).
func jsonMarshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
