package audit

import (
	"fmt"
	"sort"
	"strings"
)

// This file is a minimal msgpack encoder for the audit-event payload.
// KMES requires the payload of an emitted event to be a msgpack value,
// and PGSS §6.4 makes it one map whose fields are nested maps, one per
// path segment. The payload uses only maps, strings, unsigned integers,
// booleans and binary, so a focused encoder for those suffices and keeps
// the package dependency-free.

// node is one map of the payload tree: a field's value, or the map its
// longer paths continue into.
type node struct {
	value    any
	leaf     bool
	children map[string]*node
}

// encodePayload encodes fields, keyed by dotted path, as nested msgpack
// maps. A path that is both a value and the prefix of another path, an
// empty segment, or a value of a type the encoder does not carry is a
// programming error and is reported rather than encoded.
func encodePayload(fields map[string]any) ([]byte, error) {
	root := &node{children: map[string]*node{}}
	for path, v := range fields {
		segs := strings.Split(path, ".")
		n := root
		for i, s := range segs {
			if s == "" {
				return nil, fmt.Errorf("peipkg/audit: field %q has an empty segment", path)
			}
			if n.leaf {
				return nil, fmt.Errorf("peipkg/audit: field %q continues beneath a value", path)
			}
			child, ok := n.children[s]
			if !ok {
				child = &node{children: map[string]*node{}}
				n.children[s] = child
			}
			if i == len(segs)-1 {
				if len(child.children) > 0 {
					return nil, fmt.Errorf("peipkg/audit: field %q is also a map", path)
				}
				child.leaf, child.value = true, v
			}
			n = child
		}
	}
	return appendNode(nil, root)
}

// appendNode appends n's map, keys in sorted order so a payload's bytes
// are deterministic.
func appendNode(b []byte, n *node) ([]byte, error) {
	keys := make([]string, 0, len(n.children))
	for k := range n.children {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b = mpMapHeader(b, len(keys))
	for _, k := range keys {
		b = mpStr(b, k)
		child := n.children[k]
		var err error
		if child.leaf {
			b, err = appendValue(b, child.value)
		} else {
			b, err = appendNode(b, child)
		}
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

// appendValue appends one field value.
func appendValue(b []byte, v any) ([]byte, error) {
	switch v := v.(type) {
	case string:
		return mpStr(b, v), nil
	case uint64:
		return mpUint(b, v), nil
	case bool:
		return mpBool(b, v), nil
	case []byte:
		return mpBin(b, v), nil
	}
	return nil, fmt.Errorf("peipkg/audit: no msgpack form for a %T value", v)
}

// mpMapHeader appends a msgpack map header for n key/value pairs.
func mpMapHeader(b []byte, n int) []byte {
	switch {
	case n <= 15:
		return append(b, 0x80|byte(n))
	case n <= 0xFFFF:
		return append(b, 0xde, byte(n>>8), byte(n))
	}
	return append(b, 0xdf, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// mpStr appends a msgpack string.
func mpStr(b []byte, s string) []byte {
	switch n := len(s); {
	case n <= 31:
		b = append(b, 0xa0|byte(n))
	case n <= 0xFF:
		b = append(b, 0xd9, byte(n))
	case n <= 0xFFFF:
		b = append(b, 0xda, byte(n>>8), byte(n))
	default:
		b = append(b, 0xdb, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(b, s...)
}

// mpBin appends a msgpack binary value.
func mpBin(b []byte, v []byte) []byte {
	switch n := len(v); {
	case n <= 0xFF:
		b = append(b, 0xc4, byte(n))
	case n <= 0xFFFF:
		b = append(b, 0xc5, byte(n>>8), byte(n))
	default:
		b = append(b, 0xc6, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(b, v...)
}

// mpUint appends a msgpack unsigned integer in its shortest form.
func mpUint(b []byte, v uint64) []byte {
	switch {
	case v <= 0x7F:
		return append(b, byte(v)) // positive fixint
	case v <= 0xFF:
		return append(b, 0xcc, byte(v))
	case v <= 0xFFFF:
		return append(b, 0xcd, byte(v>>8), byte(v))
	case v <= 0xFFFFFFFF:
		return append(b, 0xce, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	return append(b, 0xcf,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// mpBool appends a msgpack boolean.
func mpBool(b []byte, v bool) []byte {
	if v {
		return append(b, 0xc3)
	}
	return append(b, 0xc2)
}
