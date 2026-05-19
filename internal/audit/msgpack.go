package audit

import "time"

// This file is a minimal msgpack encoder for the audit-event payload.
// KMES requires the payload of an emitted event to be a msgpack value
// (§7.6); the audit payload uses only maps, arrays, strings, and
// integers, so a focused encoder for those four types suffices and
// keeps the package dependency-free.

// encodeEvent encodes e's payload — every field but the event type,
// which travels separately as the KMES event tag — as a msgpack map.
func encodeEvent(e Event) []byte {
	var b []byte
	b = mpMapHeader(b, 6)
	b = mpStr(b, "txn_id")
	b = mpInt(b, e.TxnID)
	b = mpStr(b, "outcome")
	b = mpStr(b, e.Outcome)
	b = mpStr(b, "repo")
	b = mpStr(b, e.Repo)
	b = mpStr(b, "detail")
	b = mpStr(b, e.Detail)
	b = mpStr(b, "timestamp")
	b = mpStr(b, e.Timestamp.UTC().Format(time.RFC3339))
	b = mpStr(b, "packages")
	b = mpArrayHeader(b, len(e.Packages))
	for _, p := range e.Packages {
		b = mpMapHeader(b, 3)
		b = mpStr(b, "name")
		b = mpStr(b, p.Name)
		b = mpStr(b, "version")
		b = mpStr(b, p.Version)
		b = mpStr(b, "arch")
		b = mpStr(b, p.Architecture)
	}
	return b
}

// mpMapHeader appends a msgpack map header for n key/value pairs.
func mpMapHeader(b []byte, n int) []byte {
	if n <= 15 {
		return append(b, 0x80|byte(n))
	}
	return append(b, 0xde, byte(n>>8), byte(n))
}

// mpArrayHeader appends a msgpack array header for n elements.
func mpArrayHeader(b []byte, n int) []byte {
	if n <= 15 {
		return append(b, 0x90|byte(n))
	}
	return append(b, 0xdc, byte(n>>8), byte(n))
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

// mpInt appends a msgpack integer.
func mpInt(b []byte, v int64) []byte {
	if v >= 0 && v <= 0x7F {
		return append(b, byte(v)) // positive fixint
	}
	if v < 0 && v >= -32 {
		return append(b, byte(v)) // negative fixint
	}
	u := uint64(v)
	return append(b, 0xd3, // int 64
		byte(u>>56), byte(u>>48), byte(u>>40), byte(u>>32),
		byte(u>>24), byte(u>>16), byte(u>>8), byte(u))
}
