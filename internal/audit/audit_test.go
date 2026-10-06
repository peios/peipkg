package audit

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/peios/libp-go/errno"
	"github.com/peios/libp-go/event"
)

// decode reads back the subset of msgpack encodePayload writes: maps,
// strings, unsigned integers, booleans and binary.
func decode(t *testing.T, b []byte) any {
	t.Helper()
	v, rest, err := decodeValue(b)
	if err != nil {
		t.Fatalf("decode: %v (% x)", err, b)
	}
	if len(rest) != 0 {
		t.Fatalf("decode: %d trailing bytes", len(rest))
	}
	return v
}

func decodeValue(b []byte) (any, []byte, error) {
	if len(b) == 0 {
		return nil, nil, errors.New("short")
	}
	c := b[0]
	be := func(n int) (uint64, []byte, error) {
		if len(b) < 1+n {
			return 0, nil, errors.New("short")
		}
		var v uint64
		for _, x := range b[1 : 1+n] {
			v = v<<8 | uint64(x)
		}
		return v, b[1+n:], nil
	}
	switch {
	case c <= 0x7f:
		return uint64(c), b[1:], nil
	case c&0xf0 == 0x80, c == 0xde, c == 0xdf:
		var n uint64
		var rest []byte
		var err error
		switch c {
		case 0xde:
			n, rest, err = be(2)
		case 0xdf:
			n, rest, err = be(4)
		default:
			n, rest = uint64(c&0x0f), b[1:]
		}
		if err != nil {
			return nil, nil, err
		}
		m := map[string]any{}
		for i := uint64(0); i < n; i++ {
			k, r, err := decodeValue(rest)
			if err != nil {
				return nil, nil, err
			}
			ks, ok := k.(string)
			if !ok {
				return nil, nil, fmt.Errorf("non-string key %v", k)
			}
			v, r, err := decodeValue(r)
			if err != nil {
				return nil, nil, err
			}
			m[ks] = v
			rest = r
		}
		return m, rest, nil
	case c&0xe0 == 0xa0, c == 0xd9, c == 0xda, c == 0xdb, c == 0xc4, c == 0xc5, c == 0xc6:
		var n uint64
		var rest []byte
		var err error
		switch c {
		case 0xd9, 0xc4:
			n, rest, err = be(1)
		case 0xda, 0xc5:
			n, rest, err = be(2)
		case 0xdb, 0xc6:
			n, rest, err = be(4)
		default:
			n, rest = uint64(c&0x1f), b[1:]
		}
		if err != nil || uint64(len(rest)) < n {
			return nil, nil, errors.New("short")
		}
		if c >= 0xc4 && c <= 0xc6 {
			return append([]byte{}, rest[:n]...), rest[n:], nil
		}
		return string(rest[:n]), rest[n:], nil
	case c == 0xc2:
		return false, b[1:], nil
	case c == 0xc3:
		return true, b[1:], nil
	case c == 0xcc:
		return be(1)
	case c == 0xcd:
		return be(2)
	case c == 0xce:
		return be(4)
	case c == 0xcf:
		return be(8)
	}
	return nil, nil, fmt.Errorf("unsupported byte %#x", c)
}

func TestMsgpackPrimitives(t *testing.T) {
	cases := []struct {
		name string
		got  []byte
		want []byte
	}{
		{"fixstr", mpStr(nil, "ab"), []byte{0xa2, 'a', 'b'}},
		{"positive fixint", mpUint(nil, 5), []byte{0x05}},
		{"uint8", mpUint(nil, 200), []byte{0xcc, 200}},
		{"uint16", mpUint(nil, 1000), []byte{0xcd, 0x03, 0xe8}},
		{"uint32", mpUint(nil, 1<<20), []byte{0xce, 0, 0x10, 0, 0}},
		{"uint64", mpUint(nil, 1<<40), []byte{0xcf, 0, 0, 1, 0, 0, 0, 0, 0}},
		{"true", mpBool(nil, true), []byte{0xc3}},
		{"false", mpBool(nil, false), []byte{0xc2}},
		{"bin8", mpBin(nil, []byte{1, 2}), []byte{0xc4, 2, 1, 2}},
		{"fixmap", mpMapHeader(nil, 6), []byte{0x86}},
		{"map16", mpMapHeader(nil, 16), []byte{0xde, 0, 16}},
	}
	for _, c := range cases {
		if !bytes.Equal(c.got, c.want) {
			t.Errorf("%s: got % x, want % x", c.name, c.got, c.want)
		}
	}
}

// PGSS §6.4: a field's path is a chain of nested maps, never a key
// holding a dot.
func TestPayloadNestsEveryPath(t *testing.T) {
	sid := []byte{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}
	e := PackageEvent(TypePackageUpgraded, 7, Package{
		Name: "nginx", Version: "1.26.2-3", VersionPrevious: "1.26.1-1",
		Architecture: "x86_64", Repository: "peios-official",
	}).Succeeded().Bin(FieldSubjectSID, sid)
	b, err := encodePayload(e.Fields)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("object.package")) {
		t.Errorf("a dotted key reached the payload: % x", b)
	}
	got := decode(t, b)
	want := map[string]any{
		"subject":     map[string]any{"token": map[string]any{"sid": sid}},
		"transaction": map[string]any{"id": uint64(7)},
		"object": map[string]any{"package": map[string]any{
			"name": "nginx", "version": "1.26.2-3", "version-previous": "1.26.1-1",
			"architecture": "x86_64",
		}},
		"source":  map[string]any{"repository": map[string]any{"name": "peios-official"}},
		"outcome": map[string]any{"success": true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("payload:\n got %#v\nwant %#v", got, want)
	}
}

// PGSS §6.5: an absent value is no key, never "" or 0. A removal has no
// architecture or source, and a refused request no transaction.
func TestAbsentValuesAreOmitted(t *testing.T) {
	e := PackageEvent(TypePackageUninstalled, 0, Package{Name: "nginx", Version: "1.0-1"}).
		Failed("busy", "")
	for _, p := range []string{FieldTransactionID, FieldPackageArchitecture,
		FieldSourceRepository, FieldPackageVersionPrev, FieldOutcomeDetail} {
		if _, ok := e.Get(p); ok {
			t.Errorf("%s is present, want absent", p)
		}
	}
	if v, _ := e.Get(FieldOutcomeReason); v != "busy" {
		t.Errorf("outcome.reason = %v", v)
	}
	if v, _ := e.Get(FieldOutcomeSuccess); v != false {
		t.Errorf("outcome.success = %v", v)
	}
}

func TestPayloadRejectsAPathThatIsBothValueAndMap(t *testing.T) {
	_, err := encodePayload(map[string]any{"a.b": "x", "a.b.c": "y"})
	if err == nil {
		t.Fatal("a path that is both a value and a map was encoded")
	}
	if _, err := encodePayload(map[string]any{"a": int(1)}); err == nil {
		t.Fatal("an int, which the payload never carries, was encoded")
	}
}

func TestRecorder(t *testing.T) {
	var r Recorder
	if err := r.Emit(New(TypeRepositoryRefreshed)); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if len(r.OfType(TypeRepositoryRefreshed)) != 1 {
		t.Errorf("Recorder did not record the event: %+v", r.Events)
	}
}

// fakeGate stands in for the emission policy.
type fakeGate struct {
	on    bool
	asked []string
	sent  [][]byte
}

func (g *fakeGate) EmitWith(typ string, tier event.Tier, build func() ([]byte, error)) (bool, error) {
	g.asked = append(g.asked, fmt.Sprintf("%s/%s", typ, tier))
	if !g.on {
		return false, nil
	}
	b, err := build()
	if err != nil {
		return false, err
	}
	g.sent = append(g.sent, b)
	return true, nil
}

func testEmitter(g *fakeGate, sid func() ([]byte, error)) (*KMESEmitter, *[][]byte) {
	var sent [][]byte
	return &KMESEmitter{
		send:     func(_ string, p []byte) error { sent = append(sent, p); return nil },
		openGate: func() gate { return g },
		userSID:  sid,
	}, &sent
}

// PGSS §6.9: an essential type never consults the policy; any other does,
// and is not built when switched off.
func TestEmitterTiers(t *testing.T) {
	builds := 0
	g := &fakeGate{}
	k, sent := testEmitter(g, func() ([]byte, error) { builds++; return []byte{1, 0, 0, 0, 0, 0, 0, 5}, nil })

	if err := k.Emit(New(TypePackageInstalled).Succeeded()); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 1 || len(g.asked) != 0 {
		t.Fatalf("essential: sent %d, policy asked %v", len(*sent), g.asked)
	}

	for _, typ := range []string{TypeClaimChanged, TypeRepositoryRefreshed, TypeTransactionRecovered} {
		g.asked = nil
		if err := k.Emit(New(typ).Succeeded()); err != nil {
			t.Fatal(err)
		}
		if want := []string{typ + "/standard"}; !reflect.DeepEqual(g.asked, want) {
			t.Errorf("%s: policy asked %v, want %v", typ, g.asked, want)
		}
	}
	if len(g.sent) != 0 {
		t.Errorf("a switched-off type was emitted")
	}
	if builds != 1 {
		t.Errorf("the token was read %d times, want once (and only for a built payload)", builds)
	}
	g.on = true
	if err := k.Emit(New(TypeTransactionRecovered).Succeeded()); err != nil {
		t.Fatal(err)
	}
	if len(g.sent) != 1 {
		t.Errorf("a switched-on standard type was not emitted")
	}
}

func TestEmitterCarriesTheSubject(t *testing.T) {
	sid := []byte{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}
	k, sent := testEmitter(&fakeGate{}, func() ([]byte, error) { return sid, nil })
	if err := k.Emit(New(TypeRepositoryRemoved).Str(FieldRepositoryName, "x").Succeeded()); err != nil {
		t.Fatal(err)
	}
	got := decode(t, (*sent)[0]).(map[string]any)
	if !reflect.DeepEqual(got["subject"], map[string]any{"token": map[string]any{"sid": sid}}) {
		t.Errorf("subject = %#v", got["subject"])
	}
}

// A token that cannot be read still leaves a record, without the SID,
// and a warning; with no token syscalls there is no KMES either.
func TestEmitterWithoutTheSubject(t *testing.T) {
	k, sent := testEmitter(&fakeGate{}, func() ([]byte, error) { return nil, errno.EACCES })
	err := k.Emit(New(TypeRepositoryRemoved).Str(FieldRepositoryName, "x").Succeeded())
	if err == nil || len(*sent) != 1 {
		t.Fatalf("err=%v sent=%d, want a warning and the record", err, len(*sent))
	}
	if _, ok := decode(t, (*sent)[0]).(map[string]any)["subject"]; ok {
		t.Error("subject present without a token")
	}

	k, sent = testEmitter(&fakeGate{}, func() ([]byte, error) { return nil, errno.ENOSYS })
	if err := k.Emit(New(TypeRepositoryRemoved).Succeeded()); err != nil || len(*sent) != 0 {
		t.Errorf("no KMES: err=%v sent=%d, want a silent no-op", err, len(*sent))
	}
}

func TestEmitterTreatsMissingKMESAsANoOp(t *testing.T) {
	k := &KMESEmitter{
		send:     func(string, []byte) error { return fmt.Errorf("libp/event: emit: %w", errno.ENOSYS) },
		openGate: func() gate { return &fakeGate{} },
		userSID:  func() ([]byte, error) { return []byte{1}, nil },
	}
	if err := k.Emit(New(TypePackageInstalled).Succeeded()); err != nil {
		t.Errorf("ENOSYS from kmes_emit: %v, want nil", err)
	}
}

func TestEveryTypeHasATier(t *testing.T) {
	for _, typ := range []string{TypePackageInstalled, TypePackageUpgraded, TypePackageUninstalled,
		TypeClaimChanged, TypeRepositoryAdded, TypeRepositoryRemoved, TypeRepositoryReconfigured,
		TypeRepositoryRefreshed, TypeTransactionRecovered, TypeActionAuthorised} {
		if _, ok := tiers[typ]; !ok {
			t.Errorf("%s has no tier", typ)
		}
	}
}
