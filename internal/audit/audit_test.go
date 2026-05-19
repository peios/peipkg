package audit

import (
	"bytes"
	"testing"
	"time"
)

func TestMsgpackPrimitives(t *testing.T) {
	cases := []struct {
		name string
		got  []byte
		want []byte
	}{
		{"fixstr", mpStr(nil, "ab"), []byte{0xa2, 'a', 'b'}},
		{"positive fixint", mpInt(nil, 5), []byte{0x05}},
		{"int64", mpInt(nil, 1000), []byte{0xd3, 0, 0, 0, 0, 0, 0, 0x03, 0xe8}},
		{"fixmap", mpMapHeader(nil, 6), []byte{0x86}},
		{"fixarray", mpArrayHeader(nil, 2), []byte{0x92}},
	}
	for _, c := range cases {
		if !bytes.Equal(c.got, c.want) {
			t.Errorf("%s: got % x, want % x", c.name, c.got, c.want)
		}
	}
}

func TestEncodeEvent(t *testing.T) {
	b := encodeEvent(Event{
		Type: TypeInstall, TxnID: 7, Outcome: OutcomeSuccess,
		Repo: "official", Detail: "1 installed",
		Timestamp: time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC),
		Packages:  []PackageRef{{Name: "nginx", Version: "1.0-1", Architecture: "x86_64"}},
	})
	// The payload is a six-pair fixmap.
	if len(b) == 0 || b[0] != 0x86 {
		t.Fatalf("payload does not begin with a 6-pair map header: % x", b)
	}
	// msgpack strings carry their bytes inline, so every field name and
	// string value appears verbatim in the encoded payload.
	for _, want := range []string{
		"txn_id", "outcome", "success", "repo", "official", "detail",
		"timestamp", "2026-05-19T12:00:00Z", "packages", "nginx", "1.0-1", "x86_64",
	} {
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("payload is missing %q", want)
		}
	}
}

func TestRecorder(t *testing.T) {
	var r Recorder
	if err := r.Emit(Event{Type: TypeRefresh}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if len(r.Events) != 1 || r.Events[0].Type != TypeRefresh {
		t.Errorf("Recorder did not record the event: %+v", r.Events)
	}
}
