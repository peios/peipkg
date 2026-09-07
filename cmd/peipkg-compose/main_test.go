package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestXattrRecorderWritesDeterministicJSONL(t *testing.T) {
	r := newXattrRecorder()
	if err := r.Record("usr/bin/tool", "security.peios.sig", []byte{2}); err != nil {
		t.Fatal(err)
	}
	if err := r.Record("home", "security.peios.sd", []byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := r.Record("usr/bin/tool", "security.peios.sd", []byte{3}); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "records", "xattrs.jsonl")
	if err := r.Write(path); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "" +
		"{\"path\":\"home\",\"name\":\"security.peios.sd\",\"value\":\"AQ==\"}\n" +
		"{\"path\":\"usr/bin/tool\",\"name\":\"security.peios.sd\",\"value\":\"Aw==\"}\n" +
		"{\"path\":\"usr/bin/tool\",\"name\":\"security.peios.sig\",\"value\":\"Ag==\"}\n"
	if string(got) != want {
		t.Fatalf("xattr record:\n%s\nwant:\n%s", got, want)
	}
}

func TestXattrRecorderRefusesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xattrs.jsonl")
	if err := os.WriteFile(path, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := newXattrRecorder().Write(path); err == nil {
		t.Fatal("Write replaced an existing xattr record")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep\n" {
		t.Fatalf("existing file changed to %q", got)
	}
}

func TestXattrRecorderRejectsConflictingDuplicate(t *testing.T) {
	r := newXattrRecorder()
	if err := r.Record("usr/bin/tool", "security.peios.sd", []byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := r.Record("usr/bin/tool", "security.peios.sd", []byte{2}); err == nil {
		t.Fatal("Record accepted conflicting values for one path and name")
	}
}
