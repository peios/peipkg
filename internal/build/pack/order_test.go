package pack_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/peios/peipkg/internal/archive"
	"github.com/peios/peipkg/internal/build/pack"
)

// TestPackOrdersFileDirPrefixCollision is a regression test for a payload
// sort bug. When a file and a directory share a prefix — e.g. the file
// "asm/fpu.h" beside the directory "asm/fpu/" (the synthesized ancestor of
// "asm/fpu/api.h") — sorting payload entries by their bare path puts
// "asm/fpu" before "asm/fpu.h". But directory entries emit with a trailing
// slash, and the archive reader collates the emitted names, where
// "asm/fpu.h" precedes "asm/fpu/" because '.' (0x2e) < '/' (0x2f). The
// emitted order was therefore descending and the reader rejected the
// archive as "payload entries are not sorted". Packing must order entries
// by their on-wire (slash-terminated for directories) names.
//
// This shape occurs in real packages: the kernel-devel and kernel-debugsource
// trees both carry a file alongside a like-named directory (asm/fpu.h next to
// asm/fpu/, .../vdso32-setup.c next to .../vdso32/).
func TestPackOrdersFileDirPrefixCollision(t *testing.T) {
	src := t.TempDir()
	fpuH := filepath.Join(src, "fpu.h")
	if err := os.WriteFile(fpuH, []byte("/* fpu.h */\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	apiH := filepath.Join(src, "api.h")
	if err := os.WriteFile(apiH, []byte("/* fpu/api.h */\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	files := map[string]string{
		"usr/include/asm/fpu.h":     fpuH, // file
		"usr/include/asm/fpu/api.h": apiH, // forces the "asm/fpu/" directory entry
	}

	var buf bytes.Buffer
	if err := pack.Pack(pack.Input{
		Files:    files,
		Manifest: helloNoarchManifest(),
		Out:      &buf,
	}); err != nil {
		t.Fatalf("pack: %v", err)
	}

	if _, err := archive.VerifyFormat(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("VerifyFormat rejected a packed archive with a file/dir prefix collision: %v", err)
	}
}
