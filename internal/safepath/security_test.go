package safepath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirectoryDescriptorCacheTracksInodesNotNames(t *testing.T) {
	root := t.TempDir()
	r, err := OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	stamps := 0
	r.SetDirectoryDescriptors(map[string][]byte{"scope": []byte("test descriptor")}, func(string, []byte) error { stamps++; return nil })
	first, err := r.MkdirAll("scope/first", 0o755)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err := os.Rename(filepath.Join(root, "scope"), filepath.Join(root, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "scope"), 0o755); err != nil {
		t.Fatal(err)
	}
	second, err := r.MkdirAll("scope/second", 0o755)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if stamps != 2 {
		t.Fatalf("replacement directory did not receive its policy: %d stamps", stamps)
	}
}
