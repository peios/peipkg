package archive

import (
	"archive/tar"
	"fmt"
	"io"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// Extract walks the payload entries of a .peipkg archive read from r,
// yielding each to onEntry in archive order. For a regular file,
// content streams the file's bytes; for a directory or symlink it
// carries nothing. After onEntry returns, Extract drains any unread
// content so the tar walk stays aligned.
//
// Extract trusts the archive: it must already have passed [Verify], and
// the archive must not have changed since. Extract re-checks neither the
// signature nor the per-file hashes — Verify did, on an archive that is
// immutable across the two passes.
func Extract(r io.ReadSeeker, onEntry func(PayloadEntry, io.Reader) error) error {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("peipkg/archive: seek to start: %w", err)
	}
	zr, err := zstd.NewReader(r)
	if err != nil {
		return fmt.Errorf("peipkg/archive: open zstd stream: %w", err)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("peipkg/archive: reading tar: %w", err)
		}
		if strings.HasPrefix(hdr.Name, metadataPrefix) {
			continue // a `.peipkg/` metadata entry, not payload
		}
		entry, err := payloadEntry(hdr)
		if err != nil {
			return err
		}
		if err := onEntry(entry, tr); err != nil {
			return err
		}
		if _, err := io.Copy(io.Discard, tr); err != nil {
			return fmt.Errorf("peipkg/archive: draining payload entry %q: %w", entry.Path, err)
		}
	}
}
