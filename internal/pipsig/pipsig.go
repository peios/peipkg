// Package pipsig defines the payload-side carrier for a PIP signature on a
// non-ELF file: the `<path>.peios.sig` sidecar (PSPK chapter 3, PSPU §5).
//
// A PIP signature has two placements the kernel understands — the ELF
// `.peios.sig` section for executables and libraries, and the
// `security.peios.sig` extended attribute for everything else (device
// firmware, above all). A package cannot carry the second directly:
// PSPU §5.11 forbids extended attributes on package entries. So the
// package carries the signature as an ordinary payload file whose name
// is the signed file's name plus [Suffix], and the consumer that
// materialises the payload *derives* the xattr from it: it writes the
// target, sets the attribute from the sidecar's bytes, and never writes
// the sidecar itself to disk. The sidecar is therefore never an
// installed file and is never recorded as one.
//
// The rules a sidecar entry must satisfy, enforced at pack time and
// again by every consumer:
//
//  1. its target — the entry path with [Suffix] removed — is a regular
//     file entry of the same package (not a directory, not a symlink,
//     not absent);
//  2. its content is exactly [BlobLen] bytes whose first byte is
//     [Version] — the blob layout the kernel reads, verbatim;
//  3. the target is not an ELF file, which would carry the section
//     placement and so would end up with two carriers for one file.
//
// Nothing here verifies the signature. That is the kernel's job, against
// its built-in key table; a consumer stamps what it was given.
package pipsig

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// Suffix is appended to a payload path to name that file's signature
// sidecar. It is the ELF section's name, so a signer's output has one
// name whichever placement it lands in.
const Suffix = ".peios.sig"

// XattrName is the extended attribute the consumer derives from the
// sidecar and the kernel reads.
const XattrName = "security.peios.sig"

// BlobLen is the fixed size of a signature blob: one version byte
// followed by a raw ML-DSA-65 signature (3309 bytes).
const BlobLen = 3310

// Version is the only blob version PSPK defines.
const Version = 0x01

// elfMagic is the four bytes every ELF file begins with.
var elfMagic = []byte("\x7fELF")

// IsSidecar reports whether a payload path names a signature sidecar.
// A bare ".peios.sig" — a suffix with no target name — is not one; it
// is an ordinary (if oddly named) file, and the target rule would
// reject it as a sidecar anyway.
func IsSidecar(path string) bool {
	return strings.HasSuffix(path, Suffix) && len(path) > len(Suffix) &&
		!strings.HasSuffix(path, "/"+Suffix)
}

// Target returns the path of the file a sidecar signs.
func Target(sidecar string) string {
	return strings.TrimSuffix(sidecar, Suffix)
}

// ValidateBlob checks a sidecar's content against the blob layout.
func ValidateBlob(blob []byte) error {
	if len(blob) != BlobLen {
		return fmt.Errorf("signature blob is %d bytes, want %d", len(blob), BlobLen)
	}
	if blob[0] != Version {
		return fmt.Errorf("signature blob version is 0x%02x, want 0x%02x", blob[0], Version)
	}
	return nil
}

// IsELF reports whether head — the first bytes of a file — carries the
// ELF magic. Fewer than four bytes is not ELF.
func IsELF(head []byte) bool {
	return len(head) >= len(elfMagic) && bytes.Equal(head[:len(elfMagic)], elfMagic)
}

// Stamp sets the signature attribute on the file at path. It is a
// variable so tests can observe the stamp without the privilege the
// real one needs: security.* attributes are settable only with
// CAP_SYS_ADMIN, which an ordinary test process lacks.
var Stamp = func(path string, blob []byte) error {
	if err := unix.Setxattr(path, XattrName, blob, 0); err != nil {
		return fmt.Errorf("set %s on %s: %w", XattrName, path, err)
	}
	return nil
}

// Sidecars collects the sidecar entries met while a payload is being
// extracted, so their targets can be stamped once every entry has been
// written. Collecting rather than stamping inline frees the consumer
// from the archive's entry order: a sidecar sorts after its target
// today, but correctness should not rest on that.
type Sidecars struct {
	blobs map[string][]byte // keyed by target path, as it appears in the archive
}

// Add reads and validates one sidecar entry's content. entryPath is the
// sidecar's archive path.
func (s *Sidecars) Add(entryPath string, content io.Reader) error {
	blob, err := io.ReadAll(io.LimitReader(content, BlobLen+1))
	if err != nil {
		return fmt.Errorf("%s: read signature sidecar: %w", entryPath, err)
	}
	if err := ValidateBlob(blob); err != nil {
		return fmt.Errorf("%s: %w", entryPath, err)
	}
	if s.blobs == nil {
		s.blobs = map[string][]byte{}
	}
	s.blobs[Target(entryPath)] = blob
	return nil
}

// Len is the number of sidecars collected.
func (s *Sidecars) Len() int { return len(s.blobs) }

// Apply stamps every collected signature onto its target. locate maps a
// target's archive path to the on-disk path of the regular file the
// consumer wrote for it — the staged sibling during an install, the
// final path during a compose — returning false when the package wrote
// no regular file there. The target is checked not to be ELF before it
// is stamped.
func (s *Sidecars) Apply(locate func(target string) (string, bool)) error {
	return s.ApplyWith(locate, Stamp)
}

// ApplyWith is [Apply] with the stamping step supplied by the caller:
// stamp receives the target's on-disk path and the signature blob. A
// consumer that cannot set security.* attributes — an image builder
// running unprivileged — records the pair for the image writer to apply
// instead. Every check Apply makes is made here too.
func (s *Sidecars) ApplyWith(locate func(target string) (string, bool),
	stamp func(path string, blob []byte) error) error {
	targets := make([]string, 0, len(s.blobs))
	for t := range s.blobs {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	for _, target := range targets {
		path, ok := locate(target)
		if !ok {
			return fmt.Errorf("%s%s: signature sidecar has no regular-file target %s in the package",
				target, Suffix, target)
		}
		head, err := ReadHead(path, len(elfMagic))
		if err != nil {
			return fmt.Errorf("%s%s: read target: %w", target, Suffix, err)
		}
		if IsELF(head) {
			return fmt.Errorf("%s%s: target %s is an ELF file, which carries its signature in a section, not a sidecar",
				target, Suffix, target)
		}
		if err := stamp(path, s.blobs[target]); err != nil {
			return fmt.Errorf("%s%s: %w", target, Suffix, err)
		}
	}
	return nil
}

// ReadHead returns up to n leading bytes of the file at path; fewer
// when the file is shorter.
func ReadHead(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	head := make([]byte, n)
	got, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	return head[:got], nil
}
