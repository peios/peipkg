package pack

import "fmt"

// maxPayloadFileSize is the largest regular file the container can
// carry. The ustar header's 12-byte octal size field tops out at
// 8 GiB − 1, and §5.11 forbids the PAX `size` record that would extend
// it; a consumer's 4 GiB decompression bound (§5.27) would refuse the
// package long before that anyway.
const maxPayloadFileSize = 8<<30 - 1

// checkRepresentable rejects a payload the format cannot carry, before
// any byte is hashed or written.
//
// archive/tar used to be left to handle an oversized file itself, which
// it does by emitting the forbidden `size` record: pekit then produced,
// silently, a package that no conformant consumer could ever verify.
// The size is the one recorded at walk time — the same figure the tar
// header is written from — so this needs no second stat (PEI-427).
func checkRepresentable(leaves []entry) error {
	for _, e := range leaves {
		if e.kind == kindFile && e.size > maxPayloadFileSize {
			return fmt.Errorf("%s is %d bytes, and the package format cannot carry a file "+
				"of 8 GiB or more: the ustar size field tops out at 8 GiB - 1, §5.11 "+
				"forbids the PAX size record that would extend it, and a consumer's "+
				"4 GiB decompression bound (§5.27) could never verify the result. "+
				"Split the file, or ship it outside the package", e.path, e.size)
		}
	}
	return nil
}
