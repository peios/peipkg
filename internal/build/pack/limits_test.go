package pack

import (
	"strings"
	"testing"
)

// §5.11 forbids the PAX size record, so a regular file of 8 GiB or more
// has no representation in the container; the 4 GiB decompression cap
// makes the artifact unverifiable besides. Pack used to hand such a
// file to archive/tar, which emitted the forbidden record and produced
// an unusable package without a word (PEI-427 part 3).
//
// The size is the walk-time figure on the entry — what the tar header
// is written from — so the check is driven with synthetic entries and
// no 8 GiB file is ever created.
func TestCheckRepresentableRejectsAFileOfEightGiBOrMore(t *testing.T) {
	tooBig := []entry{
		{path: "usr/share/app/blob", kind: kindFile, size: 8 << 30},
		{path: "usr/share/app/blob", kind: kindFile, size: 8<<30 + 1},
		{path: "usr/share/app/blob", kind: kindFile, size: 1 << 40},
	}
	for _, e := range tooBig {
		err := checkRepresentable([]entry{
			{path: "usr/bin/app", kind: kindFile, size: 4096}, e})
		if err == nil {
			t.Errorf("size %d: accepted, want rejection", e.size)
			continue
		}
		for _, want := range []string{"usr/share/app/blob", "8 GiB", "§5.11", "4 GiB"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("size %d: error %q does not mention %q", e.size, err, want)
			}
		}
	}
}

func TestCheckRepresentableAcceptsUpToTheUstarLimit(t *testing.T) {
	ok := []entry{
		{path: "usr/bin/app", kind: kindFile, size: 0},
		{path: "usr/share/app/big", kind: kindFile, size: 8<<30 - 1},
		// Only a regular file has a body; a stray size on another kind
		// is not what is being checked.
		{path: "usr/share/app", kind: kindDir, size: 1 << 40},
		{path: "usr/bin/link", kind: kindSymlink, linkTarget: "app", size: 1 << 40},
	}
	if err := checkRepresentable(ok); err != nil {
		t.Errorf("checkRepresentable = %v, want every entry accepted", err)
	}
}
