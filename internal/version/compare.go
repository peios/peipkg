package version

import (
	"cmp"
	"strings"
)

// segmentKind distinguishes a numeric run of digits from an alphabetic
// run of letters.
type segmentKind uint8

const (
	numeric segmentKind = iota
	alphabetic
)

// segment is one token of a tokenised upstream version (§2.2.7.1).
type segment struct {
	kind segmentKind
	text string
	// preRelease marks the segment as part of the version's pre-release
	// tail (§2.2.7): it sits at or after the first `~` separator or the
	// first recognised pre-release token.
	preRelease bool
}

// tokenize splits an upstream version into segments per §2.2.7.1 and
// marks each as pre-release or not.
//
// A segment is pre-release once the walk has passed either a `~`
// separator or a recognised pre-release token; from that point every
// segment is pre-release. A `-` is an ordinary separator — it does not
// itself begin a pre-release tail (a `-` before `rc` produces a
// pre-release tail only because `rc` is a recognised token, never
// because of the `-`).
func tokenize(upstream string) []segment {
	var segments []segment
	preRelease := false

	for i := 0; i < len(upstream); {
		c := upstream[i]
		switch {
		case c == '~':
			preRelease = true // segments after a tilde are pre-release
			i++
		case c == '.' || c == '+' || c == '-':
			i++
		case isDigit(c):
			j := i
			for j < len(upstream) && isDigit(upstream[j]) {
				j++
			}
			segments = append(segments, segment{
				kind: numeric, text: upstream[i:j], preRelease: preRelease,
			})
			i = j
		default: // a run of letters
			j := i
			for j < len(upstream) && isLetter(upstream[j]) {
				j++
			}
			text := upstream[i:j]
			if preReleaseRank(text) < rankOther {
				preRelease = true // a recognised pre-release token begins the tail
			}
			segments = append(segments, segment{
				kind: alphabetic, text: text, preRelease: preRelease,
			})
			i = j
		}
	}
	return segments
}

// rankOther is the rank of an alphabetic segment that is not a
// recognised pre-release token (§2.2.7.2).
const rankOther = 5

// preReleaseRank returns the pre-release rank of an alphabetic segment
// (§2.2.7.2, §9.2). Recognised tokens rank 0-4; anything else ranks
// [rankOther]. Recognition is case-insensitive.
func preReleaseRank(s string) int {
	switch strings.ToLower(s) {
	case "dev":
		return 0
	case "alpha", "a":
		return 1
	case "beta", "b":
		return 2
	case "pre":
		return 3
	case "rc":
		return 4
	default:
		return rankOther
	}
}

// Compare orders two versions per §2.2.6: by epoch, then by the upstream
// comparison algorithm, then by revision. It returns -1, 0, or +1.
func Compare(a, b Version) int {
	if c := compareEpochUpstream(a, b); c != 0 {
		return c
	}
	return cmp.Compare(a.revision, b.revision)
}

// Equal reports whether v and other are the same version.
func (v Version) Equal(other Version) bool { return Compare(v, other) == 0 }

// Less reports whether v orders strictly before other.
func (v Version) Less(other Version) bool { return Compare(v, other) < 0 }

// compareEpochUpstream compares two versions by epoch and then by
// upstream version, ignoring the revision. The constraint matcher
// reuses it for operands whose revision was omitted.
func compareEpochUpstream(a, b Version) int {
	if a.epoch != b.epoch {
		return cmp.Compare(a.epoch, b.epoch)
	}
	return compareSegments(a.segments, b.segments)
}

// compareSegments compares two tokenised upstream versions per §2.2.7,
// including the end-of-string rule (§2.2.7.4) when one is shorter.
func compareSegments(a, b []segment) int {
	common := min(len(a), len(b))
	for i := 0; i < common; i++ {
		if c := compareSegment(a[i], b[i]); c != 0 {
			return c
		}
	}
	if len(a) == len(b) {
		return 0
	}

	// One sequence continues past the other; its next segment decides.
	longer, shorterIsA := a, false
	if len(b) > len(a) {
		longer, shorterIsA = b, true
	}
	next := longer[common]

	// shorterVsLonger is the comparison result of shorter against longer.
	shorterVsLonger := -1 // a numeric or non-pre-release tail makes the shorter side less
	if next.kind == alphabetic && next.preRelease {
		shorterVsLonger = 1 // a pre-release tail makes the shorter side greater
	}
	if shorterIsA {
		return shorterVsLonger
	}
	return -shorterVsLonger
}

// compareSegment compares two individual segments per §2.2.7.2.
func compareSegment(a, b segment) int {
	switch {
	case a.kind == numeric && b.kind == numeric:
		return compareNumeric(a.text, b.text)
	case a.kind == alphabetic && b.kind == alphabetic:
		ra, rb := preReleaseRank(a.text), preReleaseRank(b.text)
		if ra != rb {
			return cmp.Compare(ra, rb)
		}
		if ra == rankOther {
			return strings.Compare(a.text, b.text) // rank-5 tiebreak: ASCII byte order
		}
		return 0 // same recognised rank — aliases are equivalent
	case a.kind == numeric: // b is alphabetic
		if b.preRelease {
			return 1 // a pre-release alphabetic segment is less than a numeric one
		}
		return -1
	default: // a is alphabetic, b is numeric
		if a.preRelease {
			return -1
		}
		return 1
	}
}

// compareNumeric compares two non-empty decimal digit strings as
// integers, ignoring leading zeros. It works on the strings directly,
// so an arbitrarily long numeric segment cannot overflow.
func compareNumeric(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return cmp.Compare(len(a), len(b))
	}
	return strings.Compare(a, b)
}

func isDigit(c byte) bool        { return c >= '0' && c <= '9' }
func isLetter(c byte) bool       { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isAlphanumeric(c byte) bool { return isDigit(c) || isLetter(c) }
