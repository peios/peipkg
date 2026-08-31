// Package layout holds the path invariants that hold for every package
// path in every phase — the ones no flag, waiver, or package
// declaration can turn off.
//
// It exists as its own package because the same rule has to be applied
// by the producer's validator, the installer's staging, compose's
// assembly, and the manifest decoder, and those cannot all import one
// another.
package layout

import (
	"fmt"
	"path"
	"strings"
)

// forbiddenPrefixes are the trees a package path may never reach,
// whatever else permits it.
//
// PSPU §5.14: "`/lcl/policy` MUST NOT be reachable by this route under
// any circumstance. It is the tree whose contents grant authority, and
// an exemption that could reach it would convert a structural guarantee
// into a policy one." §5.23 repeats the rule for claim paths.
//
// The sentence is absolute, so the check must not be reachable-around.
// It cannot live behind the special-system-package waiver, which is
// exactly the route §5.14's own note describes; and it cannot live only
// in the payload rules, because a `provides` claim path is deliberately
// exempt from those.
var forbiddenPrefixes = []string{
	"lcl/policy",
}

// Forbidden reports whether p — a payload path relative to an
// installation root, with no leading slash — is inside a forbidden
// tree, and names the tree if so.
//
// The tree's own directory and the directories beneath it are NOT
// forbidden, and that is deliberate. What §5.14 protects is the tree
// "whose contents grant authority": an empty directory grants nothing,
// and something has to mint the skeleton — on Peios that is fsbase,
// which ships `lcl/policy/autorun.d` and `lcl/policy/autoapply.d` as
// empty-directory payload entries and is the archetype §5.14 has in
// mind when it describes special system packages. Arbitrary code at
// boot needs a *file* in autorun.d, and a file is what this refuses.
//
// See [Check] for the one caller that has no entry kind to consult.
func Forbidden(p string) (string, bool) {
	clean := strings.TrimPrefix(path.Clean("/"+p), "/")
	for _, f := range forbiddenPrefixes {
		if clean == f || strings.HasPrefix(clean, f+"/") {
			return "/" + f, true
		}
	}
	return "", false
}

// CheckEntry returns an error naming the tree when a payload entry of
// this kind at this path is forbidden. isDir exempts a directory, which
// carries no content and therefore grants no authority.
func CheckEntry(p string, isDir bool) error {
	tree, bad := Forbidden(p)
	if !bad || isDir {
		return nil
	}
	return fmt.Errorf("%q is under %s, which no package may put content into under any "+
		"circumstance: it is the tree whose contents grant authority (PSPU §5.14). "+
		"An empty directory there is permitted; a file or a symbolic link is not",
		p, tree)
}

// Check is [CheckEntry] for a path with no entry kind — a claim path,
// where the thing materialised is always a symbolic link and so is
// always content.
func Check(p string) error {
	return CheckEntry(p, false)
}
