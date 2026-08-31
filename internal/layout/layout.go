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
// The prefix matches the directory itself as well as anything under it:
// creating `lcl/policy` is as much a way to own what lands there as
// writing into it.
func Forbidden(p string) (string, bool) {
	clean := strings.TrimPrefix(path.Clean("/"+p), "/")
	for _, f := range forbiddenPrefixes {
		if clean == f || strings.HasPrefix(clean, f+"/") {
			return "/" + f, true
		}
	}
	return "", false
}

// Check returns an error naming the tree when p is forbidden. p is a
// payload path relative to an installation root; a leading slash is
// tolerated so an absolute claim path can be passed straight in.
func Check(p string) error {
	if tree, bad := Forbidden(p); bad {
		return fmt.Errorf("%q is under %s, which no package may write to under any "+
			"circumstance: it is the tree whose contents grant authority (PSPU §5.14)",
			p, tree)
	}
	return nil
}
