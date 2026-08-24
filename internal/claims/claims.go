// Package claims computes claim materialisation (PSD-009 §4.4): given the
// installed packages and which package holds each role, it derives the
// set of symlinks that must exist, and diffs that against what exists to
// produce the create/repoint/remove plan a transaction applies.
//
// The package is pure — it touches neither the filesystem nor the
// database. The install layer feeds it manifests and holder records and
// turns its [Plan] into journalled file operations and database rows.
package claims

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/peios/peipkg/internal/manifest"
)

// Installed is one installed package's claim-relevant manifest data.
type Installed struct {
	Name     string
	Manifest manifest.Manifest
}

// RelativeTarget expresses a link's Target relative to the directory that
// contains its Path — the body to write into the on-disk symlink. Both Path
// and Target are absolute, in-root logical paths (a claim target is always an
// owned payload file of the holder, so it never leaves the root), which makes
// the result a clean in-tree relative path. A relative link keeps a composed
// root self-contained: /init -> usr/sbin/prelude resolves correctly whether
// the root is mounted at / or examined off-mount (compose output, --root
// installs, container/image builds, the initramfs cpio before boot). The
// stored claim metadata keeps the absolute logical Target; only the physical
// symlink is relativised.
func RelativeTarget(link Link) (string, error) {
	rel, err := filepath.Rel(filepath.Dir(link.Path), link.Target)
	if err != nil {
		return "", fmt.Errorf(
			"peipkg/claims: relative target for %s -> %s: %w", link.Path, link.Target, err)
	}
	return rel, nil
}

// Link is a materialised claim symlink: the path it lives at, the role
// and slot it serves, and the target it points at (§4.4.4).
type Link struct {
	Path   string
	Role   string
	Slot   string
	Target string
}

// EligibleProvider reports whether pkg is an eligible provider of role —
// it has a provides entry for role declaring a target for at least one
// slot (§4.4.3). Only an eligible provider may hold a role.
func EligibleProvider(m manifest.Manifest, role string) bool {
	for _, p := range m.Provides {
		if p.Name != role {
			continue
		}
		for _, slot := range p.Claims {
			if slot.Target != "" {
				return true
			}
		}
	}
	return false
}

// ProvidedRoles returns, sorted, every role pkg is an eligible provider
// of (§4.4.3) — the roles install-time auto-claim and the claim flags
// range over.
func ProvidedRoles(m manifest.Manifest) []string {
	var roles []string
	seen := map[string]bool{}
	for _, p := range m.Provides {
		if seen[p.Name] {
			continue
		}
		if EligibleProvider(m, p.Name) {
			roles = append(roles, p.Name)
			seen[p.Name] = true
		}
	}
	sort.Strings(roles)
	return roles
}

// maxClaimPathsPerRole is the §5.A limit on the claim paths materialised
// for one role, counted across every slot the holder fills and every
// installed consumer that declares a path.
const maxClaimPathsPerRole = 256

// Desired computes the claim links that should exist, given the installed
// packages and the current holders (role -> holder package name). For
// each held role it materialises, per slot the holder fills, a link at
// every claim path — the union of the holder's default path and every
// installed consumer's declared path (§4.4.4). The result is sorted by
// path. It errors if two roles would claim the same path.
func Desired(installed []Installed, holders map[string]string) ([]Link, error) {
	byName := make(map[string]manifest.Manifest, len(installed))
	for _, p := range installed {
		byName[p.Name] = p.Manifest
	}

	result := map[string]Link{}
	roles := sortedKeys(holders)
	for _, role := range roles {
		// §5.A caps the claim paths materialised per role at 256. The
		// appendix is explicit that this is a materialisation limit
		// rather than a manifest one: it bounds the union computed
		// across every installed package declaring a path for the role,
		// which is precisely the quantity an adversary controls by
		// installing many consumer-only packages. This loop is the only
		// place that sees the true count.
		perRole := map[string]bool{}
		hm, ok := byName[holders[role]]
		if !ok {
			// The holder is not installed; a held role with no installed
			// holder cannot materialise. Defensive — the holder record
			// cascades away with its package.
			continue
		}
		hp := providesFor(hm, role)
		for slot, desc := range hp {
			if desc.Target == "" {
				continue // not a fillable slot
			}
			paths := map[string]bool{}
			if desc.Path != "" {
				paths[desc.Path] = true // provider default path
			}
			for _, p := range installed {
				for _, path := range consumerPaths(p.Manifest, role, slot) {
					paths[path] = true
				}
			}
			for path := range paths {
				perRole[path] = true
				link := Link{Path: path, Role: role, Slot: slot, Target: desc.Target}
				if prev, dup := result[path]; dup && prev != link {
					return nil, fmt.Errorf(
						"peipkg/claims: path %q is claimed by both role %q and role %q",
						path, prev.Role, role)
				}
				result[path] = link
			}
		}
		if len(perRole) > maxClaimPathsPerRole {
			return nil, fmt.Errorf(
				"peipkg/claims: role %q materialises %d claim paths, the limit is %d",
				role, len(perRole), maxClaimPathsPerRole)
		}
	}
	return sortLinks(result), nil
}

// Plan is the difference between the actual and desired link sets: the
// links to create, repoint (same path, changed target/role/slot), and
// remove (§4.4.4). Each list is sorted by path.
type Plan struct {
	Create  []Link
	Repoint []Link
	Remove  []Link
}

// Empty reports whether the plan changes nothing.
func (p Plan) Empty() bool {
	return len(p.Create) == 0 && len(p.Repoint) == 0 && len(p.Remove) == 0
}

// Reconcile diffs desired against actual and returns the plan that makes
// the on-disk link set equal the desired set.
func Reconcile(actual, desired []Link) Plan {
	actualByPath := indexByPath(actual)
	desiredByPath := indexByPath(desired)

	var plan Plan
	for _, d := range desired {
		switch a, ok := actualByPath[d.Path]; {
		case !ok:
			plan.Create = append(plan.Create, d)
		case a != d:
			plan.Repoint = append(plan.Repoint, d)
		}
	}
	for _, a := range actual {
		if _, ok := desiredByPath[a.Path]; !ok {
			plan.Remove = append(plan.Remove, a)
		}
	}
	return plan
}

// providesFor returns the claims map of m's provides entry for role, or
// nil when m does not provide role (or declares no claims for it).
func providesFor(m manifest.Manifest, role string) map[string]manifest.ClaimSlot {
	for _, p := range m.Provides {
		if p.Name == role {
			return p.Claims
		}
	}
	return nil
}

// consumerPaths returns the claim paths m declares, as a consumer, for
// the given role and slot — across both its required and optional
// dependencies (§4.4.2).
func consumerPaths(m manifest.Manifest, role, slot string) []string {
	var paths []string
	for _, group := range [][]manifest.Dependency{m.Dependencies, m.OptionalDependencies} {
		for _, dep := range group {
			if dep.Name != role {
				continue
			}
			if cs, ok := dep.Claims[slot]; ok && cs.Path != "" {
				paths = append(paths, cs.Path)
			}
		}
	}
	return paths
}

func indexByPath(links []Link) map[string]Link {
	m := make(map[string]Link, len(links))
	for _, l := range links {
		m[l.Path] = l
	}
	return m
}

func sortLinks(m map[string]Link) []Link {
	links := make([]Link, 0, len(m))
	for _, l := range m {
		links = append(links, l)
	}
	sort.Slice(links, func(i, j int) bool { return links[i].Path < links[j].Path })
	return links
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
