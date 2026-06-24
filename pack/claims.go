package pack

import (
	"fmt"
	"sort"
	"strings"
)

// ValidateClaimTargets enforces the in-root, provider-owns-its-target
// invariant for claims (§4.4): every provider claim slot's Target must name a
// file this package itself ships. files is the payload destination -> source
// map [Pack] packs; claim targets are absolute logical paths while payload
// destinations are root-relative, so a target is owned when its leading "/"
// trims to a destination key.
//
// A target outside the package's own payload is a packaging bug — the
// materialised claim symlink would dangle or point at another package's (or
// the host's) file. Keeping targets in-root is also what lets the symlink be
// materialised relative (see claims.RelativeTarget), so this guard backs the
// relocatability the relative links rely on. Like the other pack validators it
// is opt-in and aggregates every offender into one error.
func ValidateClaimTargets(provides []Provides, files map[string]string) error {
	var errs []string
	for _, p := range provides {
		slots := make([]string, 0, len(p.Claims))
		for slot := range p.Claims {
			slots = append(slots, slot)
		}
		sort.Strings(slots)
		for _, slot := range slots {
			target := p.Claims[slot].Target
			if target == "" {
				continue // a consumer-side or path-only slot owns no target
			}
			if _, ok := files[strings.TrimPrefix(target, "/")]; !ok {
				errs = append(errs, fmt.Sprintf(
					"provides %q slot %q: target %s is not a file this package ships",
					p.Name, slot, target))
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("peipkg/pack: claim target ownership: %s", strings.Join(errs, "; "))
	}
	return nil
}
