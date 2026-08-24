package claims_test

import (
	"fmt"
	"testing"

	"github.com/peios/peipkg/internal/claims"
	"github.com/peios/peipkg/internal/manifest"
)

// PSPU §5.A caps the claim paths materialised per role at 256, and the
// appendix is explicit that this is a materialisation limit rather than a
// manifest one: it bounds the union across every installed package
// declaring a path for the role.
//
// Slots-per-field was enforced (maxClaimSlots = 64) but this was not, so
// the quantity an adversary actually controls — install many
// consumer-only packages, each declaring a handful of paths for one
// popular role — was unbounded symlink creation in a single transaction.
func TestClaimPathsPerRoleAreCapped(t *testing.T) {
	// consumersDeclaring builds n consumer packages, each declaring
	// perConsumer distinct paths for one role, across several slots so
	// the count has to be summed per *role* rather than per slot.
	build := func(n, perConsumer int) []claims.Installed {
		slots := map[string]manifest.ClaimSlot{}
		for s := range 4 {
			slots[fmt.Sprintf("slot%d", s)] = manifest.ClaimSlot{
				Target: fmt.Sprintf("/usr/sbin/impl%d", s),
			}
		}
		installed := []claims.Installed{provider("impl", "role", slots)}
		for c := range n {
			cs := map[string]manifest.ClaimSlot{}
			for i := range perConsumer {
				cs[fmt.Sprintf("slot%d", i%4)] = manifest.ClaimSlot{
					Path: fmt.Sprintf("/usr/sbin/c%d-p%d", c, i),
				}
			}
			installed = append(installed, claims.Installed{
				Name: fmt.Sprintf("consumer%d", c),
				Manifest: manifest.Manifest{
					Name:         fmt.Sprintf("consumer%d", c),
					Dependencies: []manifest.Dependency{{Name: "role", Claims: cs}},
				},
			})
		}
		return installed
	}

	holders := map[string]string{"role": "impl"}

	// 100 consumers x 4 paths each, plus the provider's own defaults:
	// comfortably over 256 once unioned, and no single manifest is
	// anywhere near a limit of its own.
	links, err := claims.Desired(build(100, 4), holders)
	if err == nil {
		t.Fatalf("Desired materialised %d links for one role with no limit applied", len(links))
	}

	// Well under the cap, the same shape must still work.
	if _, err := claims.Desired(build(10, 4), holders); err != nil {
		t.Fatalf("Desired rejected a modest claim set: %v", err)
	}
}

// The limit is per role, so two roles may each materialise up to the cap
// without either being rejected.
func TestTheClaimPathLimitIsPerRoleNotGlobal(t *testing.T) {
	build := func(role string, n int) []claims.Installed {
		slots := map[string]manifest.ClaimSlot{"s": {Target: "/usr/sbin/" + role}}
		installed := []claims.Installed{provider(role+"-impl", role, slots)}
		for c := range n {
			installed = append(installed, claims.Installed{
				Name: fmt.Sprintf("%s-c%d", role, c),
				Manifest: manifest.Manifest{
					Name: fmt.Sprintf("%s-c%d", role, c),
					Dependencies: []manifest.Dependency{{Name: role, Claims: map[string]manifest.ClaimSlot{
						"s": {Path: fmt.Sprintf("/usr/sbin/%s-p%d", role, c)},
					}}},
				},
			})
		}
		return installed
	}

	var installed []claims.Installed
	installed = append(installed, build("alpha", 200)...)
	installed = append(installed, build("beta", 200)...)
	holders := map[string]string{"alpha": "alpha-impl", "beta": "beta-impl"}

	// 400 paths in total, but only 200 for either role. The provider
	// contributes none of its own here: it declares a Target without a
	// default Path.
	links, err := claims.Desired(installed, holders)
	if err != nil {
		t.Fatalf("Desired rejected two roles each inside the cap: %v", err)
	}
	if len(links) != 400 {
		t.Errorf("links: got %d, want 400 (200 per role)", len(links))
	}
}
