package claims_test

import (
	"testing"

	"github.com/peios/peipkg/internal/claims"
	"github.com/peios/peipkg/internal/manifest"
)

// provider builds an installed package that provides role with the given
// slot targets (and optional default paths).
func provider(name, role string, slots map[string]manifest.ClaimSlot) claims.Installed {
	return claims.Installed{
		Name: name,
		Manifest: manifest.Manifest{
			Name:     name,
			Provides: []manifest.Provides{{Name: role, Claims: slots}},
		},
	}
}

// consumer builds an installed package that depends on role declaring
// the given slot paths.
func consumer(name, role string, slots map[string]manifest.ClaimSlot, optional bool) claims.Installed {
	dep := manifest.Dependency{Name: role, Claims: slots}
	m := manifest.Manifest{Name: name}
	if optional {
		m.OptionalDependencies = []manifest.Dependency{dep}
	} else {
		m.Dependencies = []manifest.Dependency{dep}
	}
	return claims.Installed{Name: name, Manifest: m}
}

func TestDesiredConsumerPath(t *testing.T) {
	loregd := provider("loregd", "registryd",
		map[string]manifest.ClaimSlot{"binary": {Target: "/usr/bin/loregd"}})
	peinit := consumer("peinit", "registryd",
		map[string]manifest.ClaimSlot{"binary": {Path: "/usr/bin/registryd"}}, false)

	links, err := claims.Desired([]claims.Installed{loregd, peinit},
		map[string]string{"registryd": "loregd"})
	if err != nil {
		t.Fatalf("Desired: %v", err)
	}
	want := []claims.Link{{Path: "/usr/bin/registryd", Role: "registryd", Slot: "binary", Target: "/usr/bin/loregd"}}
	if !equalLinks(links, want) {
		t.Errorf("links: got %+v, want %+v", links, want)
	}
}

func TestDesiredHeldButUnmaterialised(t *testing.T) {
	// Holder, no default path, no consumer: the role is held but
	// materialises nothing (§4.4.4).
	loregd := provider("loregd", "registryd",
		map[string]manifest.ClaimSlot{"binary": {Target: "/usr/bin/loregd"}})
	links, err := claims.Desired([]claims.Installed{loregd},
		map[string]string{"registryd": "loregd"})
	if err != nil {
		t.Fatalf("Desired: %v", err)
	}
	if len(links) != 0 {
		t.Errorf("expected no links, got %+v", links)
	}
}

func TestDesiredProviderDefaultPath(t *testing.T) {
	loregd := provider("loregd", "registryd",
		map[string]manifest.ClaimSlot{"binary": {Target: "/usr/bin/loregd", Path: "/usr/bin/registryd"}})
	links, err := claims.Desired([]claims.Installed{loregd},
		map[string]string{"registryd": "loregd"})
	if err != nil {
		t.Fatalf("Desired: %v", err)
	}
	if len(links) != 1 || links[0].Path != "/usr/bin/registryd" {
		t.Errorf("links: got %+v", links)
	}
}

func TestDesiredRetroactiveAndMultiPath(t *testing.T) {
	// Two consumers declare different paths for the same slot; both
	// materialise against the one holder target (§4.4.4 union rule).
	loregd := provider("loregd", "registryd",
		map[string]manifest.ClaimSlot{"binary": {Target: "/usr/bin/loregd"}})
	a := consumer("svc-a", "registryd",
		map[string]manifest.ClaimSlot{"binary": {Path: "/usr/bin/registryd"}}, false)
	b := consumer("svc-b", "registryd",
		map[string]manifest.ClaimSlot{"binary": {Path: "/opt/registryd"}}, true)

	links, err := claims.Desired([]claims.Installed{loregd, a, b},
		map[string]string{"registryd": "loregd"})
	if err != nil {
		t.Fatalf("Desired: %v", err)
	}
	want := []claims.Link{
		{Path: "/opt/registryd", Role: "registryd", Slot: "binary", Target: "/usr/bin/loregd"},
		{Path: "/usr/bin/registryd", Role: "registryd", Slot: "binary", Target: "/usr/bin/loregd"},
	}
	if !equalLinks(links, want) {
		t.Errorf("links: got %+v, want %+v", links, want)
	}
}

func TestDesiredPathClaimedByTwoRoles(t *testing.T) {
	loregd := provider("loregd", "registryd",
		map[string]manifest.ClaimSlot{"binary": {Target: "/usr/bin/loregd", Path: "/usr/bin/x"}})
	other := provider("other", "altrole",
		map[string]manifest.ClaimSlot{"binary": {Target: "/usr/bin/other", Path: "/usr/bin/x"}})
	_, err := claims.Desired([]claims.Installed{loregd, other},
		map[string]string{"registryd": "loregd", "altrole": "other"})
	if err == nil {
		t.Fatal("expected a conflict error for the shared path")
	}
}

func TestReconcileDiff(t *testing.T) {
	stay := claims.Link{Path: "/a", Role: "r", Slot: "s", Target: "/t"}
	repointOld := claims.Link{Path: "/b", Role: "r", Slot: "s", Target: "/old"}
	repointNew := claims.Link{Path: "/b", Role: "r", Slot: "s", Target: "/new"}
	gone := claims.Link{Path: "/c", Role: "r", Slot: "s", Target: "/t"}
	fresh := claims.Link{Path: "/d", Role: "r", Slot: "s", Target: "/t"}

	plan := claims.Reconcile(
		[]claims.Link{stay, repointOld, gone},
		[]claims.Link{stay, repointNew, fresh},
	)
	if len(plan.Create) != 1 || plan.Create[0] != fresh {
		t.Errorf("Create: got %+v", plan.Create)
	}
	if len(plan.Repoint) != 1 || plan.Repoint[0] != repointNew {
		t.Errorf("Repoint: got %+v", plan.Repoint)
	}
	if len(plan.Remove) != 1 || plan.Remove[0] != gone {
		t.Errorf("Remove: got %+v", plan.Remove)
	}
}

func TestEligibleProviderAndProvidedRoles(t *testing.T) {
	m := manifest.Manifest{Provides: []manifest.Provides{
		{Name: "registryd", Claims: map[string]manifest.ClaimSlot{"binary": {Target: "/usr/bin/loregd"}}},
		{Name: "smtp-server"}, // a plain provides, no claims — not claimable
	}}
	if !claims.EligibleProvider(m, "registryd") {
		t.Error("registryd should be eligible")
	}
	if claims.EligibleProvider(m, "smtp-server") {
		t.Error("smtp-server has no claim target; not eligible")
	}
	roles := claims.ProvidedRoles(m)
	if len(roles) != 1 || roles[0] != "registryd" {
		t.Errorf("ProvidedRoles: got %+v", roles)
	}
}

func equalLinks(a, b []claims.Link) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRelativeTarget(t *testing.T) {
	cases := []struct{ path, target, want string }{
		{"/init", "/usr/sbin/prelude", "usr/sbin/prelude"},  // root link, target below
		{"/usr/bin/registryd", "/usr/bin/loregd", "loregd"}, // same directory
		{"/etc/foo", "/usr/lib/x/foo", "../usr/lib/x/foo"},  // cross-tree
	}
	for _, c := range cases {
		got, err := claims.RelativeTarget(claims.Link{Path: c.path, Target: c.target})
		if err != nil || got != c.want {
			t.Errorf("RelativeTarget(%s -> %s) = %q (err %v), want %q",
				c.path, c.target, got, err, c.want)
		}
	}
}
