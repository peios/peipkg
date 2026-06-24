package resolver_test

import (
	"slices"
	"testing"

	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/resolver"
)

// depRoot builds a dependency placed in a named root (§4.1.1).
func depRoot(t *testing.T, name, constraint, root string) manifest.Dependency {
	t.Helper()
	d := dep(t, name, constraint)
	d.Root = root
	return d
}

// summaryRoot renders a plan as "kind name@root" strings, in order, so a
// test can assert both placement and ordering.
func summaryRoot(p resolver.Plan) []string {
	kinds := map[resolver.OpKind]string{
		resolver.OpInstall: "install", resolver.OpUpgrade: "upgrade",
		resolver.OpDowngrade: "downgrade", resolver.OpRemove: "remove",
	}
	out := make([]string, len(p.Operations))
	for i, op := range p.Operations {
		out[i] = kinds[op.Kind] + " " + op.Name + "@" + op.Root
	}
	return out
}

// indexOf returns the position of "kind name@root" in a plan summary, or
// -1. Used to assert relative ordering.
func indexOf(sum []string, entry string) int {
	return slices.Index(sum, entry)
}

// TestCrossRootExplicitPlacement: a package in "/" with a dependency
// declared `IN initramfs` pulls that dependency into the initramfs root,
// and the dependency is ordered before the dependent that needs it.
func TestCrossRootExplicitPlacement(t *testing.T) {
	liveBoot := cand(t, "live-boot", "1.0-1", depRoot(t, "busybox", "", "initramfs"))
	plan, err := resolver.ResolveMultiRoot(
		[]resolver.Request{{Kind: resolver.Install, Name: "live-boot", Root: "/"}},
		map[string][]resolver.Installed{"/": nil, "/irf": nil},
		[]resolver.Candidate{liveBoot, cand(t, "busybox", "1.0-1")},
		map[string]string{"initramfs": "/irf"},
		defaultOptions())
	if err != nil {
		t.Fatalf("ResolveMultiRoot: %v", err)
	}
	sum := summaryRoot(plan)
	if indexOf(sum, "install busybox@/irf") < 0 {
		t.Errorf("busybox was not placed in the initramfs root: %v", sum)
	}
	if indexOf(sum, "install live-boot@/") < 0 {
		t.Errorf("live-boot was not placed in the anchor root: %v", sum)
	}
	if i, j := indexOf(sum, "install busybox@/irf"), indexOf(sum, "install live-boot@/"); i > j {
		t.Errorf("the cross-root dependency must be ordered before its dependent: %v", sum)
	}
}

// TestCrossRootDependerDefault: a package installed directly into the
// initramfs root pulls its ordinary (un-annotated) dependencies into that
// same root — a closure flows into the root that occupies it.
func TestCrossRootDependerDefault(t *testing.T) {
	app := cand(t, "app", "1.0-1", dep(t, "libz", ""))
	plan, err := resolver.ResolveMultiRoot(
		[]resolver.Request{{Kind: resolver.Install, Name: "app", Root: "/irf"}},
		map[string][]resolver.Installed{"/irf": nil},
		[]resolver.Candidate{app, cand(t, "libz", "1.0-1")},
		map[string]string{},
		defaultOptions())
	if err != nil {
		t.Fatalf("ResolveMultiRoot: %v", err)
	}
	want := []string{"install libz@/irf", "install app@/irf"}
	if got := summaryRoot(plan); !slices.Equal(got, want) {
		t.Errorf("dependency closure did not flow into the depender's root:\ngot  %v\nwant %v", got, want)
	}
}

// TestSameNameVersionInTwoRootsIsNotAConflict: the identical package
// installed into two roots is two independent installs (DESIGN: identity
// is (name, root)), never a self-conflict.
func TestSameNameVersionInTwoRootsIsNotAConflict(t *testing.T) {
	plan, err := resolver.ResolveMultiRoot(
		[]resolver.Request{
			{Kind: resolver.Install, Name: "glibc", Root: "/"},
			{Kind: resolver.Install, Name: "glibc", Root: "/irf"},
		},
		map[string][]resolver.Installed{"/": nil, "/irf": nil},
		[]resolver.Candidate{cand(t, "glibc", "2.43-1")},
		map[string]string{},
		defaultOptions())
	if err != nil {
		t.Fatalf("ResolveMultiRoot: %v", err)
	}
	sum := summaryRoot(plan)
	if indexOf(sum, "install glibc@/") < 0 || indexOf(sum, "install glibc@/irf") < 0 {
		t.Errorf("the same package should install independently into both roots: %v", sum)
	}
}

// TestDependencySatisfiedPerRoot: a dependency in root "/" is NOT
// satisfied by a same-named package installed in a different root — it
// must be installed into "/" too. Identity is per-root.
func TestDependencySatisfiedPerRoot(t *testing.T) {
	app := cand(t, "app", "1.0-1", dep(t, "libc", ">= 2.0"))
	plan, err := resolver.ResolveMultiRoot(
		[]resolver.Request{{Kind: resolver.Install, Name: "app", Root: "/"}},
		// libc is installed only in the initramfs root, not in "/".
		map[string][]resolver.Installed{"/": nil, "/irf": {inst(t, "libc", "2.5-1")}},
		[]resolver.Candidate{app, cand(t, "libc", "2.5-1")},
		map[string]string{},
		defaultOptions())
	if err != nil {
		t.Fatalf("ResolveMultiRoot: %v", err)
	}
	sum := summaryRoot(plan)
	if indexOf(sum, "install libc@/") < 0 {
		t.Errorf("libc must be installed into / despite existing in /irf: %v", sum)
	}
}

// TestCrossRootIndependentVersions: the same name may exist at different
// versions in two roots without a regression or conflict — an initramfs
// may legitimately lead or lag the real root.
func TestCrossRootIndependentVersions(t *testing.T) {
	// app@/ depends on libc within / ; libc@/irf is at a newer version and
	// must not interfere with resolving libc into /.
	app := cand(t, "app", "1.0-1", dep(t, "libc", ""))
	_, err := resolver.ResolveMultiRoot(
		[]resolver.Request{{Kind: resolver.Install, Name: "app", Root: "/"}},
		map[string][]resolver.Installed{
			"/":    {inst(t, "libc", "2.0-1")},
			"/irf": {inst(t, "libc", "9.0-1")},
		},
		[]resolver.Candidate{app},
		map[string]string{},
		defaultOptions())
	if err != nil {
		t.Fatalf("differing versions across roots should resolve cleanly: %v", err)
	}
}

// TestCrossRootUnregisteredRootRejected: a dependency placed in a root
// reference that is not registered is a hard rejection.
func TestCrossRootUnregisteredRootRejected(t *testing.T) {
	liveBoot := cand(t, "live-boot", "1.0-1", depRoot(t, "busybox", "", "ghost"))
	_, err := resolver.ResolveMultiRoot(
		[]resolver.Request{{Kind: resolver.Install, Name: "live-boot", Root: "/"}},
		map[string][]resolver.Installed{"/": nil},
		[]resolver.Candidate{liveBoot, cand(t, "busybox", "1.0-1")},
		map[string]string{"initramfs": "/irf"}, // "ghost" is not registered
		defaultOptions())
	if err == nil {
		t.Fatal("a dependency placed in an unregistered root should be rejected")
	}
	assertRejection(t, err, resolver.ReasonUnsatisfiable)
}

// TestSingleRootResolveIgnoresDependencyRoot: the single-root entry point
// is unaffected by a dependency's placement root — it has nowhere else to
// place a dependency, so the field is inert and the dependency stays in
// the one root. (Guards the "single-root call sites unchanged" contract.)
func TestSingleRootResolveIgnoresDependencyRoot(t *testing.T) {
	liveBoot := cand(t, "live-boot", "1.0-1", depRoot(t, "busybox", "", "initramfs"))
	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "live-boot"}},
		nil,
		[]resolver.Candidate{liveBoot, cand(t, "busybox", "1.0-1")},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Both land in the single (empty) root; the cross-root annotation is inert.
	want := []string{"install busybox@", "install live-boot@"}
	if got := summaryRoot(plan); !slices.Equal(got, want) {
		t.Errorf("single-root Resolve should ignore dependency root:\ngot  %v\nwant %v", got, want)
	}
}
