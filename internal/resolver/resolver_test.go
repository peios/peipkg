package resolver_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/resolver"
	"github.com/peios/peipkg/internal/version"
)

const primaryArch = "x86_64"

func ver(t *testing.T, s string) version.Version {
	t.Helper()
	v, err := version.Parse(s)
	if err != nil {
		t.Fatalf("version.Parse(%q): %v", s, err)
	}
	return v
}

// dep builds a dependency; an empty constraint means "any version".
func dep(t *testing.T, name, constraint string) manifest.Dependency {
	t.Helper()
	c := version.Constraint{}
	if constraint != "" {
		parsed, err := version.ParseConstraint(constraint)
		if err != nil {
			t.Fatalf("ParseConstraint(%q): %v", constraint, err)
		}
		c = parsed
	}
	return manifest.Dependency{Name: name, Constraint: c}
}

// cand builds an available candidate at the primary architecture, from
// the "official" repository.
func cand(t *testing.T, name, v string, deps ...manifest.Dependency) resolver.Candidate {
	t.Helper()
	return resolver.Candidate{
		Name: name, Version: ver(t, v), Architecture: primaryArch,
		Dependencies: deps, Repo: "official", RepoPriority: 10,
		URL: "/p/" + name, Hash: "hash-" + name,
	}
}

// inst builds an installed package at the primary architecture.
func inst(t *testing.T, name, v string, deps ...manifest.Dependency) resolver.Installed {
	t.Helper()
	return resolver.Installed{
		Name: name, Version: ver(t, v), Architecture: primaryArch, Dependencies: deps,
	}
}

func defaultOptions() resolver.Options {
	return resolver.Options{PrimaryArch: primaryArch}
}

// summary renders a plan as "kind name" strings, in order.
func summary(p resolver.Plan) []string {
	kinds := map[resolver.OpKind]string{
		resolver.OpInstall: "install", resolver.OpUpgrade: "upgrade",
		resolver.OpDowngrade: "downgrade", resolver.OpRemove: "remove",
	}
	out := make([]string, len(p.Operations))
	for i, op := range p.Operations {
		out[i] = kinds[op.Kind] + " " + op.Name
	}
	return out
}

func assertRejection(t *testing.T, err error, want resolver.RejectReason) {
	t.Helper()
	var rej *resolver.Rejection
	if !errors.As(err, &rej) {
		t.Fatalf("expected a *Rejection, got %v", err)
	}
	if rej.Reason != want {
		t.Errorf("rejection reason: got %d, want %d (%s)", rej.Reason, want, rej.Detail)
	}
}

func TestInstallSimple(t *testing.T) {
	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "nginx"}},
		nil,
		[]resolver.Candidate{cand(t, "nginx", "1.0-1")},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := summary(plan); !slices.Equal(got, []string{"install nginx"}) {
		t.Errorf("plan: got %v", got)
	}
}

func TestInstallOrdersDependenciesFirst(t *testing.T) {
	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "nginx"}},
		nil,
		[]resolver.Candidate{
			cand(t, "nginx", "1.0-1", dep(t, "libssl", "")),
			cand(t, "libssl", "3.0-1", dep(t, "libc", "")),
			cand(t, "libc", "2.39-1"),
		},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Dependencies must precede their dependents.
	if got := summary(plan); !slices.Equal(got,
		[]string{"install libc", "install libssl", "install nginx"}) {
		t.Errorf("plan order: got %v", got)
	}
}

func TestInstallSharedDependencyAppearsOnce(t *testing.T) {
	plan, err := resolver.Resolve(
		[]resolver.Request{
			{Kind: resolver.Install, Name: "alpha"},
			{Kind: resolver.Install, Name: "bravo"},
		},
		nil,
		[]resolver.Candidate{
			cand(t, "alpha", "1.0-1", dep(t, "libc", "")),
			cand(t, "bravo", "1.0-1", dep(t, "libc", "")),
			cand(t, "libc", "2.39-1"),
		},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	libc := 0
	for _, op := range plan.Operations {
		if op.Name == "libc" {
			libc++
		}
	}
	if libc != 1 {
		t.Errorf("shared dependency libc appears %d times, want 1", libc)
	}
}

func TestInstallUsesSatisfyingInstalledDependency(t *testing.T) {
	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "nginx"}},
		[]resolver.Installed{inst(t, "libc", "2.39-1")},
		[]resolver.Candidate{
			cand(t, "nginx", "1.0-1", dep(t, "libc", ">= 2.39-1")),
			cand(t, "libc", "2.39-1"),
		},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// libc already satisfies the constraint: only nginx is installed.
	if got := summary(plan); !slices.Equal(got, []string{"install nginx"}) {
		t.Errorf("plan: got %v, want [install nginx]", got)
	}
}

func TestInstallForcesDependencyUpgrade(t *testing.T) {
	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "nginx"}},
		[]resolver.Installed{inst(t, "libc", "2.39-1")},
		[]resolver.Candidate{
			cand(t, "nginx", "1.0-1", dep(t, "libc", ">= 2.40-1")),
			cand(t, "libc", "2.40-1"),
		},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := summary(plan); !slices.Equal(got, []string{"upgrade libc", "install nginx"}) {
		t.Errorf("plan: got %v, want [upgrade libc, install nginx]", got)
	}
}

func TestInstallUnsatisfiableConstraint(t *testing.T) {
	_, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "nginx"}},
		nil,
		[]resolver.Candidate{
			cand(t, "nginx", "1.0-1", dep(t, "libc", ">= 99.0-1")),
			cand(t, "libc", "2.39-1"),
		},
		defaultOptions())
	assertRejection(t, err, resolver.ReasonUnsatisfiable)
}

func TestInstallViaProvides(t *testing.T) {
	postfix := cand(t, "postfix", "3.8-1")
	smtpVer := ver(t, "3.0-1")
	postfix.Provides = []manifest.Provides{{Name: "smtp-server", Version: &smtpVer}}

	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "mailapp"}},
		nil,
		[]resolver.Candidate{
			cand(t, "mailapp", "1.0-1", dep(t, "smtp-server", ">= 2.0-1")),
			postfix,
		},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := summary(plan); !slices.Equal(got, []string{"install postfix", "install mailapp"}) {
		t.Errorf("plan: got %v, want [install postfix, install mailapp]", got)
	}
}

func TestInstallConflict(t *testing.T) {
	apache := cand(t, "apache", "2.4-1")
	apache.Conflicts = []manifest.Dependency{dep(t, "nginx", "")}

	_, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "apache"}},
		[]resolver.Installed{inst(t, "nginx", "1.0-1")},
		[]resolver.Candidate{apache},
		defaultOptions())
	assertRejection(t, err, resolver.ReasonConflict)
}

func TestInstallCycleRejected(t *testing.T) {
	_, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "alpha"}},
		nil,
		[]resolver.Candidate{
			cand(t, "alpha", "1.0-1", dep(t, "bravo", "")),
			cand(t, "bravo", "1.0-1", dep(t, "alpha", "")),
		},
		defaultOptions())
	assertRejection(t, err, resolver.ReasonCycle)
}

func TestUpgrade(t *testing.T) {
	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Upgrade, Name: "libc"}},
		[]resolver.Installed{inst(t, "libc", "2.39-1")},
		[]resolver.Candidate{cand(t, "libc", "2.40-1")},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := summary(plan); !slices.Equal(got, []string{"upgrade libc"}) {
		t.Errorf("plan: got %v, want [upgrade libc]", got)
	}
	if op := plan.Operations[0]; op.FromVersion.String() != "2.39-1" || op.ToVersion.String() != "2.40-1" {
		t.Errorf("upgrade versions: %s -> %s", op.FromVersion, op.ToVersion)
	}
}

func TestUpgradeAll(t *testing.T) {
	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Upgrade}}, // empty name = all
		[]resolver.Installed{inst(t, "libc", "2.39-1"), inst(t, "nginx", "1.0-1")},
		[]resolver.Candidate{cand(t, "libc", "2.40-1"), cand(t, "nginx", "1.1-1")},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(plan.Operations) != 2 {
		t.Errorf("upgrade-all: got %d operations, want 2 (%v)", len(plan.Operations), summary(plan))
	}
}

func TestDowngrade(t *testing.T) {
	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Downgrade, Name: "libc", Version: ver(t, "2.39-1")}},
		[]resolver.Installed{inst(t, "libc", "2.40-1")},
		[]resolver.Candidate{cand(t, "libc", "2.39-1"), cand(t, "libc", "2.40-1")},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := summary(plan); !slices.Equal(got, []string{"downgrade libc"}) {
		t.Errorf("plan: got %v, want [downgrade libc]", got)
	}
}

func TestRemove(t *testing.T) {
	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Remove, Name: "nginx"}},
		[]resolver.Installed{inst(t, "nginx", "1.0-1"), inst(t, "libc", "2.39-1")},
		nil,
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := summary(plan); !slices.Equal(got, []string{"remove nginx"}) {
		t.Errorf("plan: got %v, want [remove nginx]", got)
	}
}

func TestRemoveCascade(t *testing.T) {
	opts := defaultOptions()
	opts.CascadeRemovals = true
	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Remove, Name: "libc"}},
		[]resolver.Installed{
			inst(t, "libc", "2.39-1"),
			inst(t, "nginx", "1.0-1", dep(t, "libc", "")),
		},
		nil,
		opts)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// The dependent is removed before the dependency.
	if got := summary(plan); !slices.Equal(got, []string{"remove nginx", "remove libc"}) {
		t.Errorf("cascade plan: got %v, want [remove nginx, remove libc]", got)
	}
}

func TestRemoveRefusedWithoutCascade(t *testing.T) {
	_, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Remove, Name: "libc"}},
		[]resolver.Installed{
			inst(t, "libc", "2.39-1"),
			inst(t, "nginx", "1.0-1", dep(t, "libc", "")),
		},
		nil,
		defaultOptions())
	assertRejection(t, err, resolver.ReasonRemovalBlocked)
}

func TestNoarchInstalls(t *testing.T) {
	docs := cand(t, "peios-docs", "1.0-1")
	docs.Architecture = "noarch"
	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "peios-docs"}},
		nil,
		[]resolver.Candidate{docs},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := summary(plan); !slices.Equal(got, []string{"install peios-docs"}) {
		t.Errorf("plan: got %v", got)
	}
}

func TestDeterministic(t *testing.T) {
	reqs := []resolver.Request{{Kind: resolver.Install, Name: "nginx"}}
	installed := []resolver.Installed{inst(t, "libc", "2.39-1")}
	available := []resolver.Candidate{
		cand(t, "nginx", "1.0-1", dep(t, "libssl", "")),
		cand(t, "libssl", "3.0-1", dep(t, "libc", "")),
		cand(t, "libc", "2.39-1"),
	}
	first, err := resolver.Resolve(reqs, installed, available, defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for i := 0; i < 5; i++ {
		again, err := resolver.Resolve(reqs, installed, available, defaultOptions())
		if err != nil {
			t.Fatalf("Resolve (repeat): %v", err)
		}
		if !slices.Equal(summary(first), summary(again)) {
			t.Fatalf("resolution is not deterministic: %v vs %v",
				summary(first), summary(again))
		}
	}
}

// opRepo returns the repository of the candidate chosen for the named
// package's operation, or "" when the package has no operation.
func opRepo(p resolver.Plan, name string) string {
	for _, op := range p.Operations {
		if op.Name == name && op.Candidate != nil {
			return op.Candidate.Repo
		}
	}
	return ""
}

func TestSelectionRule2PrefersDependerRepo(t *testing.T) {
	// app (repo "official", priority 10) depends on lib. lib is offered
	// by "official" at 1.0-1 and by "extra" (equal priority) at 2.0-1.
	// §4.2.4 rule 2: the depender's own repository wins over the higher
	// version, because "official" is at least as high-priority as "extra".
	app := cand(t, "app", "1.0-1", dep(t, "lib", ""))
	libOfficial := cand(t, "lib", "1.0-1")
	libExtra := cand(t, "lib", "2.0-1")
	libExtra.Repo, libExtra.RepoPriority = "extra", 10

	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "app"}},
		nil,
		[]resolver.Candidate{app, libOfficial, libExtra},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if repo := opRepo(plan, "lib"); repo != "official" {
		t.Errorf("rule 2: lib chosen from %q, want \"official\" (the depender's repo)", repo)
	}
}

func TestSelectionRule2BoundedByPriority(t *testing.T) {
	// A low-priority depender does not pull its own repository's
	// candidate over a higher-trust alternative: §4.2.4 rule 2 does not
	// apply when the depender's repo is lower-priority than the
	// cross-repository candidate, so rule 3 selects the higher-priority
	// repository instead.
	app := cand(t, "app", "1.0-1", dep(t, "lib", ""))
	app.Repo, app.RepoPriority = "extra", 50
	libExtra := cand(t, "lib", "1.0-1")
	libExtra.Repo, libExtra.RepoPriority = "extra", 50
	libOfficial := cand(t, "lib", "2.0-1") // "official", priority 10

	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "app"}},
		nil,
		[]resolver.Candidate{app, libExtra, libOfficial},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if repo := opRepo(plan, "lib"); repo != "official" {
		t.Errorf("rule 2 bound: lib chosen from %q, want \"official\" (higher-priority repo)", repo)
	}
}
