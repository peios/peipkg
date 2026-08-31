package resolver_test

import (
	"errors"
	"slices"
	"strings"
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

func TestDependencySelectionKeepsSameVersionRepositoryPriority(t *testing.T) {
	app := cand(t, "app", "1.0-1", dep(t, "libfoo", ""))
	low := cand(t, "libfoo", "1.0-1")
	low.Repo, low.RepoPriority, low.URL = "extra", 50, "/extra/libfoo"
	high := cand(t, "libfoo", "1.0-1")
	high.Repo, high.RepoPriority, high.URL = "official", 10, "/official/libfoo"

	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "app"}},
		nil,
		[]resolver.Candidate{app, low, high},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, op := range plan.Operations {
		if op.Name == "libfoo" {
			if op.Candidate == nil || op.Candidate.Repo != "official" {
				t.Fatalf("libfoo candidate = %+v, want official", op.Candidate)
			}
			return
		}
	}
	t.Fatalf("plan did not install libfoo: %+v", plan.Operations)
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

func TestNoarchDependsOnArchSpecific(t *testing.T) {
	// §4.1.3: a noarch depender's effective architecture is the system's
	// primary architecture — its deps on arch-specific packages resolve
	// like a native package's (the build-essentials / script→interpreter
	// shape).
	meta := cand(t, "build-meta", "1.0-1", dep(t, "binutils", ""))
	meta.Architecture = "noarch"
	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "build-meta"}},
		nil,
		[]resolver.Candidate{meta, cand(t, "binutils", "2.46-1")},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := summary(plan); !slices.Equal(got, []string{"install binutils", "install build-meta"}) {
		t.Errorf("plan: got %v, want [install binutils, install build-meta]", got)
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

func TestLowTrustProvidesRaisesAuthorization(t *testing.T) {
	// mailapp depends on smtp-server >= 2.0-1. The "official" repo has a
	// package literally named smtp-server, but only at 1.0-1 — it fails
	// the constraint. A lower-priority repo's postfix provides
	// smtp-server 3.0-1. Choosing postfix shadows the official
	// name-match, so §4.2.4 requires explicit operator authorisation.
	mailapp := cand(t, "mailapp", "1.0-1", dep(t, "smtp-server", ">= 2.0-1"))
	smtpOfficial := cand(t, "smtp-server", "1.0-1") // "official", priority 10
	postfix := cand(t, "postfix", "3.8-1")
	postfix.Repo, postfix.RepoPriority = "extra", 50
	pv := ver(t, "3.0-1")
	postfix.Provides = []manifest.Provides{{Name: "smtp-server", Version: &pv}}

	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "mailapp"}},
		nil,
		[]resolver.Candidate{mailapp, smtpOfficial, postfix},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(plan.Authorizations) != 1 ||
		plan.Authorizations[0].Kind != resolver.AuthLowTrustProvides {
		t.Fatalf("expected one AuthLowTrustProvides, got %#v", plan.Authorizations)
	}
}

func TestReplacesSupersedesInstalled(t *testing.T) {
	// nginx supersedes the renamed nginx-core (§4.1.5). Installing nginx
	// removes nginx-core and installs nginx in its place.
	nginx := cand(t, "nginx", "1.26-1")
	nginx.Replaces = []manifest.Replaces{{Name: "nginx-core"}}

	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "nginx"}},
		[]resolver.Installed{inst(t, "nginx-core", "1.20-1")},
		[]resolver.Candidate{nginx},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := summary(plan); !slices.Equal(got, []string{"remove nginx-core", "install nginx"}) {
		t.Errorf("plan: got %v, want [remove nginx-core, install nginx]", got)
	}
	if len(plan.Authorizations) != 0 {
		t.Errorf("unexpected authorizations: %#v", plan.Authorizations)
	}
}

func TestForeignReplacesRaisesAuthorization(t *testing.T) {
	// A package from a low-priority repository replacing one installed
	// from a higher-priority repository is an elevated action (§6.5.7).
	nginx := cand(t, "nginx", "1.26-1")
	nginx.Repo, nginx.RepoPriority = "extra", 50
	nginx.Replaces = []manifest.Replaces{{Name: "nginx-core"}}
	core := inst(t, "nginx-core", "1.20-1")
	core.Repo, core.RepoPriority = "official", 10

	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "nginx"}},
		[]resolver.Installed{core},
		[]resolver.Candidate{nginx},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(plan.Authorizations) != 1 ||
		plan.Authorizations[0].Kind != resolver.AuthForeignReplaces {
		t.Fatalf("expected one AuthForeignReplaces, got %#v", plan.Authorizations)
	}
}

func TestForeignReplacesStillRaisedAfterVictimUpgradeSelection(t *testing.T) {
	// A mixed transaction can first select an upgrade candidate for the
	// victim, then later supersede it via `replaces`. The installed
	// repository provenance must survive that candidate placement so the
	// foreign-replaces gate still sees the original higher-priority source.
	nginx := cand(t, "nginx", "1.26-1")
	nginx.Repo, nginx.RepoPriority = "extra", 50
	nginx.Replaces = []manifest.Replaces{{Name: "nginx-core"}}
	coreUpgrade := cand(t, "nginx-core", "1.21-1")
	core := inst(t, "nginx-core", "1.20-1")
	core.Repo, core.RepoPriority = "official", 10

	plan, err := resolver.Resolve(
		[]resolver.Request{
			{Kind: resolver.Upgrade},
			{Kind: resolver.Install, Name: "nginx"},
		},
		[]resolver.Installed{core},
		[]resolver.Candidate{coreUpgrade, nginx},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(plan.Authorizations) != 1 ||
		plan.Authorizations[0].Kind != resolver.AuthForeignReplaces {
		t.Fatalf("expected one AuthForeignReplaces, got %#v", plan.Authorizations)
	}
}

func TestDowngradeRaisesAuthorization(t *testing.T) {
	// Moving a package backward is an elevated action (§7.2.5, §7.6.6).
	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Downgrade, Name: "libc", Version: ver(t, "2.39-1")}},
		[]resolver.Installed{inst(t, "libc", "2.40-1")},
		[]resolver.Candidate{cand(t, "libc", "2.39-1"), cand(t, "libc", "2.40-1")},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(plan.Authorizations) != 1 ||
		plan.Authorizations[0].Kind != resolver.AuthDowngrade {
		t.Fatalf("expected one AuthDowngrade, got %#v", plan.Authorizations)
	}
}

// A goal may name a role rather than a concrete package: nothing is named
// "coreutils", but coreutils-gnu provides it (§4.2.3).
func TestInstallGoalResolvesViaProvides(t *testing.T) {
	gnu := cand(t, "coreutils-gnu", "9.9-1")
	roleVer := ver(t, "9.9-1")
	gnu.Provides = []manifest.Provides{{Name: "coreutils", Version: &roleVer}}

	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "coreutils"}},
		nil, []resolver.Candidate{gnu}, defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := summary(plan); !slices.Equal(got, []string{"install coreutils-gnu"}) {
		t.Errorf("plan: got %v, want [install coreutils-gnu]", got)
	}
	if len(plan.Notices) != 1 || plan.Notices[0].Kind != resolver.NoticeGoalViaProvides {
		t.Errorf("want one NoticeGoalViaProvides, got %+v", plan.Notices)
	}
}

// Rule 4 orders provides matches by the ROLE version, not the package
// version. peiosutils 0.4 offers coreutils 10.0 and must beat
// coreutils-gnu 9.9 offering coreutils 9.9 — comparing 0.4 against 9.9
// would be a comparison of nothing, and would pin the role to whichever
// package happens to carry bigger numbers.
func TestGoalViaProvidesOrdersByRoleVersion(t *testing.T) {
	gnu := cand(t, "coreutils-gnu", "9.9-1")
	gnuRole := ver(t, "9.9-1")
	gnu.Provides = []manifest.Provides{{Name: "coreutils", Version: &gnuRole}}

	peios := cand(t, "peiosutils", "0.4-1")
	peiosRole := ver(t, "10.0-1")
	peios.Provides = []manifest.Provides{{Name: "coreutils", Version: &peiosRole}}

	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "coreutils"}},
		nil, []resolver.Candidate{gnu, peios}, defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := summary(plan); !slices.Equal(got, []string{"install peiosutils"}) {
		t.Errorf("plan: got %v, want [install peiosutils]", got)
	}
}

// Distinct packages filling one role, alike under rules 1-4, must be
// separated by a rule rather than by index order. Candidate order is
// reversed between runs; the winner must not move.
func TestGoalViaProvidesTieBreaksOnPackageName(t *testing.T) {
	mk := func(name string) resolver.Candidate {
		c := cand(t, name, "1.0-1")
		rv := ver(t, "1.0-1")
		c.Provides = []manifest.Provides{{Name: "awk", Version: &rv}}
		return c
	}
	gawk, mawk := mk("gawk"), mk("mawk")

	for _, order := range [][]resolver.Candidate{{gawk, mawk}, {mawk, gawk}} {
		plan, err := resolver.Resolve(
			[]resolver.Request{{Kind: resolver.Install, Name: "awk"}},
			nil, order, defaultOptions())
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got := summary(plan); !slices.Equal(got, []string{"install gawk"}) {
			t.Errorf("candidate order %s/%s: got %v, want [install gawk]",
				order[0].Name, order[1].Name, got)
		}
	}
}

// Two versions of one package providing the same role version tie on
// every §4.2.4 rule; the newer package must win regardless of candidate
// order. Found when a farm listing loregd_0.21.4 before loregd_0.21.5 kept
// composing the older registryd provider.
func TestProvidesTieBetweenVersionsOfOnePackagePrefersNewer(t *testing.T) {
	mk := func(pkgVer string) resolver.Candidate {
		c := cand(t, "loregd", pkgVer)
		rv := ver(t, "1-1")
		c.Provides = []manifest.Provides{{Name: "registryd", Version: &rv}}
		return c
	}
	older, newer := mk("0.21.4-1"), mk("0.21.5-1")

	for _, order := range [][]resolver.Candidate{{older, newer}, {newer, older}} {
		plan, err := resolver.Resolve(
			[]resolver.Request{{Kind: resolver.Install, Name: "registryd"}},
			nil, order, defaultOptions())
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got := summary(plan); !slices.Equal(got, []string{"install loregd"}) {
			t.Fatalf("plan: got %v, want [install loregd]", got)
		}
		for _, op := range plan.Operations {
			if op.Name == "loregd" && op.ToVersion.String() != "0.21.5-1" {
				t.Errorf("candidate order %s/%s: chose %s, want 0.21.5-1",
					order[0].Version, order[1].Version, op.ToVersion)
			}
		}
	}
}

// A name match beats a provides match for the same name only through the
// ordinary rules — but it must never be skipped: a real package named
// coreutils is a candidate for the coreutils goal.
func TestGoalPrefersHigherRoleVersionOverNameMatch(t *testing.T) {
	real := cand(t, "coreutils", "9.0-1")
	other := cand(t, "peiosutils", "0.4-1")
	roleVer := ver(t, "9.5-1")
	other.Provides = []manifest.Provides{{Name: "coreutils", Version: &roleVer}}

	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "coreutils"}},
		nil, []resolver.Candidate{real, other}, defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := summary(plan); !slices.Equal(got, []string{"install peiosutils"}) {
		t.Errorf("plan: got %v, want [install peiosutils]", got)
	}
}

// An unversioned `provides` satisfies any constraint (§4.1.4) but asserts
// no version, so it loses rule 4 to a provider that states one.
func TestGoalPrefersVersionedProvidesOverUnversioned(t *testing.T) {
	quiet := cand(t, "aaa-quiet", "1.0-1")
	quiet.Provides = []manifest.Provides{{Name: "awk"}}

	loud := cand(t, "zzz-loud", "1.0-1")
	rv := ver(t, "1.0-1")
	loud.Provides = []manifest.Provides{{Name: "awk", Version: &rv}}

	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "awk"}},
		nil, []resolver.Candidate{quiet, loud}, defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := summary(plan); !slices.Equal(got, []string{"install zzz-loud"}) {
		t.Errorf("plan: got %v, want [install zzz-loud] (versioned provides wins rule 4)", got)
	}
}

// Upgrade acts on a concrete installed package; resolving it through
// `provides` would let an upgrade silently swap one package for another.
func TestUpgradeDoesNotResolveViaProvides(t *testing.T) {
	usurper := cand(t, "peiosutils", "2.0-1")
	rv := ver(t, "2.0-1")
	usurper.Provides = []manifest.Provides{{Name: "coreutils-gnu", Version: &rv}}

	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Upgrade, Name: "coreutils-gnu"}},
		[]resolver.Installed{inst(t, "coreutils-gnu", "9.9-1")},
		[]resolver.Candidate{usurper},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := summary(plan); len(got) != 0 {
		t.Errorf("plan: got %v, want no operations (provides must not satisfy an upgrade)", got)
	}
}

// §4.2.4 rule 2 scopes itself to "when the dependency is being resolved
// for a depending package D", with no restriction to packages being
// newly installed. originRepo returned "" for a depender that was already
// installed and had no chosen candidate, and morePreferred treats an
// empty depender repo as "rule 2 inert".
//
// So the same dependency resolved to different providers depending on
// whether the depender happened to be part of the transaction — precisely
// the "low-trust depender pulling in low-trust transitive dependencies"
// gate the rule exists for, applied inconsistently.
func TestSelectionRule2AppliesToAnInstalledDepender(t *testing.T) {
	// Two providers of lib at equal priority, differing in repository. The
	// "extra" one carries the *higher* version, so if rule 2 goes inert
	// the ordinary version preference picks it — which is what makes this
	// able to tell the two behaviours apart.
	libOfficial := cand(t, "lib", "1.0-1")
	libExtra := cand(t, "lib", "2.0-1")
	libExtra.Repo, libExtra.RepoPriority = "extra", 10

	// app is already installed from "official" and is not itself being
	// changed: no candidate for it is offered, so the resolver must reach
	// for its recorded installed repository.
	installedApp := inst(t, "app", "1.0-1", dep(t, "lib", ""))
	installedApp.Repo, installedApp.RepoPriority = "official", 10

	// app is requested but already installed at the offered version, so
	// it seeds the forward walk without acquiring a candidate of its own.
	// That is the state where originRepo had nothing to report: the
	// depender is on the worklist and pkg.candidate is nil.
	appCand := cand(t, "app", "1.0-1", dep(t, "lib", ""))
	appCand.Repo, appCand.RepoPriority = "official", 10
	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "app"}},
		[]resolver.Installed{installedApp},
		[]resolver.Candidate{appCand, libOfficial, libExtra},
		defaultOptions())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if repo := opRepo(plan, "lib"); repo != "official" {
		t.Errorf("rule 2 for an installed depender: lib chosen from %q, want \"official\" — "+
			"the rule must not depend on whether the depender is in the transaction", repo)
	}
}

// §5.21: a depending package's effective architecture is its own when
// arch-specific, and the system's primary architecture when the depender
// is noarch.
//
// Skipping the architecture test outright for a noarch depender let any
// architecture satisfy, foreign ones included. The foreign candidate
// then entered the matching set, won on version, was placed, and was
// caught only by checkConsistency — which rejects the *entire*
// resolution. §4.2.5(1) permits failure only when no available package
// satisfies, and a satisfying noarch candidate was available the whole
// time (PEI-395).
func TestNoarchDependerResolvesAgainstThePrimaryArchitecture(t *testing.T) {
	candidates := []resolver.Candidate{
		{Name: "build-meta", Version: ver(t, "1.0-1"), Architecture: "noarch",
			Dependencies: []manifest.Dependency{dep(t, "tool", "")}},
		{Name: "tool", Version: ver(t, "2.0-1"), Architecture: "aarch64"},
		{Name: "tool", Version: ver(t, "1.0-1"), Architecture: "noarch"},
	}
	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "build-meta"}},
		nil, candidates, resolver.Options{PrimaryArch: primaryArch})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var got string
	for _, op := range plan.Operations {
		if op.Name == "tool" {
			got = op.ToVersion.String() + " " + op.Candidate.Architecture
		}
	}
	if got != "1.0-1 noarch" {
		t.Errorf("tool resolved to %q, want the noarch candidate", got)
	}
}

// The primary-architecture candidate still outranks a noarch one, so
// the effective-architecture rule has not turned into "prefer noarch".
func TestNoarchDependerPrefersThePrimaryArchitecture(t *testing.T) {
	candidates := []resolver.Candidate{
		{Name: "build-meta", Version: ver(t, "1.0-1"), Architecture: "noarch",
			Dependencies: []manifest.Dependency{dep(t, "tool", "")}},
		{Name: "tool", Version: ver(t, "2.0-1"), Architecture: primaryArch},
		{Name: "tool", Version: ver(t, "1.0-1"), Architecture: "noarch"},
	}
	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "build-meta"}},
		nil, candidates, resolver.Options{PrimaryArch: primaryArch})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, op := range plan.Operations {
		if op.Name == "tool" && op.Candidate.Architecture != primaryArch {
			t.Errorf("tool resolved to %s, want the %s candidate",
				op.Candidate.Architecture, primaryArch)
		}
	}
}

// §4.2.4 rule 6's rationale: "Rule 6 guarantees the rules impose a total
// order, so a resolution never depends on enumeration order."
//
// Two different versions of the same package matched through an
// *unversioned* provides tie on every rule above — a provides entry
// carries the role's version, not the package's — and then on name and
// on repository, so the winner was whichever the index enumerated first
// (PEI-418).
func TestUnversionedProvidesDoesNotFallToEnumerationOrder(t *testing.T) {
	provides := []manifest.Provides{{Name: "sh"}}
	older := resolver.Candidate{Name: "foo", Version: ver(t, "1.0-1"),
		Architecture: primaryArch, Repo: "official", Provides: provides}
	newer := resolver.Candidate{Name: "foo", Version: ver(t, "2.0-1"),
		Architecture: primaryArch, Repo: "official", Provides: provides}

	for name, candidates := range map[string][]resolver.Candidate{
		"older first": {older, newer},
		"newer first": {newer, older},
	} {
		t.Run(name, func(t *testing.T) {
			plan, err := resolver.Resolve(
				[]resolver.Request{{Kind: resolver.Install, Name: "sh"}},
				nil, candidates, resolver.Options{PrimaryArch: primaryArch})
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if len(plan.Operations) != 1 {
				t.Fatalf("plan = %+v, want one operation", plan.Operations)
			}
			if got := plan.Operations[0].ToVersion.String(); got != "2.0-1" {
				t.Errorf("resolved %s, want 2.0-1 whatever the enumeration order", got)
			}
		})
	}
}

// §5.37: an orphan's origin — a repository removed or revoked — counts
// as at least as trusted as any configured one wherever a gate compares
// priorities, so the §6.5.7 foreign-replaces gate still fires.
//
// Leaving an unresolvable origin zero-valued skipped the gate entirely,
// so any newly added low-trust repository could declare `replaces`
// against an orphaned ex-official package and take it over with no
// confirmation. Revoking a repository because its keys were stolen is
// exactly when that must not happen (PEI-379).
func TestReplacingAnOrphanNeedsAuthorisation(t *testing.T) {
	installed := []resolver.Installed{{
		Name: "official-tool", Version: ver(t, "1.0-1"), Architecture: primaryArch,
		// The origin is recorded but no longer configured.
		Repo: "peios-official", RepoPriority: resolver.OrphanPriority, Orphaned: true,
	}}
	candidates := []resolver.Candidate{{
		Name: "usurper", Version: ver(t, "1.0-1"), Architecture: primaryArch,
		Repo: "some-third-party", RepoPriority: 500,
		Replaces: []manifest.Replaces{{Name: "official-tool"}},
	}}
	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "usurper"}},
		installed, candidates, resolver.Options{PrimaryArch: primaryArch})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var found bool
	for _, a := range plan.Authorizations {
		if a.Kind == resolver.AuthForeignReplaces {
			found = true
			if !strings.Contains(a.Detail, "no longer configured") {
				t.Errorf("authorisation detail does not explain the orphan: %s", a.Detail)
			}
		}
	}
	if !found {
		t.Fatal("a low-trust repository took over an orphaned package with no authorisation")
	}
}

// The same takeover against a package whose repository is still
// configured and higher-trust already required authorisation; this is
// the guard that the orphan handling did not disturb it, and that a
// same-or-higher-trust replacer still needs none.
func TestReplacingAConfiguredPackageIsUnchanged(t *testing.T) {
	installed := []resolver.Installed{{
		Name: "tool", Version: ver(t, "1.0-1"), Architecture: primaryArch,
		Repo: "official", RepoPriority: 10,
	}}
	candidates := []resolver.Candidate{{
		Name: "same-trust", Version: ver(t, "1.0-1"), Architecture: primaryArch,
		Repo: "official", RepoPriority: 10,
		Replaces: []manifest.Replaces{{Name: "tool"}},
	}}
	plan, err := resolver.Resolve(
		[]resolver.Request{{Kind: resolver.Install, Name: "same-trust"}},
		installed, candidates, resolver.Options{PrimaryArch: primaryArch})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, a := range plan.Authorizations {
		if a.Kind == resolver.AuthForeignReplaces {
			t.Errorf("a same-priority replace demanded authorisation: %s", a.Detail)
		}
	}
}

// PEI-499: a republished revision of an unpinned provider silently
// failed to reach the image. Two revisions of one package provide the
// same unversioned capability, tie on every selection rule, and index
// order picked the older — so `libpeios 0.3.4-2` published beside
// `0.3.4-1` never shipped unless the manifest pinned it by name.
//
// The same tie as TestUnversionedProvidesDoesNotFallToEnumerationOrder,
// but between two *revisions* of one upstream version, which is the
// shape a farm directory actually produces.
func TestUnpinnedProviderTakesTheHighestRevision(t *testing.T) {
	provides := []manifest.Provides{{Name: "libpeios.so.0"}}
	older := resolver.Candidate{Name: "libpeios", Version: ver(t, "0.3.4-1"),
		Architecture: primaryArch, Repo: "official", Provides: provides}
	newer := resolver.Candidate{Name: "libpeios", Version: ver(t, "0.3.4-2"),
		Architecture: primaryArch, Repo: "official", Provides: provides}
	consumer := resolver.Candidate{Name: "peinit", Version: ver(t, "1.0-1"),
		Architecture: primaryArch, Repo: "official",
		Dependencies: []manifest.Dependency{dep(t, "libpeios.so.0", "")}}

	for name, candidates := range map[string][]resolver.Candidate{
		"older listed first": {older, newer, consumer},
		"newer listed first": {newer, older, consumer},
	} {
		t.Run(name, func(t *testing.T) {
			plan, err := resolver.Resolve(
				[]resolver.Request{{Kind: resolver.Install, Name: "peinit"}},
				nil, candidates, resolver.Options{PrimaryArch: primaryArch})
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			var got string
			for _, op := range plan.Operations {
				if op.Name == "libpeios" {
					got = op.ToVersion.String()
				}
			}
			if got != "0.3.4-2" {
				t.Errorf("resolved libpeios %s, want the highest revision 0.3.4-2", got)
			}
		})
	}
}
