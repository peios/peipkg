package resolver_test

import (
	"testing"

	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/resolver"
)

func TestArchitectureMigrationSelectsNewerPackageRevision(t *testing.T) {
	const name = "dev.peios.build-essentials-c"
	old := cand(t, name, "1.0.0-9")
	next := cand(t, name, "1.0.0-10", dep(t, "dwz", ""))
	next.Architecture = "noarch"
	parent := cand(t, "consumer", "1.0-1", dep(t, name, ""))
	for _, reverse := range []bool{false, true} {
		for _, kind := range []string{"goal", "dependency", "upgrade"} {
			t.Run(kind+map[bool]string{false: "/forward", true: "/reverse"}[reverse], func(t *testing.T) {
				candidates := []resolver.Candidate{old, next, cand(t, "dwz", "1.0-1"), parent}
				if reverse {
					candidates[0], candidates[1] = candidates[1], candidates[0]
				}
				request := resolver.Request{Kind: resolver.Install, Name: name}
				var installed []resolver.Installed
				if kind == "dependency" {
					request.Name = "consumer"
				}
				if kind == "upgrade" {
					request.Kind = resolver.Upgrade
					installed = []resolver.Installed{inst(t, name, "1.0.0-9")}
				}
				plan, err := resolver.Resolve([]resolver.Request{request}, installed, candidates, defaultOptions())
				if err != nil {
					t.Fatal(err)
				}
				found, foundDependency := false, false
				for _, op := range plan.Operations {
					if op.Name == "dwz" {
						foundDependency = true
					}
					if op.Name == name {
						found = true
						if op.ToVersion.String() != "1.0.0-10" || op.Candidate.Architecture != "noarch" {
							t.Fatalf("selected %s %s", op.ToVersion, op.Candidate.Architecture)
						}
					}
				}
				if !found || !foundDependency {
					t.Fatalf("new revision and dependency missing: %v", summary(plan))
				}
			})
		}
	}
}

func TestArchitectureMigrationKeepsConstraintsAndRepositoryPriority(t *testing.T) {
	old := cand(t, "tool", "1.0-1")
	for _, constrained := range []bool{false, true} {
		next := cand(t, "tool", "2.0-1")
		next.Architecture = "noarch"
		request := resolver.Request{Kind: resolver.Install, Name: "tool"}
		candidates := []resolver.Candidate{old}
		if constrained {
			request.Name = "consumer"
			candidates = append(candidates, cand(t, "consumer", "1.0-1", dep(t, "tool", "= 1.0-1")))
		} else {
			next.Repo, next.RepoPriority = "lower-priority", 50
		}
		candidates = append(candidates, next)
		plan, err := resolver.Resolve([]resolver.Request{request}, nil, candidates, defaultOptions())
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range plan.Operations {
			if op.Name == "tool" && op.ToVersion.String() != "1.0-1" {
				t.Fatalf("selected %s", op.ToVersion)
			}
		}
	}
}

func TestArchitecturePreferenceBetweenProvidersUsesSelectedRevisions(t *testing.T) {
	aOld := cand(t, "a", "1.0-1")
	aNew := cand(t, "a", "2.0-1")
	aNew.Architecture = "noarch"
	b := cand(t, "b", "1.0-1")
	for _, c := range []*resolver.Candidate{&aOld, &aNew, &b} {
		c.Provides = []manifest.Provides{{Name: "role"}}
	}
	candidates := []resolver.Candidate{aOld, aNew, b}
	for _, order := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		plan, err := resolver.Resolve([]resolver.Request{{Kind: resolver.Install, Name: "role"}}, nil,
			[]resolver.Candidate{candidates[order[0]], candidates[order[1]], candidates[order[2]]}, defaultOptions())
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.Operations) != 1 || plan.Operations[0].Name != "b" {
			t.Fatalf("order %v: selected %v, want native provider b over noarch a", order, summary(plan))
		}
	}
}

func TestArchitectureMigrationViaProvidesAndSameRevisionTie(t *testing.T) {
	for _, versioned := range []bool{false, true} {
		old := cand(t, "tool", "1.0-1")
		next := cand(t, "tool", "2.0-1")
		next.Architecture = "noarch"
		offered := manifest.Provides{Name: "role"}
		if versioned {
			v := ver(t, "5.0-1")
			offered.Version = &v
		}
		old.Provides, next.Provides = []manifest.Provides{offered}, []manifest.Provides{offered}
		for _, tie := range []bool{false, true} {
			if tie {
				old.Version = next.Version
			}
			for _, candidates := range [][]resolver.Candidate{{old, next}, {next, old}} {
				plan, err := resolver.Resolve([]resolver.Request{{Kind: resolver.Install, Name: "role"}}, nil, candidates, defaultOptions())
				if err != nil {
					t.Fatal(err)
				}
				wantArch := "noarch"
				if tie {
					wantArch = primaryArch
				}
				got := plan.Operations[0].Candidate
				if got.Version.String() != "2.0-1" || got.Architecture != wantArch {
					t.Fatalf("versioned=%v tie=%v: %s %s", versioned, tie, got.Version, got.Architecture)
				}
			}
		}
	}
}
