package install

import (
	"os/exec"
	"sort"
	"strings"

	"github.com/peios/peipkg/internal/db"
)

// sideEffectCommands maps a recognised side-effect identifier (PSPU
// §5.24) to the fixed absolute command that performs it. The path is
// fixed — PATH is never searched — so the genuine system tool runs and a
// package cannot shadow it.
//
// depmod is absent: it is not a fixed command. See [depmodCommands].
var sideEffectCommands = map[string][]string{
	"man-db": {"/bin/mandb", "-q"},
}

// depmodBinary is machine-facing and ships in libexec rather than on
// PATH — this is one of the callers that puts it there.
const depmodBinary = "/libexec/depmod"

// modulesPrefix is where a package's kernel modules live, one directory
// per kernel release.
const modulesPrefix = "usr/lib/modules/"

// sideEffect is one post-commit maintenance command, named by the
// identifier that asked for it so a failure can be reported against the
// declaration rather than against an argv.
type sideEffect struct {
	name string
	argv []string
}

// plannedSideEffects expands the side effects the staged packages declare
// into the commands that perform them, once each.
//
// depmod is the reason this is not a straight name lookup. PSPU §5.24
// requires it to run against the kernel release the modules being
// installed belong to, once per affected release — not against the
// running kernel. Bare `depmod -a` does the latter, so the normal kernel
// update (install release X while running release W, reboot later)
// indexed W's tree and left X's modules.dep stale or absent: on the next
// boot modprobe resolves nothing, with no error naming the cause.
//
// The releases are read from the payload, which is where the answer
// actually is: a package's modules sit under usr/lib/modules/<release>/,
// and a package may carry more than one.
func plannedSideEffects(staged []stagedOp) ([]sideEffect, []string) {
	seen := map[string]bool{}
	var names []string
	var warnings []string
	for _, s := range staged {
		// A removal contributes its side effects too: §5.24 ties an
		// effect to files whose *absence* affects its target, so
		// removing the last owner of a shared library needs ldconfig and
		// removing kernel modules needs depmod, exactly as installing
		// them does. stageRemoval reads them off the stored manifest.
		for _, e := range s.sideEffects {
			if !seen[e] {
				seen[e] = true
				names = append(names, e)
			}
		}
	}

	var effects []sideEffect
	for _, name := range names {
		if name == "depmod" {
			commands, warning := depmodCommands(staged)
			if warning != "" {
				warnings = append(warnings, warning)
			}
			effects = append(effects, commands...)
			continue
		}
		argv, ok := sideEffectCommands[name]
		if !ok {
			continue // an unrecognised effect is rejected at manifest decode
		}
		effects = append(effects, sideEffect{name: name, argv: argv})
	}
	return effects, warnings
}

// depmodCommands returns one depmod invocation per kernel release the
// transaction installed modules for.
//
// Releases come from every staged package's payload, not only from the
// packages that declared depmod: a release whose module set changed needs
// reindexing whichever package in the transaction carried the change, and
// splitting a release's modules across packages is exactly what
// kernel-modules and kernel-modules-irf do.
//
// A removal's files count for the same reason (§5.24): deleting a
// release's modules changes that release's module set as surely as
// adding to it, and leaves modules.dep naming files that are gone.
func depmodCommands(staged []stagedOp) ([]sideEffect, string) {
	seen := map[string]bool{}
	for _, s := range staged {
		for _, f := range append(append([]db.PackageFile(nil), s.files...), s.removedFiles...) {
			if release, ok := moduleRelease(f); ok {
				seen[release] = true
			}
		}
	}
	if len(seen) == 0 {
		// Declared with nothing to index. `pack` rejects the reverse —
		// modules without the declaration — but cannot rule this out, and
		// falling back to `depmod -a` would reintroduce exactly the
		// running-kernel bug this replaced.
		return nil, "side effect depmod declared, but neither the payload nor the removed " +
			"files contain kernel modules: nothing reindexed"
	}
	releases := make([]string, 0, len(seen))
	for release := range seen {
		releases = append(releases, release)
	}
	sort.Strings(releases) // deterministic order, so runs are reproducible
	effects := make([]sideEffect, 0, len(releases))
	for _, release := range releases {
		effects = append(effects, sideEffect{
			name: "depmod",
			argv: []string{depmodBinary, "-a", release},
		})
	}
	return effects, ""
}

// moduleRelease returns the kernel release a payload file belongs to, if
// it is a kernel module.
//
// Only regular files count. A directory under usr/lib/modules/<release>/
// says nothing about whether any module landed there, and an empty
// release directory is not a release to index.
func moduleRelease(f db.PackageFile) (string, bool) {
	if f.Type != db.FileTypeFile {
		return "", false
	}
	rest, ok := strings.CutPrefix(strings.TrimPrefix(f.Path, "/"), modulesPrefix)
	if !ok {
		return "", false
	}
	release, remainder, ok := strings.Cut(rest, "/")
	if !ok || release == "" || remainder == "" {
		return "", false
	}
	return release, true
}

// runSideEffects runs each post-commit maintenance operation once, with
// a cleared environment and stdin closed (PSPU §5.24). It runs after the
// durability boundary, so a failure is a reported warning rather than a
// transaction failure: the operations are idempotent and self-correct
// when next invoked. It returns one warning per failed side effect.
func runSideEffects(effects []sideEffect) []string {
	var warnings []string
	for _, effect := range effects {
		cmd := exec.Command(effect.argv[0], effect.argv[1:]...)
		cmd.Env = []string{"LC_ALL=C", "PATH=/bin"}
		// cmd.Stdin left nil: the child reads from the null device.
		if out, err := cmd.CombinedOutput(); err != nil {
			warnings = append(warnings,
				"side effect "+effect.name+" failed: "+failureDetail(err, out))
		}
	}
	return warnings
}

// failureDetail summarises a failed side effect, preferring its output
// and capping the length so a runaway tool cannot flood the report.
func failureDetail(err error, out []byte) string {
	const max = 240
	detail := err.Error()
	if len(out) > 0 {
		detail = string(out)
	}
	if len(detail) > max {
		detail = detail[:max] + "…"
	}
	return detail
}
