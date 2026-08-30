package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/peios/peipkg/internal/resolver"
)

// alternateUpgradeWarning is the §5.18 warning a consumer reports with
// every refused or held-back package, verbatim.
const alternateUpgradeWarning = "Warning: Alternate upgrade paths may bypass normal peipkg " +
	"protections; ensure you fully trust the authors of the package before running."

// alternateUpgradeBlock renders the §5.18 report for one package: its
// name, its message verbatim, and the warning.
func alternateUpgradeBlock(name, message string) string {
	return fmt.Sprintf("The package %q has an alternate upgrade path.\n\n%s\n\n%s\n",
		name, message, alternateUpgradeWarning)
}

// alternateUpgradeOps returns the plan's install and upgrade operations
// whose chosen package declares alternate_upgrade (§5.18) — the
// operations the declaration exists to stop. A removal or downgrade is
// never one: the declaration speaks to moving the package forward.
func alternateUpgradeOps(plan resolver.Plan) []resolver.Operation {
	var ops []resolver.Operation
	for _, op := range plan.Operations {
		if op.Kind != resolver.OpInstall && op.Kind != resolver.OpUpgrade {
			continue
		}
		if op.Candidate != nil && op.Candidate.AlternateUpgrade != nil {
			ops = append(ops, op)
		}
	}
	return ops
}

// refuseAlternateUpgrade builds the §5.18 rule-1 error for a plan that
// would install or upgrade one or more alternate-upgrade packages: one
// report block per package, then the one-line pointer at the override.
func refuseAlternateUpgrade(ops []resolver.Operation) error {
	var b strings.Builder
	for i, op := range ops {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(alternateUpgradeBlock(op.Name, op.Candidate.AlternateUpgrade.Message))
	}
	b.WriteString("peipkg proceeds only with --bypass-alternate-upgrade.")
	return fmt.Errorf("%s", b.String())
}

// isEveryPackageUpgrade reports whether reqs is the upgrade-everything
// request — the one shape §5.18 rule 2 holds packages back from rather
// than refusing outright.
func isEveryPackageUpgrade(reqs []resolver.Request) bool {
	return len(reqs) == 1 && reqs[0].Kind == resolver.Upgrade && reqs[0].Name == ""
}

// enforceAlternateUpgrade applies §5.18 rules 1 and 2 to a resolved
// plan. The package manager grants nothing on the declaration's behalf;
// it only refuses or holds:
//
//   - A request naming the package, or any plan that would install or
//     upgrade it as a dependency, is refused (rule 1): the error carries
//     each package's message and the warning, and nothing is applied.
//   - An every-package upgrade holds each such package back at its
//     installed version (rule 2): the same report is printed to stderr
//     once per held package, and the rest of the upgrade proceeds.
//
// Holding back is done by re-resolving, not by deleting operations from
// the plan: the plan's remaining operations are re-requested as explicit
// named upgrades, so the resolver — not this function — decides what the
// rest of the upgrade looks like without the held packages. Should that
// narrower plan still reach a held package (as a dependency of another
// upgrade), rule 1 applies to it.
//
// The caller skips this entirely under --bypass-alternate-upgrade (rule
// 3), which is the intended way for the out-of-band tool to drive
// peipkg.
func (app *App) enforceAlternateUpgrade(ctx context.Context, plan resolver.Plan,
	reqs []resolver.Request,
	resolve func(context.Context, []resolver.Request) (resolver.Plan, error)) (resolver.Plan, error) {

	held := alternateUpgradeOps(plan)
	if len(held) == 0 {
		return plan, nil
	}
	if !isEveryPackageUpgrade(reqs) {
		return resolver.Plan{}, refuseAlternateUpgrade(held)
	}

	// Rule 2: report, then re-resolve for everything else that was
	// going to move.
	heldNames := make(map[string]bool, len(held))
	for _, op := range held {
		heldNames[op.Name] = true
		fmt.Fprint(app.errOut, alternateUpgradeBlock(op.Name, op.Candidate.AlternateUpgrade.Message))
		fmt.Fprintf(app.errOut, "held back: %s %s -> %s\n", op.Name, op.FromVersion, op.ToVersion)
	}
	var rest []resolver.Request
	for _, op := range plan.Operations {
		if op.Kind == resolver.OpUpgrade && !heldNames[op.Name] {
			rest = append(rest, resolver.Request{Kind: resolver.Upgrade, Name: op.Name, Root: op.Root})
		}
	}
	if len(rest) == 0 {
		return resolver.Plan{}, nil
	}
	narrowed, err := resolve(ctx, rest)
	if err != nil {
		return resolver.Plan{}, err
	}
	if still := alternateUpgradeOps(narrowed); len(still) > 0 {
		return resolver.Plan{}, refuseAlternateUpgrade(still)
	}
	return narrowed, nil
}
