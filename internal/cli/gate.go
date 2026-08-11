package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/peios/peipkg/internal/audit"
	"github.com/peios/peipkg/internal/resolver"
)

// presentPlan prints a resolved plan for the operator to review,
// including any elevated actions it carries.
func (app *App) presentPlan(plan resolver.Plan) {
	if len(plan.Operations) == 0 {
		app.printf("nothing to do — the request is already satisfied\n")
		return
	}
	app.printf("the following changes will be made:\n")
	for _, op := range plan.Operations {
		app.printf("  %s\n", describeOp(op, app.paths.root))
	}
	for _, a := range plan.Authorizations {
		app.printf("  ! elevated: %s\n", a.Detail)
	}
	for _, n := range plan.Notices {
		app.printf("  note: %s\n", n.Detail)
	}
	// Loud cross-root plans (DESIGN-named-roots.md): if an operation
	// touches a root other than the one invoked, say so prominently before
	// the confirmation gate — installing "into a second filesystem image"
	// is unfamiliar and must never be silent.
	if others := otherRoots(plan, app.paths.root); len(others) > 0 {
		app.printf("note: this also changes other roots: %s\n", strings.Join(others, ", "))
	}
}

// otherRoots returns the distinct operation roots that are not the
// anchor, sorted — the roots a cross-root plan reaches beyond the one the
// operator invoked.
func otherRoots(plan resolver.Plan, anchor string) []string {
	seen := map[string]bool{}
	var out []string
	for _, op := range plan.Operations {
		if op.Root != "" && op.Root != anchor && !seen[op.Root] {
			seen[op.Root] = true
			out = append(out, op.Root)
		}
	}
	sort.Strings(out)
	return out
}

// describeOp renders one planned operation. A package supplied as a
// local file — recognised by an empty candidate Repo — is marked, so
// the operator sees that the repository trust layer was skipped. An
// operation whose target root differs from anchor is tagged with that
// root, so a cross-root effect is visible per line.
func describeOp(op resolver.Operation, anchor string) string {
	var s string
	switch op.Kind {
	case resolver.OpInstall:
		s = fmt.Sprintf("install    %s %s", op.Name, op.ToVersion)
	case resolver.OpUpgrade:
		s = fmt.Sprintf("upgrade    %s %s -> %s", op.Name, op.FromVersion, op.ToVersion)
	case resolver.OpDowngrade:
		s = fmt.Sprintf("downgrade  %s %s -> %s", op.Name, op.FromVersion, op.ToVersion)
	default:
		s = fmt.Sprintf("remove     %s %s", op.Name, op.FromVersion)
	}
	if op.Candidate != nil && op.Candidate.Repo == "" {
		s += "  (local file)"
	}
	if op.Root != "" && op.Root != anchor {
		s += "  -> " + op.Root
	}
	return s
}

// authorize obtains the deliberate, specific operator authorisation that
// §7.6.6 requires for each elevated action in a plan. Each action is
// presented and confirmed on its own; the routine proceed prompt — and
// the --yes flag that skips it — never satisfy this. With no elevated
// actions it is a no-op that returns true.
func (app *App) authorize(auths []resolver.Authorization) bool {
	for _, a := range auths {
		app.printf("\nthis operation requires elevated authorisation:\n  %s\n", a.Detail)
		app.printf("authorise this specific action? [y/N] ")
		if !app.readConfirmation() {
			return false
		}
		// §7.6.6: the authorising act and what it authorised are
		// recorded in the audit stream.
		app.emit(audit.Event{Type: audit.TypeAuthorisation,
			Outcome: audit.OutcomeSuccess, Detail: a.Detail})
	}
	return true
}

// confirm asks the operator to approve the plan, returning true when the
// operation should proceed. End-of-input is treated as a refusal.
func (app *App) confirm() bool {
	app.printf("proceed? [y/N] ")
	return app.readConfirmation()
}

// readConfirmation reads one line from the shared input and reports
// whether it is an affirmative answer. End-of-input is a refusal.
func (app *App) readConfirmation() bool {
	line, _ := app.reader.ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
