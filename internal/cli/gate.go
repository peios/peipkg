package cli

import (
	"fmt"
	"strings"

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
		app.printf("  %s\n", describeOp(op))
	}
	for _, a := range plan.Authorizations {
		app.printf("  ! elevated: %s\n", a.Detail)
	}
}

// describeOp renders one planned operation. A package supplied as a
// local file — recognised by an empty candidate Repo — is marked, so
// the operator sees that the repository trust layer was skipped.
func describeOp(op resolver.Operation) string {
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
