package cli

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/peios/peipkg/internal/resolver"
)

// presentPlan prints a resolved plan for the operator to review.
func (app *App) presentPlan(plan resolver.Plan) {
	if len(plan.Operations) == 0 {
		app.printf("nothing to do — the request is already satisfied\n")
		return
	}
	app.printf("the following changes will be made:\n")
	for _, op := range plan.Operations {
		app.printf("  %s\n", describeOp(op))
	}
}

// describeOp renders one planned operation.
func describeOp(op resolver.Operation) string {
	switch op.Kind {
	case resolver.OpInstall:
		return fmt.Sprintf("install    %s %s", op.Name, op.ToVersion)
	case resolver.OpUpgrade:
		return fmt.Sprintf("upgrade    %s %s -> %s", op.Name, op.FromVersion, op.ToVersion)
	case resolver.OpDowngrade:
		return fmt.Sprintf("downgrade  %s %s -> %s", op.Name, op.FromVersion, op.ToVersion)
	default:
		return fmt.Sprintf("remove     %s %s", op.Name, op.FromVersion)
	}
}

// confirm asks the operator to approve the plan, returning true when
// the operation should proceed. End-of-input is treated as a refusal.
func (app *App) confirm() bool {
	app.printf("proceed? [y/N] ")
	line, _ := bufio.NewReader(app.in).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
