package install

import "os/exec"

// sideEffectCommands maps a recognised side-effect identifier (§4.3.4)
// to the fixed absolute command that performs it. The path is fixed —
// PATH is never searched — so the genuine system tool runs and a
// package cannot shadow it.
var sideEffectCommands = map[string][]string{
	"ldconfig": {"/usr/bin/ldconfig"},
	"depmod":   {"/usr/bin/depmod", "-a"},
	"man-db":   {"/usr/bin/mandb", "-q"},
}

// runSideEffects runs each post-commit maintenance operation once, with
// a cleared environment and stdin closed (§4.3). It runs after the
// durability boundary, so a failure is a reported warning rather than a
// transaction failure: the operations are idempotent and self-correct
// when next invoked. It returns one warning per failed side effect.
func runSideEffects(effects []string) []string {
	var warnings []string
	for _, effect := range effects {
		argv, ok := sideEffectCommands[effect]
		if !ok {
			continue // an unrecognised effect is rejected at manifest decode
		}
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin"}
		// cmd.Stdin left nil: the child reads from the null device.
		if out, err := cmd.CombinedOutput(); err != nil {
			warnings = append(warnings, "side effect "+effect+" failed: "+failureDetail(err, out))
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
