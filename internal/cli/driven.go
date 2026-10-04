package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os/signal"
	"strings"
	"syscall"

	"github.com/peios/peipkg/internal/install"
	"github.com/peios/peipkg/internal/repository"
	"github.com/peios/peipkg/internal/resolver"
)

// The driven mode (--driven) is how a program, rather than a person at a
// terminal, runs peipkg: Package Manager is the first. Standard output
// becomes JSON Lines events — the plan, each question, progress, warnings
// and one terminal event — and standard input carries the answers, one
// JSON object a line. Nothing about what is asked or what an answer
// authorises changes; only the channel does.

// driver is the driven mode's half of an App: where events go, and the
// running count that gives each question its id.
type driver struct {
	events io.Writer // the real standard output
	asked  int
	// outcome is how a command that returned no error ended: a
	// cancellation's reason, or what was done and in which transaction.
	cancelled string
	done      string
	txn       int64
}

// startDriven puts app into the driven mode. What the commands print
// still arrives, as message and warning events, so nothing a person at a
// terminal would have been told is lost to the program.
func (app *App) startDriven() {
	// A program that goes away mid-transaction must not take the
	// transaction with it. Writing to its closed pipe fails rather than
	// killing peipkg, the events are lost, and any question still to come
	// reads the end of input: a refusal.
	signal.Ignore(syscall.SIGPIPE)
	d := &driver{events: app.out}
	app.driven = d
	app.out = &eventLines{emit: func(line string) {
		app.event(map[string]any{"event": "message", "text": line})
	}}
	app.errOut = &eventLines{emit: func(line string) {
		line = strings.TrimPrefix(line, "peipkg: ")
		if rest, ok := strings.CutPrefix(line, "warning: "); ok {
			app.event(map[string]any{"event": "warning", "text": rest})
			return
		}
		app.event(map[string]any{"event": "message", "text": line})
	}}
}

// event writes one event as a line of JSON.
func (app *App) event(v map[string]any) {
	data, err := json.Marshal(v)
	if err != nil {
		data = []byte(`{"event":"warning","text":"an event could not be encoded"}`)
	}
	data = append(data, '\n')
	_, _ = app.driven.events.Write(data)
}

// ask sends a question and reads its answer. The answer must carry the
// question's id; an answer that does not, that cannot be read, or the end
// of input, is returned as "" — which every caller treats as a refusal,
// as end-of-input is at a terminal.
func (app *App) ask(question map[string]any) string {
	app.driven.asked++
	id := app.driven.asked
	question["event"] = "question"
	question["id"] = id
	app.event(question)
	// A final answer without its newline still counts, so the read's
	// error matters only through what it left in line.
	line, _ := app.reader.ReadBytes('\n')
	if len(bytes.TrimSpace(line)) == 0 {
		return ""
	}
	var answer struct {
		ID     int    `json:"id"`
		Answer string `json:"answer"`
	}
	if jerr := json.Unmarshal(line, &answer); jerr != nil || answer.ID != id {
		app.event(map[string]any{"event": "warning",
			"text": fmt.Sprintf("the answer to question %d was not understood, so it was refused", id)})
		return ""
	}
	return answer.Answer
}

// planEvent sends a resolved plan as the plan event.
func (app *App) planEvent(plan resolver.Plan) {
	ops := make([]map[string]any, 0, len(plan.Operations))
	for _, op := range plan.Operations {
		o := map[string]any{"name": op.Name}
		switch op.Kind {
		case resolver.OpInstall:
			o["kind"] = "install"
		case resolver.OpUpgrade:
			o["kind"] = "upgrade"
		case resolver.OpDowngrade:
			o["kind"] = "downgrade"
		default:
			o["kind"] = "remove"
		}
		if op.Kind != resolver.OpInstall {
			o["from"] = op.FromVersion.String()
		}
		if op.Kind != resolver.OpRemove {
			o["to"] = op.ToVersion.String()
		}
		if c := op.Candidate; c != nil {
			o["repository"] = c.Repo
			o["local"] = c.Repo == ""
			o["size_download"] = c.SizeCompressed
			o["size_installed"] = c.SizeInstalled
		}
		if op.Root != "" && op.Root != app.paths.root {
			o["root"] = op.Root
		}
		ops = append(ops, o)
	}
	auths := make([]string, 0, len(plan.Authorizations))
	for _, a := range plan.Authorizations {
		auths = append(auths, a.Detail)
	}
	notes := make([]string, 0, len(plan.Notices))
	for _, n := range plan.Notices {
		notes = append(notes, n.Detail)
	}
	others := otherRoots(plan, app.paths.root)
	if others == nil {
		others = []string{}
	}
	app.event(map[string]any{"event": "plan", "operations": ops,
		"authorisations": auths, "notes": notes, "other_roots": others})
}

// progress is the install.Env.Progress of a driven transaction.
func (app *App) progress(p install.Progress) {
	ev := map[string]any{"event": "progress", "phase": string(p.Phase),
		"step": p.Step, "steps": p.Steps}
	if p.Package != "" {
		ev["package"] = p.Package
	}
	app.event(ev)
}

// progressFunc is the install.Env.Progress for this App: nil unless
// driven, so a terminal run reports nothing it did not before.
func (app *App) progressFunc() func(install.Progress) {
	if app.driven == nil {
		return nil
	}
	return app.progress
}

// cancelledBecause records that a command ended without doing anything,
// and prints why for a terminal.
func (app *App) cancelledBecause(reason string) {
	if app.driven != nil {
		if reason == "" {
			reason = "the plan was not approved"
		}
		app.driven.cancelled = reason
		return
	}
	if reason == "" {
		app.printf("cancelled\n")
		return
	}
	app.printf("cancelled — %s\n", reason)
}

// finish sends the terminal event for a driven command that returned err.
// It returns the exit code.
func (app *App) finish(err error) int {
	d := app.driven
	switch {
	case err != nil:
		app.event(map[string]any{"event": "error", "code": errorCode(err),
			"message": err.Error()})
		return 1
	case d.cancelled != "":
		app.event(map[string]any{"event": "cancelled", "reason": d.cancelled})
	default:
		ev := map[string]any{"event": "done"}
		if d.done != "" {
			ev["summary"] = d.done
		}
		if d.txn != 0 {
			ev["transaction"] = d.txn
		}
		app.event(ev)
	}
	return 0
}

// codedError gives an error one of the driven mode's stable codes.
type codedError struct {
	code string
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }

// withCode marks err with a stable code for the driven mode's error event.
func withCode(code string, err error) error {
	return &codedError{code: code, err: err}
}

// errorCode is the stable code a driven caller acts on:
//
//   - stale: a repository's trust state or metadata is too old, and
//     refreshing did not cure it. --allow-stale proceeds.
//   - busy: another package operation holds the lock. Try again later.
//   - denied: the operator may not do this.
//   - unowned: a file that belongs to no package would be replaced.
//     --overwrite-unowned proceeds, keeping the displaced copy.
//   - alternate-upgrade: a package declares that it is upgraded another
//     way. --bypass-alternate-upgrade proceeds.
//   - unresolvable: no plan satisfies the request.
//   - untrusted: a configured repository's trust ceremony has never run.
//     `repo add <name>` runs it.
//   - failed: anything else.
func errorCode(err error) string {
	var coded *codedError
	var unowned *install.UnownedFileError
	var rejection *resolver.Rejection
	switch {
	case errors.As(err, &coded):
		return coded.code
	case errors.Is(err, install.ErrBusy):
		return "busy"
	case errors.Is(err, repository.ErrNoTrustState):
		return "untrusted"
	case errors.As(err, &unowned):
		return "unowned"
	case errors.As(err, &rejection):
		return "unresolvable"
	case errors.Is(err, fs.ErrPermission):
		return "denied"
	}
	return "failed"
}

// eventLines turns what is written to it into one event per line.
type eventLines struct {
	emit    func(line string)
	pending []byte
}

func (w *eventLines) Write(p []byte) (int, error) {
	w.pending = append(w.pending, p...)
	for {
		i := bytes.IndexByte(w.pending, '\n')
		if i < 0 {
			return len(p), nil
		}
		line := strings.TrimRight(string(w.pending[:i]), " ")
		w.pending = w.pending[i+1:]
		if strings.TrimSpace(line) != "" {
			w.emit(line)
		}
	}
}
