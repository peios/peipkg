// Package cli implements the peipkg command-line surface: it parses the
// command line, wires together the package database, the repository
// layer, the resolver, and the transaction executor, and renders their
// results.
package cli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/peios/peipkg/internal/audit"
	"github.com/peios/peipkg/internal/db"
)

// peipkgVersion is the peipkg build version, recorded on every
// transaction.
const peipkgVersion = "0.1.0"

// paths locates peipkg's files beneath an operating root.
type paths struct {
	root      string // the install root — "/" in normal use
	stateDir  string // <root>/var/state/peipkg — the database, lock, caches
	configDir string // <root>/lcl/conf/peipkg — the repository .repo files
	dbPath    string
	lockPath  string
	cacheDir  string // verified repository indexes
}

// App is the context shared by every peipkg command.
type App struct {
	paths paths
	// rootExplicit records whether the operator passed --root. When false,
	// a top-level install may re-root itself to a package's default_root
	// (§3.3.6, DESIGN-named-roots.md); an explicit --root always wins.
	rootExplicit bool
	in           io.Reader
	reader       *bufio.Reader // buffers in; shared so prompts do not lose input
	out          io.Writer
	errOut       io.Writer
	emitter      audit.Emitter // the §7.6 audit-event sink
	// bypassPathRestrictions is the operator's half of the Special System
	// Package exemption (--dangerously-bypass-path-restrictions). It
	// waives the §3.4 payload layout check, but only for a package that
	// itself declares special_system_package: the flag cannot exempt an
	// ordinary package, and the declaration cannot exempt itself.
	bypassPathRestrictions bool
}

// newPaths locates peipkg's files beneath an operating root.
func newPaths(root string) paths {
	state := filepath.Join(root, "var/state/peipkg")
	return paths{
		root:      root,
		stateDir:  state,
		configDir: filepath.Join(root, "conf/peipkg"),
		dbPath:    filepath.Join(state, "db.sqlite"),
		lockPath:  filepath.Join(state, "lock"),
		cacheDir:  filepath.Join(state, "cache"),
	}
}

// newApp builds an App rooted at root, reading from in and writing to
// out and errOut.
func newApp(root string, in io.Reader, out, errOut io.Writer) *App {
	return &App{
		paths:   newPaths(root),
		in:      in,
		reader:  bufio.NewReader(in),
		out:     out,
		errOut:  errOut,
		emitter: audit.KMESEmitter{},
	}
}

// setRoot re-points the App at a different operating root, recomputing
// every derived path. It is how a top-level install moves itself to a
// package's default_root before the transaction opens.
func (app *App) setRoot(root string) {
	app.paths = newPaths(root)
}

// command is the handler for one peipkg verb.
type command func(app *App, args []string) error

// dispatch maps each verb to its handler.
var dispatch map[string]command

func init() {
	dispatch = map[string]command{
		"install":   cmdInstall,
		"upgrade":   cmdUpgrade,
		"downgrade": cmdDowngrade,
		"uninstall": cmdUninstall,
		"remove":    cmdUninstall, // alias
		"claim":     cmdClaim,
		"undo":      cmdUndo,
		"list":      cmdList,
		"info":      cmdInfo,
		"files":     cmdFiles,
		"owns":      cmdOwns,
		"search":    cmdSearch,
		"verify":    cmdVerify,
		"history":   cmdHistory,
		"repo":      cmdRepo,
		"root":      cmdRoot,
		"refresh":   cmdRefresh,
		"clean":     cmdClean,
		"recover":   cmdRecover,
	}
}

// Run parses args (the arguments after the program name), executes the
// requested command, and returns a process exit code.
func Run(args []string) int {
	global := flag.NewFlagSet("peipkg", flag.ContinueOnError)
	global.SetOutput(os.Stderr)
	root := global.String("root", "/", "filesystem root to operate under")
	if err := global.Parse(args); err != nil {
		return 2
	}
	rest := global.Args()
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "peipkg: a command is required")
		printUsage(os.Stderr)
		return 2
	}

	// Resolve --root: a path-like value is a literal filesystem path
	// (today's behaviour), a bare name is a registered root resolved
	// against the system anchor (DESIGN-named-roots.md D2/D3).
	resolvedRoot, err := resolveRootRef(context.Background(), systemAnchor, *root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "peipkg: %v\n", err)
		return 2
	}
	// Whether --root was given explicitly governs default_root: an
	// explicit root always wins over a package's preference (§3.3.6).
	rootExplicit := false
	global.Visit(func(f *flag.Flag) {
		if f.Name == "root" {
			rootExplicit = true
		}
	})

	app := newApp(resolvedRoot, os.Stdin, os.Stdout, os.Stderr)
	app.rootExplicit = rootExplicit
	verb, cmdArgs := rest[0], rest[1:]
	handler, ok := dispatch[verb]
	if !ok {
		fmt.Fprintf(os.Stderr, "peipkg: unknown command %q\n", verb)
		printUsage(os.Stderr)
		return 2
	}
	if err := handler(app, cmdArgs); err != nil {
		fmt.Fprintf(os.Stderr, "peipkg: %v\n", err)
		return 1
	}
	return 0
}

// openDB opens — creating and migrating if necessary — the operating
// root's package database.
func (app *App) openDB(ctx context.Context) (*db.DB, error) {
	return app.openDBAt(ctx, app.paths.root)
}

// openDBAt opens — creating and migrating if necessary — the package
// database of an arbitrary root. It is how a cross-root transaction
// reaches a participating root other than the one invoked (and how a root
// receiving its first cross-root install gets its database created).
func (app *App) openDBAt(ctx context.Context, root string) (*db.DB, error) {
	p := newPaths(root)
	if err := os.MkdirAll(p.stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating %s: %w", p.stateDir, err)
	}
	return db.Open(ctx, p.dbPath)
}

// printf writes a formatted line to the command's standard output.
func (app *App) printf(format string, a ...any) {
	fmt.Fprintf(app.out, format, a...)
}

// emit records an audit event for an operation (§7.6). It stamps the
// event with the current time; emission is best-effort, so a failure
// is reported as a warning, never raised as a fault.
func (app *App) emit(ev audit.Event) {
	ev.Timestamp = time.Now()
	if err := app.emitter.Emit(ev); err != nil {
		fmt.Fprintf(app.errOut, "peipkg: warning: audit emission failed: %v\n", err)
	}
}

// printUsage writes the list of commands to w.
func printUsage(w io.Writer) {
	verbs := make([]string, 0, len(dispatch))
	for v := range dispatch {
		verbs = append(verbs, v)
	}
	sort.Strings(verbs)
	fmt.Fprintf(w, "usage: peipkg [--root DIR] <command> [arguments]\ncommands: %s\n",
		strings.Join(verbs, ", "))
}
