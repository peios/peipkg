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

	"github.com/peios/peipkg/internal/db"
)

// peipkgVersion is the peipkg build version, recorded on every
// transaction.
const peipkgVersion = "0.1.0"

// paths locates peipkg's files beneath an operating root.
type paths struct {
	root      string // the install root — "/" in normal use
	stateDir  string // <root>/var/lib/peipkg — the database, lock, caches
	configDir string // <root>/conf/peipkg — the repository .repo files
	dbPath    string
	lockPath  string
	cacheDir  string // verified repository indexes
}

// App is the context shared by every peipkg command.
type App struct {
	paths  paths
	in     io.Reader
	reader *bufio.Reader // buffers in; shared so prompts do not lose input
	out    io.Writer
	errOut io.Writer
}

// newApp builds an App rooted at root, reading from in and writing to
// out and errOut.
func newApp(root string, in io.Reader, out, errOut io.Writer) *App {
	state := filepath.Join(root, "var/lib/peipkg")
	return &App{
		paths: paths{
			root:      root,
			stateDir:  state,
			configDir: filepath.Join(root, "conf/peipkg"),
			dbPath:    filepath.Join(state, "db.sqlite"),
			lockPath:  filepath.Join(state, "lock"),
			cacheDir:  filepath.Join(state, "cache"),
		},
		in:     in,
		reader: bufio.NewReader(in),
		out:    out,
		errOut: errOut,
	}
}

// command is the handler for one peipkg verb.
type command func(app *App, args []string) error

// dispatch maps each verb to its handler.
var dispatch map[string]command

func init() {
	dispatch = map[string]command{
		"install":   cmdInstall,
		"upgrade":   cmdUpgrade,
		"uninstall": cmdUninstall,
		"remove":    cmdUninstall, // alias
		"list":      cmdList,
		"info":      cmdInfo,
		"files":     cmdFiles,
		"owns":      cmdOwns,
		"search":    cmdSearch,
		"verify":    cmdVerify,
		"history":   cmdHistory,
		"repo":      cmdRepo,
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

	app := newApp(*root, os.Stdin, os.Stdout, os.Stderr)
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

// openDB opens — creating and migrating if necessary — the package
// database.
func (app *App) openDB(ctx context.Context) (*db.DB, error) {
	if err := os.MkdirAll(app.paths.stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating %s: %w", app.paths.stateDir, err)
	}
	return db.Open(ctx, app.paths.dbPath)
}

// printf writes a formatted line to the command's standard output.
func (app *App) printf(format string, a ...any) {
	fmt.Fprintf(app.out, format, a...)
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
