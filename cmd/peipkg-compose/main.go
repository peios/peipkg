// Command peipkg-compose builds a populated peipkg root directory from
// a declarative manifest. It is the image-assembly counterpart to the
// peipkg consumer command: peipkg mutates a live system; peipkg-compose
// builds a fresh root from nothing.
//
// Two verbs:
//
//	peipkg-compose lock  <manifest> [-o <lock>]
//	peipkg-compose build <manifest> --out <dir> [--locked] [--update]
//
// See cmd/peipkg-compose/DESIGN.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/peios/peipkg/internal/compose"
	"github.com/peios/peipkg/internal/repository"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run dispatches a verb and returns the process exit code. Splitting it
// from main lets tests drive it without an os.Exit.
func run(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}
	switch verb, rest := args[0], args[1:]; verb {
	case "lock":
		return cmdLock(rest)
	case "build":
		return cmdBuild(rest)
	case "-h", "--help", "help":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "peipkg-compose: unknown command %q\n", verb)
		usage(os.Stderr)
		return 2
	}
}

func usage(w *os.File) {
	fmt.Fprintln(w, `usage:
  peipkg-compose lock  <manifest> [-o <lock>]
                     resolve the manifest and write the lock
  peipkg-compose build <manifest> --out <dir> [--locked] [--update]
                     produce a populated root from a manifest

flags for build:
  --locked   require an existing lock; do not resolve
  --update   re-resolve and overwrite any existing lock`)
}

// parseOneManifest parses a flag set that takes exactly one positional —
// the manifest path — and tolerates it appearing either before or after
// the flags. Go's flag package stops at the first non-flag token, so the
// natural `<verb> <manifest> --out <dir>` form would otherwise leave the
// flags unparsed; lifting a leading positional out before Parse accepts
// both orderings.
func parseOneManifest(fs *flag.FlagSet, args []string) (string, error) {
	var manifest string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		manifest, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	rest := fs.Args()
	if manifest == "" && len(rest) > 0 {
		manifest, rest = rest[0], rest[1:]
	}
	if manifest == "" {
		return "", fmt.Errorf("a manifest path is required")
	}
	if len(rest) > 0 {
		return "", fmt.Errorf("unexpected extra arguments: %v", rest)
	}
	return manifest, nil
}

// cmdLock implements `peipkg-compose lock`.
func cmdLock(args []string) int {
	fs := flag.NewFlagSet("lock", flag.ContinueOnError)
	out := fs.String("o", "", "output lock path (default <manifest>.lock.toml)")
	manifest, err := parseOneManifest(fs, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "peipkg-compose lock:", err)
		return 2
	}
	err = compose.LockManifest(context.Background(), manifest, *out,
		repository.NewHTTPFetcher(), os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "peipkg-compose: %v\n", err)
		return 1
	}
	return 0
}

// cmdBuild implements `peipkg-compose build`.
func cmdBuild(args []string) int {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	out := fs.String("out", "", "output root directory")
	locked := fs.Bool("locked", false, "require an existing lock; do not resolve")
	update := fs.Bool("update", false, "re-resolve and overwrite the lock")
	manifest, err := parseOneManifest(fs, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "peipkg-compose build:", err)
		return 2
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "peipkg-compose build: --out is required")
		return 2
	}
	err = compose.Build(context.Background(), compose.BuildOptions{
		ManifestPath: manifest,
		OutDir:       *out,
		Locked:       *locked,
		Update:       *update,
		Fetcher:      repository.NewHTTPFetcher(),
		Warnings:     os.Stderr,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "peipkg-compose: %v\n", err)
		return 1
	}
	return 0
}
