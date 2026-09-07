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
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
                     [--record-xattrs <file>]
                     produce a populated root from a manifest

flags for build:
  --locked               require an existing lock; do not resolve
  --update               re-resolve and overwrite any existing lock
  --record-xattrs <file> record implied security xattrs as JSONL instead of setting them`)
}

// recordedXattr is the CLI's portable representation of an attribute that
// compose would otherwise set on the output tree. encoding/json represents
// Value as standard base64, so the record is safe JSONL even when
// the attribute contains an arbitrary binary security descriptor.
type recordedXattr struct {
	Path  string `json:"path"`
	Name  string `json:"name"`
	Value []byte `json:"value"`
}

type xattrKey struct {
	path string
	name string
}

// xattrRecorder collects records in memory because package extraction is
// parallel. Sorting after a successful compose makes the sidecar reproducible
// regardless of goroutine completion order.
type xattrRecorder struct {
	values map[xattrKey][]byte
}

func newXattrRecorder() *xattrRecorder {
	return &xattrRecorder{values: map[xattrKey][]byte{}}
}

func (r *xattrRecorder) Record(path, name string, value []byte) error {
	key := xattrKey{path: path, name: name}
	if previous, ok := r.values[key]; ok {
		if bytes.Equal(previous, value) {
			return nil
		}
		return fmt.Errorf("conflicting values recorded for %s on %s", name, path)
	}
	r.values[key] = append([]byte(nil), value...)
	return nil
}

// Write creates path without replacing an existing record. The temporary file
// and final hard link are siblings, so publication is atomic and cannot race
// into overwriting a caller-owned file.
func (r *xattrRecorder) Write(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	} else if !os.IsNotExist(err) {
		return err
	}

	keys := make([]xattrKey, 0, len(r.values))
	for key := range r.values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].path != keys[j].path {
			return keys[i].path < keys[j].path
		}
		return keys[i].name < keys[j].name
	})

	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	enc := json.NewEncoder(f)
	for _, key := range keys {
		if err := enc.Encode(recordedXattr{
			Path: key.path, Name: key.name, Value: r.values[key],
		}); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Link(tmp, path); err != nil {
		return err
	}
	return nil
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
	bypassPaths := fs.Bool("dangerously-bypass-path-restrictions", false,
		"permit packages declaring special_system_package to compose outside the §3.4 layout")
	recordXattrs := fs.String("record-xattrs", "",
		"record implied security xattrs as JSONL instead of setting them")
	manifest, err := parseOneManifest(fs, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "peipkg-compose build:", err)
		return 2
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "peipkg-compose build: --out is required")
		return 2
	}
	var recorder *xattrRecorder
	if *recordXattrs != "" {
		recorder = newXattrRecorder()
	}
	err = compose.Build(context.Background(), compose.BuildOptions{
		ManifestPath: manifest,
		OutDir:       *out,
		Locked:       *locked,
		Update:       *update,
		Fetcher:      repository.NewHTTPFetcher(),
		Warnings:     os.Stderr,

		BypassPathRestrictions: *bypassPaths,
		RecordXattr: func() func(string, string, []byte) error {
			if recorder == nil {
				return nil
			}
			return recorder.Record
		}(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "peipkg-compose: %v\n", err)
		return 1
	}
	if recorder != nil {
		if err := recorder.Write(*recordXattrs); err != nil {
			fmt.Fprintf(os.Stderr, "peipkg-compose: writing xattr record: %v\n", err)
			return 1
		}
	}
	return 0
}
