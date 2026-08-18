package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/peios/peipkg/internal/db"
)

// systemAnchor is the implicit anchor for a named --root reference: the
// first segment of a reference is looked up in this root's registry
// (DESIGN-named-roots.md D3). On a running system it is the filesystem
// root; named-root topology describes a single system rooted there.
const systemAnchor = "/"

// rootNameHelp describes the named-root grammar for error messages: a
// segment is a lowercase letter or digit followed by any of lowercase
// letters, digits, '-' and '_'; '.' separates segments of a nested
// reference (§3.3.6, DESIGN-named-roots.md D2).
const rootNameHelp = "a root name is a lowercase letter or digit followed by " +
	"lowercase letters, digits, '-' or '_'; nest with '.'"

// validRootSegment reports whether s is a single valid root-name segment:
// [a-z0-9][a-z0-9_-]* (no '.', no '/').
func validRootSegment(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			// always allowed
		case (r == '-' || r == '_') && i > 0:
			// allowed after the first character
		default:
			return false
		}
	}
	return true
}

// parseRootName splits a bare (non-path) reference into its dotted
// segments, validating each against the segment grammar.
func parseRootName(ref string) ([]string, error) {
	segments := strings.Split(ref, ".")
	for _, seg := range segments {
		if !validRootSegment(seg) {
			return nil, fmt.Errorf("invalid root reference %q (%s)", ref, rootNameHelp)
		}
	}
	return segments, nil
}

// resolveRootRef resolves a --root reference to a filesystem path
// (DESIGN-named-roots.md D2/D3):
//
//   - A reference containing '/' is a literal filesystem path, returned
//     unchanged — every existing invocation keeps its meaning.
//   - A bare dotted identifier is a named-root reference, resolved by
//     walking registries from anchor: the first segment is looked up in
//     anchor's registry, the next in that child's registry, and so on.
//
// An unregistered segment is a hard error — never a silently-created or
// relative-path fallback. A reference whose resolution loops back into an
// already-visited root is rejected as a cycle.
func resolveRootRef(ctx context.Context, anchor, ref string) (string, error) {
	if ref == "" {
		return "", errors.New("empty root reference")
	}
	if strings.ContainsRune(ref, '/') {
		return ref, nil // literal path — today's behaviour, untouched
	}
	segments, err := parseRootName(ref)
	if err != nil {
		return "", err
	}

	current := anchor
	startAbs, err := filepath.Abs(anchor)
	if err != nil {
		return "", err
	}
	visited := map[string]bool{startAbs: true}

	for _, seg := range segments {
		store, exists, err := openRootDB(ctx, current)
		if err != nil {
			return "", err
		}
		if !exists {
			return "", fmt.Errorf("named root %q is not registered", seg)
		}
		rel, found, err := store.NamedRoot(ctx, seg)
		_ = store.Close()
		if err != nil {
			return "", err
		}
		if !found {
			return "", fmt.Errorf("named root %q is not registered", seg)
		}
		current = filepath.Join(current, rel)
		abs, err := filepath.Abs(current)
		if err != nil {
			return "", err
		}
		if visited[abs] {
			return "", fmt.Errorf("root reference %q forms a resolution cycle at %s", ref, current)
		}
		visited[abs] = true
	}
	return current, nil
}

// openRootDB opens the package database of the root at path, without
// creating it. exists is false — with a nil store and nil error — when
// the root has no database yet, which for resolution means the root holds
// no registry (so a name looked up there is simply unregistered).
func openRootDB(ctx context.Context, root string) (store *db.DB, exists bool, err error) {
	dbPath := filepath.Join(root, "var/state/peipkg/db.sqlite")
	if _, err := os.Stat(dbPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("stat %s: %w", dbPath, err)
	}
	store, err = db.Open(ctx, dbPath)
	if err != nil {
		return nil, false, err
	}
	return store, true, nil
}

// relativeToRoot returns path expressed relative to root, for storage in
// the registry — a registered path is stored relative to its owning root
// so the whole tree stays relocatable. A path already relative is cleaned
// and kept; an absolute path is made relative to root.
func relativeToRoot(root, path string) (string, error) {
	if !filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absRoot, path)
	if err != nil {
		return "", fmt.Errorf("expressing %s relative to root %s: %w", path, root, err)
	}
	return rel, nil
}

// rootStatus reports "present" if path is a directory on disk, else
// "dangling" — a registered root whose tree no longer exists (D3).
func rootStatus(path string) string {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return "present"
	}
	return "dangling"
}

// gatherRootRefs resolves every named root reachable from anchor to its
// path, returning a map keyed by the dotted reference a dependency's
// `root` field would name (initramfs, initramfs.subroot, …). It is the
// caller's bridge between the named references in package metadata and the
// resolved root keys the multi-root resolver and executor work in.
func gatherRootRefs(ctx context.Context, anchor string) (map[string]string, error) {
	startAbs, err := filepath.Abs(anchor)
	if err != nil {
		return nil, err
	}
	views, err := collectRoots(ctx, anchor, true, map[string]bool{startAbs: true})
	if err != nil {
		return nil, err
	}
	refs := map[string]string{}
	var walk func(prefix string, vs []rootView)
	walk = func(prefix string, vs []rootView) {
		for _, v := range vs {
			ref := v.Name
			if prefix != "" {
				ref = prefix + "." + v.Name
			}
			refs[ref] = v.ResolvedPath
			walk(ref, v.Children)
		}
	}
	walk("", views)
	return refs, nil
}

// newCrossRootID returns a fresh identifier tying together the per-root
// journal rows of one cross-root transaction.
func newCrossRootID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating a cross-root transaction id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// cmdRoot dispatches the root subcommands (DESIGN-named-roots.md → CLI
// surface).
func cmdRoot(app *App, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("root: a subcommand is required (add, remove, list, show)")
	}
	switch sub, rest := args[0], args[1:]; sub {
	case "add":
		return cmdRootAdd(app, rest)
	case "remove":
		return cmdRootRemove(app, rest)
	case "list":
		return cmdRootList(app, rest)
	case "show":
		return cmdRootShow(app, rest)
	default:
		return fmt.Errorf("root: unknown subcommand %q", sub)
	}
}

// cmdRootAdd registers a named root in the current root's registry. The
// path is stored relative to the current root.
func cmdRootAdd(app *App, args []string) error {
	fs := flags("root add")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("root add: usage: root add <name> <path>")
	}
	name, path := pos[0], pos[1]
	if !validRootSegment(name) {
		return fmt.Errorf("root add: %q is not a valid root name (%s)", name, rootNameHelp)
	}
	rel, err := relativeToRoot(app.paths.root, path)
	if err != nil {
		return err
	}

	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.SetNamedRoot(ctx, name, rel); err != nil {
		return err
	}
	app.printf("registered root %q -> %s\n", name, rel)
	return nil
}

// cmdRootRemove unregisters a named root. Files are left in place unless
// --purge is given, which deletes the root's tree.
func cmdRootRemove(app *App, args []string) error {
	fs := flags("root remove")
	purge := fs.Bool("purge", false, "also delete the root's filesystem tree")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("root remove: usage: root remove <name> [--purge]")
	}
	name := pos[0]
	if !validRootSegment(name) {
		return fmt.Errorf("root remove: %q is not a valid root name (%s)", name, rootNameHelp)
	}

	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	rel, found, err := store.NamedRoot(ctx, name)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("root remove: %q is not registered", name)
	}
	if err := store.DeleteNamedRoot(ctx, name); err != nil {
		return err
	}
	app.printf("unregistered root %q\n", name)

	if *purge {
		target := filepath.Join(app.paths.root, rel)
		if err := os.RemoveAll(target); err != nil {
			return fmt.Errorf("purging %s: %w", target, err)
		}
		app.printf("purged %s\n", target)
	}
	return nil
}

// rootView is the listing/JSON shape of one registered root.
type rootView struct {
	Name         string     `json:"name"`
	Path         string     `json:"path"` // as registered, relative to its parent
	ResolvedPath string     `json:"resolved_path"`
	Status       string     `json:"status"` // present | dangling
	Children     []rootView `json:"children,omitempty"`
}

// collectRoots lists the registry of the root at path. When recurse is
// set, it descends into each present child's own registry; a visited-set
// of resolved absolute paths guards cycles and double-visits.
func collectRoots(ctx context.Context, path string, recurse bool, visited map[string]bool) ([]rootView, error) {
	store, exists, err := openRootDB(ctx, path)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	entries, err := store.NamedRoots(ctx)
	_ = store.Close()
	if err != nil {
		return nil, err
	}

	var views []rootView
	for _, e := range entries {
		resolved := filepath.Join(path, e.Path)
		v := rootView{Name: e.Name, Path: e.Path, ResolvedPath: resolved, Status: rootStatus(resolved)}
		if recurse && v.Status == "present" {
			abs, err := filepath.Abs(resolved)
			if err != nil {
				return nil, err
			}
			if !visited[abs] {
				visited[abs] = true
				children, err := collectRoots(ctx, resolved, recurse, visited)
				if err != nil {
					return nil, err
				}
				v.Children = children
			}
		}
		views = append(views, v)
	}
	return views, nil
}

// cmdRootList prints the current root's registry, optionally recursing.
func cmdRootList(app *App, args []string) error {
	fs := flags("root list")
	asJSON := fs.Bool("json", false, "emit JSON")
	tree := fs.Bool("tree", false, "recurse through child registries")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx := context.Background()
	startAbs, err := filepath.Abs(app.paths.root)
	if err != nil {
		return err
	}
	views, err := collectRoots(ctx, app.paths.root, *tree, map[string]bool{startAbs: true})
	if err != nil {
		return err
	}

	if *asJSON {
		if views == nil {
			views = []rootView{}
		}
		return app.emitJSON(views)
	}
	if len(views) == 0 {
		app.printf("no named roots registered\n")
		return nil
	}
	printRootViews(app, views, 0)
	return nil
}

// printRootViews renders a registry listing, indenting nested children.
func printRootViews(app *App, views []rootView, depth int) {
	indent := strings.Repeat("  ", depth)
	for _, v := range views {
		suffix := ""
		if v.Status != "present" {
			suffix = "  (" + v.Status + ")"
		}
		app.printf("%s%s -> %s%s\n", indent, v.Name, v.Path, suffix)
		printRootViews(app, v.Children, depth+1)
	}
}

// cmdRootShow resolves a reference and reports its path, status, and
// installed-package count.
func cmdRootShow(app *App, args []string) error {
	fs := flags("root show")
	asJSON := fs.Bool("json", false, "emit JSON")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("root show: usage: root show <reference>")
	}
	ref := pos[0]

	ctx := context.Background()
	resolved, err := resolveRootRef(ctx, app.paths.root, ref)
	if err != nil {
		return err
	}
	status := rootStatus(resolved)

	packages := 0
	if status == "present" {
		store, exists, err := openRootDB(ctx, resolved)
		if err != nil {
			return err
		}
		if exists {
			pkgs, err := store.ListPackages(ctx)
			_ = store.Close()
			if err != nil {
				return err
			}
			packages = len(pkgs)
		}
	}

	if *asJSON {
		return app.emitJSON(struct {
			Reference string `json:"reference"`
			Path      string `json:"path"`
			Status    string `json:"status"`
			Packages  int    `json:"packages"`
		}{ref, resolved, status, packages})
	}
	app.printf("reference: %s\npath:      %s\nstatus:    %s\npackages:  %d\n",
		ref, resolved, status, packages)
	return nil
}
