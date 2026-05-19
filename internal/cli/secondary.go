package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/peios/peipkg/internal/db"
)

// cmdSearch searches the configured repositories' active indexes for
// packages whose name or description contains a term.
func cmdSearch(app *App, args []string) error {
	fs := flags("search")
	asJSON := fs.Bool("json", false, "emit JSON")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("search: exactly one search term is required")
	}
	term := strings.ToLower(pos[0])

	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	repos, err := app.configProvider().Repositories()
	if err != nil {
		return err
	}
	client := app.repoClient(store)

	type match struct {
		Name, Version, Repository, Description string
	}
	var matches []match
	for _, cfg := range repos {
		idx, err := client.ActiveIndex(ctx, cfg.Name)
		if err != nil {
			fmt.Fprintf(app.errOut, "peipkg: skipping repository %q: %v\n", cfg.Name, err)
			continue
		}
		for _, e := range idx.Packages {
			if strings.Contains(strings.ToLower(e.Name), term) ||
				strings.Contains(strings.ToLower(e.Description), term) {
				matches = append(matches,
					match{e.Name, e.Version.String(), cfg.Name, e.Description})
			}
		}
	}
	if *asJSON {
		return app.emitJSON(matches)
	}
	if len(matches) == 0 {
		app.printf("no packages match %q\n", pos[0])
		return nil
	}
	for _, m := range matches {
		app.printf("%s  %s  [%s]  %s\n", m.Name, m.Version, m.Repository, m.Description)
	}
	return nil
}

// cmdVerify checks installed packages' files against the content
// recorded for them at install: every regular file's hash, every
// symlink's target, and every directory's presence. With no argument
// it verifies every installed package.
func cmdVerify(app *App, args []string) error {
	fs := flags("verify")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}

	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	names := pos
	if len(names) == 0 {
		pkgs, err := store.ListPackages(ctx)
		if err != nil {
			return err
		}
		for _, p := range pkgs {
			names = append(names, p.Name)
		}
	}

	problems := 0
	for _, name := range names {
		if _, found, err := store.GetPackage(ctx, name); err != nil {
			return err
		} else if !found {
			return fmt.Errorf("verify: %q is not installed", name)
		}
		files, err := store.PackageFiles(ctx, name)
		if err != nil {
			return err
		}
		for _, f := range files {
			if issue := verifyFile(app.paths.root, f); issue != "" {
				app.printf("%s: %s\n", name, issue)
				problems++
			}
		}
	}
	if problems > 0 {
		return fmt.Errorf("verify: %d problem(s) found", problems)
	}
	app.printf("all recorded files are intact\n")
	return nil
}

// verifyFile checks one recorded file against the filesystem, returning
// a description of any problem, or "" when it is intact.
func verifyFile(root string, f db.PackageFile) string {
	physical := filepath.Join(root, f.Path)
	switch f.Type {
	case db.FileTypeDir:
		if info, err := os.Lstat(physical); err != nil || !info.IsDir() {
			return f.Path + " is missing or not a directory"
		}
	case db.FileTypeSymlink:
		target, err := os.Readlink(physical)
		if err != nil {
			return f.Path + " is missing"
		}
		if target != f.SymlinkTarget {
			return fmt.Sprintf("%s points at %q, recorded as %q", f.Path, target, f.SymlinkTarget)
		}
	case db.FileTypeFile:
		got, err := sha256File(physical)
		if err != nil {
			return f.Path + " is missing or unreadable"
		}
		if f.Hash != "" && got != f.Hash {
			return f.Path + " has been modified since install"
		}
	}
	return ""
}

// cmdClean removes cached repository indexes that no longer correspond
// to a configured repository.
func cmdClean(app *App, args []string) error {
	fs := flags("clean")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}

	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	repos, err := app.configProvider().Repositories()
	if err != nil {
		return err
	}
	configured := make(map[string]bool, len(repos))
	for _, r := range repos {
		configured[r.Name] = true
	}

	entries, err := os.ReadDir(app.paths.cacheDir)
	if os.IsNotExist(err) {
		app.printf("the cache is already empty\n")
		return nil
	}
	if err != nil {
		return err
	}
	removed := 0
	for _, e := range entries {
		repo := cachedRepoName(e.Name())
		if repo == "" || configured[repo] {
			continue
		}
		if err := os.Remove(filepath.Join(app.paths.cacheDir, e.Name())); err != nil {
			return err
		}
		removed++
	}
	app.printf("removed %d orphaned cache file(s)\n", removed)
	return nil
}

// cachedRepoName extracts the repository name from a cached index
// filename (<repo>.active.json or <repo>.active.json.sig), or "" if the
// filename is not a cached index.
func cachedRepoName(filename string) string {
	for _, suffix := range []string{".active.json.sig", ".active.json"} {
		if name, ok := strings.CutSuffix(filename, suffix); ok {
			return name
		}
	}
	return ""
}

// sha256File returns the lowercase-hex SHA-256 of a file's content.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
