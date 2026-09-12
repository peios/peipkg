package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// reclaimDirectories removes, deepest-first, every directory the
// transaction released ownership of that is now owned by no package and
// is empty (§7.3.3, §7.2.4). It runs after the commit, because "owned
// by no package" is a question about the committed ownership rows: a
// removed package's rows are gone only then, and an upgrade's new rows
// exist only then.
//
// A removal used to skip directory entries outright, so uninstalling a
// package left its whole directory skeleton behind — and, because the
// package's rows were cascaded away with it, left those directories
// owned by nothing, which no later operation would ever reclaim.
//
// Anything that stops a directory being removed is a reason to keep it,
// not an error: another package still owns it, an operator or a runtime
// has put something in it, or it is already gone. Only an unexpected
// failure is reported, and only as a warning — the transaction has
// committed and the directory is merely untidy.
func reclaimDirectories(ctx context.Context, env Env, pins *pinnedDirs,
	staged []stagedOp) []string {

	seen := map[string]bool{}
	var dirs []string
	for _, s := range staged {
		for _, d := range s.removedDirs {
			if !seen[d] {
				seen[d] = true
				dirs = append(dirs, d)
			}
		}
	}
	// Deepest first, so a directory is attempted after everything it
	// contained; equal depth in reverse lexical order for determinism.
	sort.Slice(dirs, func(i, j int) bool {
		di, dj := strings.Count(dirs[i], "/"), strings.Count(dirs[j], "/")
		if di != dj {
			return di > dj
		}
		return dirs[i] > dirs[j]
	})

	var warnings []string
	for _, logical := range dirs {
		owners, err := env.DB.FileOwners(ctx, logical)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf(
				"could not decide whether %s is still owned: %v", logical, err))
			continue
		}
		if len(owners) > 0 {
			continue
		}
		physical := filepath.Join(env.Root, logical)
		if filepath.Clean(physical) == filepath.Clean(env.Root) {
			continue // the root itself is never a candidate
		}
		// The parent is pinned like every other operation's: the entry
		// removed must be the one the path named when it was resolved,
		// not whatever a swapped component resolves to now (§5.26).
		parent, err := pins.existingDirFor(physical)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf(
				"could not reclaim %s: %v", logical, err))
			continue
		}
		if parent == nil {
			continue // the parent is gone, so this is too
		}
		err = parent.RemoveDir(filepath.Base(physical))
		switch {
		case err == nil, errors.Is(err, os.ErrNotExist),
			errors.Is(err, unix.ENOTEMPTY), errors.Is(err, unix.EEXIST),
			errors.Is(err, unix.ENOTDIR):
			// Removed, already gone, still populated, or not a directory
			// any more: nothing to say.
		default:
			warnings = append(warnings, fmt.Sprintf(
				"could not reclaim the empty directory %s: %v", logical, err))
		}
	}
	return warnings
}
