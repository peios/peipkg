package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/peios/peipkg/internal/safepath"
)

// pinnedDirs holds an open descriptor on the parent directory of every
// path a transaction touches, from the moment the plan is computed
// until the commit that acts on it.
//
// PSPU §5.26 asks for two things and they are separate. Resolving
// without following a symlink stops a payload entry whose *ancestor* is
// a symlink from redirecting a write, which needs no race at all.
// Holding the descriptor closes the window between the plan and the
// commit — which in this codebase spans every download, decompression
// and staging step of the whole transaction, and had nothing pinning
// the directory across it.
//
// A cache entry is per directory, not per file, so the descriptor count
// is the number of distinct directories the transaction writes into.
type pinnedDirs struct {
	root *safepath.Root
	dirs map[string]*safepath.Dir
}

func newPinnedDirs(rootPath string) (*pinnedDirs, error) {
	// The root itself is operator-supplied — `peipkg install --root`,
	// or a composed tree's directory — so creating it is outside the
	// boundary this package defends. Everything beneath it is not.
	if err := os.MkdirAll(rootPath, 0o755); err != nil {
		return nil, fmt.Errorf("peipkg/install: creating the installation root: %w", err)
	}
	r, err := safepath.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	return &pinnedDirs{root: r, dirs: map[string]*safepath.Dir{}}, nil
}

// close releases every descriptor. It is called once the transaction
// can no longer act on disk.
func (p *pinnedDirs) close() {
	if p == nil {
		return
	}
	for _, d := range p.dirs {
		_ = d.Close()
	}
	p.dirs = nil
	_ = p.root.Close()
}

// dirFor pins the parent directory of an absolute path under the root,
// creating missing components. The returned directory is cached, so the
// plan and the commit act on the same descriptor.
func (p *pinnedDirs) dirFor(absPath string) (*safepath.Dir, error) {
	rel, err := p.rel(absPath)
	if err != nil {
		return nil, err
	}
	dirRel, _ := safepath.Split(rel)
	return p.mkdirAll(dirRel)
}

// existingDirFor is dirFor without creating anything: it is how the
// recovery path resolves a journalled string. A directory that is no
// longer there yields (nil, nil) — there is nothing left to undo under
// it, and inventing it would be worse than leaving it alone.
func (p *pinnedDirs) existingDirFor(absPath string) (*safepath.Dir, error) {
	rel, err := p.rel(absPath)
	if err != nil {
		return nil, err
	}
	dirRel, _ := safepath.Split(rel)
	if d, ok := p.dirs[dirRel]; ok {
		return d, nil
	}
	d, err := p.root.Dir(dirRel)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.dirs[dirRel] = d
	return d, nil
}

// mkdirAllAbs pins an absolute path under the root as a directory,
// creating it and any missing ancestors.
func (p *pinnedDirs) mkdirAllAbs(absPath string) (*safepath.Dir, error) {
	rel, err := p.rel(absPath)
	if err != nil {
		return nil, err
	}
	return p.mkdirAll(rel)
}

func (p *pinnedDirs) mkdirAll(dirRel string) (*safepath.Dir, error) {
	if d, ok := p.dirs[dirRel]; ok {
		return d, nil
	}
	d, err := p.root.MkdirAll(dirRel, 0o755)
	if err != nil {
		return nil, err
	}
	p.dirs[dirRel] = d
	return d, nil
}

// rel turns an absolute path under the root into a root-relative one. A
// path outside the root is a programming error, not an attack: every
// caller built it by joining onto env.Root.
func (p *pinnedDirs) rel(absPath string) (string, error) {
	rel, err := filepath.Rel(p.root.Path(), absPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("peipkg/install: %s is not under the installation root %s",
			absPath, p.root.Path())
	}
	return rel, nil
}
