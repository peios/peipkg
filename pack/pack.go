// Package pack exposes the peipkg package-production API for external
// build tools.
//
// The implementation remains in peipkg's internal packages. This facade
// is intentionally narrow and purely struct-driven: the caller supplies
// a fully-resolved [Manifest] and a staged payload tree on disk, and
// [Pack] emits one byte-deterministic .peipkg conforming to PSD-009 §3.
// All parsing — recipes, manifest documents, key files — is the
// caller's job; nothing here reads configuration from disk.
//
// Higher-level build orchestration (running build scripts, deciding
// which build output lands where, resolving recipe conveniences) also
// belongs to the caller. [PackOptions.Files] and [ValidateFiles] are
// the seams provided for it.
package pack

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"sort"

	internalmanifest "github.com/peios/peipkg/internal/build/manifest"
	internalpack "github.com/peios/peipkg/internal/build/pack"
)

// Manifest is the fully-resolved metadata of one package (PSD-009
// §3.3). The caller supplies every declared field; schema_version and
// size_installed are computed during packing and cannot be declared.
//
// Array fields need not be pre-sorted: Pack sorts them into the
// canonical on-wire order and rejects duplicate names within a field
// (§4.1).
type Manifest struct {
	Name         string
	Version      string
	Architecture string
	Description  string
	License      string
	Homepage     string

	Dependencies         []Dependency
	OptionalDependencies []Dependency
	Conflicts            []Dependency
	Provides             []Provides
	Replaces             []Replaces

	// SideEffects values come from the §4.3.4 enumerated set. Emitted
	// in the order given.
	SideEffects []string

	// SDOverrides are §3.3.5 security-descriptor overrides. SD is the
	// base64-encoded binary self-relative SD.
	SDOverrides []SDOverride

	// Build is the §3.3.4 build-provenance object. Required.
	Build BuildInfo
}

// Dependency is one entry in Dependencies, OptionalDependencies, or
// Conflicts (§4.1.1, §4.1.2). It is fully resolved: recipe-level
// conveniences like same_build pinning are the caller's concern.
type Dependency struct {
	Name       string
	Constraint string // e.g. ">= 1.2", empty = any version
	Arch       string // empty = any architecture
}

// Provides is one entry in the provides array (§4.1.4).
type Provides struct {
	Name    string
	Version string
}

// Replaces is one entry in the replaces array (§4.1.5).
type Replaces struct {
	Name       string
	Constraint string
}

// SDOverride is one entry in the sd_overrides array (§3.3.5).
type SDOverride struct {
	Path string
	SD   string
}

// BuildInfo is the build-provenance object (§3.3.4). Timestamp MUST be
// an RFC 3339 UTC instant with the 'Z' zone designator; it drives every
// tar entry's modification time (§3.1.4 #2).
type BuildInfo struct {
	Timestamp string
	FarmID    string
	SourceRef string
}

// PackOptions is everything Pack needs to emit one .peipkg. The payload
// is supplied as exactly one of StagedRoot and Files.
type PackOptions struct {
	// Manifest is the package's fully-resolved metadata.
	Manifest Manifest

	// StagedRoot is the root of a staged payload tree on disk whose
	// layout is the archive layout. Every regular file and symlink
	// under it is included.
	StagedRoot string

	// Files maps archive paths (clean, slash-separated, relative — e.g.
	// "usr/bin/foo") to source paths on disk. Sources may live anywhere
	// in any layout; nothing is staged or copied, each source is read
	// once directly into the archive. A source's type decides the entry
	// kind: regular file, symlink (target preserved verbatim), or
	// directory (an explicit empty-directory payload entry). Mapping an
	// archive path underneath a non-directory entry is an error.
	//
	// In both forms, ancestor directories of every included entry are
	// emitted automatically.
	Files map[string]string

	// SignKey, when non-nil, signs the package per §5.1. Nil produces
	// an unsigned package (still spec-conformant per §5.1.7).
	SignKey ed25519.PrivateKey

	// Out receives the compressed .peipkg bytes. Pack streams its
	// output and does not seek; Out may be a file, a buffer, or a
	// network sink.
	Out io.Writer
}

// Pack assembles and writes one .peipkg. Given identical inputs, two
// invocations produce byte-identical output (§3.1.4).
func Pack(opts PackOptions) error {
	m, err := toInternalManifest(opts.Manifest)
	if err != nil {
		return fmt.Errorf("pack: manifest: %w", err)
	}
	return internalpack.Pack(internalpack.Input{
		StagedRoot: opts.StagedRoot,
		Files:      opts.Files,
		Manifest:   m,
		SignKey:    opts.SignKey,
		Out:        opts.Out,
	})
}

// ValidatePayload runs the PSD-009 §3.4 layout checks over a staged
// tree: permitted top-level destinations (§3.4.1), /usr/lib/<triplet>/
// coherence against architecture (§3.4.2), the empty-/var/ rule
// (§3.4.4), and symlink-target containment (§3.4.10).
//
// Validation is a separate, opt-in call rather than part of [Pack]:
// exotic packages (a kernel's /boot tree, for one) deliberately stage
// layouts the strict rules reject. Ordinary producers should validate
// before packing so violations surface at build time rather than at
// install time on a target system. Failures are aggregated so a single
// run reports every problem.
func ValidatePayload(architecture, stagedRoot string) error {
	return internalpack.ValidatePayload(architecture, stagedRoot)
}

// ValidateFiles runs the same §3.4 layout checks over an explicit
// archive-path -> source-path map, the [PackOptions.Files] counterpart
// to [ValidatePayload]. Checks apply to the archive paths; sources are
// only consulted for entry kinds and symlink targets, so they must
// exist.
func ValidateFiles(architecture string, files map[string]string) error {
	return internalpack.ValidateFiles(architecture, files)
}

// toInternalManifest converts the public manifest into its internal
// on-wire form: each name-keyed array is checked for duplicates (§4.1
// forbids identical names within a field) and sorted into canonical
// order, and sd_overrides is sorted by path (§3.3.5).
func toInternalManifest(m Manifest) (internalmanifest.Manifest, error) {
	deps, err := convertDeps(m.Dependencies, "dependencies")
	if err != nil {
		return internalmanifest.Manifest{}, err
	}
	optDeps, err := convertDeps(m.OptionalDependencies, "optional_dependencies")
	if err != nil {
		return internalmanifest.Manifest{}, err
	}
	conflicts, err := convertDeps(m.Conflicts, "conflicts")
	if err != nil {
		return internalmanifest.Manifest{}, err
	}

	provides := make([]internalmanifest.Provides, 0, len(m.Provides))
	seenProv := make(map[string]struct{}, len(m.Provides))
	for _, v := range m.Provides {
		if _, dup := seenProv[v.Name]; dup {
			return internalmanifest.Manifest{}, fmt.Errorf("provides: duplicate name %q", v.Name)
		}
		seenProv[v.Name] = struct{}{}
		provides = append(provides, internalmanifest.Provides{Name: v.Name, Version: v.Version})
	}
	sort.Slice(provides, func(i, j int) bool { return provides[i].Name < provides[j].Name })

	replaces := make([]internalmanifest.Replaces, 0, len(m.Replaces))
	seenRepl := make(map[string]struct{}, len(m.Replaces))
	for _, v := range m.Replaces {
		if _, dup := seenRepl[v.Name]; dup {
			return internalmanifest.Manifest{}, fmt.Errorf("replaces: duplicate name %q", v.Name)
		}
		seenRepl[v.Name] = struct{}{}
		replaces = append(replaces, internalmanifest.Replaces{Name: v.Name, Constraint: v.Constraint})
	}
	sort.Slice(replaces, func(i, j int) bool { return replaces[i].Name < replaces[j].Name })

	overrides := make([]internalmanifest.SDOverride, 0, len(m.SDOverrides))
	seenOver := make(map[string]struct{}, len(m.SDOverrides))
	for _, v := range m.SDOverrides {
		if _, dup := seenOver[v.Path]; dup {
			return internalmanifest.Manifest{}, fmt.Errorf("sd_overrides: duplicate path %q", v.Path)
		}
		seenOver[v.Path] = struct{}{}
		overrides = append(overrides, internalmanifest.SDOverride{Path: v.Path, SD: v.SD})
	}
	sort.Slice(overrides, func(i, j int) bool { return overrides[i].Path < overrides[j].Path })

	return internalmanifest.Manifest{
		Name:                 m.Name,
		Version:              m.Version,
		Architecture:         m.Architecture,
		Description:          m.Description,
		License:              m.License,
		Homepage:             m.Homepage,
		Dependencies:         deps,
		OptionalDependencies: optDeps,
		Conflicts:            conflicts,
		Provides:             provides,
		Replaces:             replaces,
		SideEffects:          append([]string(nil), m.SideEffects...),
		SDOverrides:          overrides,
		Build: internalmanifest.Build{
			Timestamp: m.Build.Timestamp,
			FarmID:    m.Build.FarmID,
			SourceRef: m.Build.SourceRef,
		},
	}, nil
}

func convertDeps(in []Dependency, field string) ([]internalmanifest.Dependency, error) {
	out := make([]internalmanifest.Dependency, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, d := range in {
		if _, dup := seen[d.Name]; dup {
			return nil, fmt.Errorf("%s: duplicate name %q (PSD-009 §4.1 forbids identical names within a field)", field, d.Name)
		}
		seen[d.Name] = struct{}{}
		out = append(out, internalmanifest.Dependency{
			Name:       d.Name,
			Constraint: d.Constraint,
			Arch:       d.Arch,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
