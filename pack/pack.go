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
	"encoding/base64"
	"fmt"
	"io"
	"sort"

	"github.com/peios/libp-go/sddl"

	internalmanifest "github.com/peios/peipkg/internal/build/manifest"
	internalpack "github.com/peios/peipkg/internal/build/pack"
	consumermanifest "github.com/peios/peipkg/internal/manifest"
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

	// DefaultRoot is the package's top-level placement preference — the
	// named root a top-level install lands in (§3.3.6,
	// DESIGN-named-roots.md). Empty for a package with no preference. It
	// is a root reference (a named reference, never a path).
	DefaultRoot string

	// SpecialSystemPackage marks a package exempt from the §3.4 payload
	// layout rules: fsbase's mountpoint tree, the kernel, and the few
	// others whose job is to lay down the very structure those rules
	// protect. Declaring it makes [ValidatePayload] and [ValidateFiles]
	// no-ops for this package.
	//
	// It grants nothing at install time. An installer refuses an
	// out-of-layout payload unless the operator ALSO passes
	// --dangerously-bypass-path-restrictions (or the compose
	// equivalent). A package may propose its own exemption; only the
	// operator can grant it.
	SpecialSystemPackage bool

	Dependencies         []Dependency
	OptionalDependencies []Dependency
	Conflicts            []Dependency
	Provides             []Provides
	Replaces             []Replaces

	// SideEffects values come from the §4.3.4 enumerated set. Emitted
	// in the order given.
	SideEffects []string

	// SDOverrides are §3.3.5 security-descriptor overrides, supplied
	// in binary or SDDL form; Pack owns the on-wire encoding.
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
	// Root places this dependency in a named root other than the
	// depender's (§4.1.1, DESIGN-named-roots.md). Empty means the
	// depender's own root (the default). A root reference, never a path.
	Root string
	// Claims attaches consumer claim slots to this dependency (§4.4.2),
	// keyed by slot name; each descriptor carries a Path. Empty for a
	// dependency that declares no claim.
	Claims map[string]ClaimSlot
}

// Provides is one entry in the provides array (§4.1.4).
type Provides struct {
	Name    string
	Version string
	// Claims attaches provider claim slots to this provides entry
	// (§4.4.2), keyed by slot name; each descriptor carries a Target and
	// an optional default Path. Empty for a provides with no claim.
	Claims map[string]ClaimSlot
}

// ClaimSlot is one slot of a claims field (§4.4.2): a filesystem Path
// (the claim location, set by a consumer or as a provider default) and a
// Target (the holder file the link points at, set by a provider).
type ClaimSlot struct {
	Path   string
	Target string
}

// Replaces is one entry in the replaces array (§4.1.5).
type Replaces struct {
	Name       string
	Constraint string
}

// SDOverride is one entry in the sd_overrides array (§3.3.5).
// Exactly one of SD and SDDL must be set.
type SDOverride struct {
	Path string

	// SD is the binary self-relative security descriptor, used
	// verbatim. Pack handles the on-wire base64 encoding.
	SD []byte

	// SDDL is the textual form (MS-DTYP §2.5.1); Pack compiles it to
	// the binary self-relative descriptor via libp. Absolute SID
	// aliases only — there is no domain/machine resolution context at
	// pack time, so domain-relative aliases (DA, EA, …) are an error.
	SDDL string
}

// BuildInfo is the build-provenance object (§3.3.4). Timestamp MUST be
// an RFC 3339 UTC instant with the 'Z' zone designator; it drives every
// tar entry's modification time (§3.1.4 #2).
type BuildInfo struct {
	Timestamp string
	FarmID    string
	SourceRef string
	// SourcePackage names the corresponding-source package built from the
	// same recipe and source, empty when none exists (§3.3.4).
	SourcePackage string
	// RecipeRef pins the recipe tree the build ran from — e.g.
	// "git:<commit>", "+dirty"-suffixed for an uncommitted tree. Empty
	// when the producer has no recipe identity to record (§3.3.4).
	RecipeRef string
	// Builder identifies the producing tool and its revision — e.g.
	// "pekit/2f4c9a1b8d3e". Empty when unrecorded (§3.3.4).
	Builder string
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
// Validation is a separate call rather than part of [Pack] so a
// producer keeps control of when it runs. A package that declares
// [Manifest.SpecialSystemPackage] is exempt and this returns nil
// immediately — that declaration is how a kernel or fsbase stages a
// layout the ordinary rules reject, replacing the old convention of
// simply not calling this.
//
// Producers should validate before packing so violations surface at
// build time rather than at install time on a target system. Failures
// are aggregated so a single run reports every problem.
func ValidatePayload(m Manifest, stagedRoot string) error {
	if m.SpecialSystemPackage {
		return nil
	}
	return internalpack.ValidatePayload(m.Architecture, stagedRoot)
}

// ValidateFiles runs the same §3.4 layout checks over an explicit
// archive-path -> source-path map, the [PackOptions.Files] counterpart
// to [ValidatePayload]. Checks apply to the archive paths; sources are
// only consulted for entry kinds and symlink targets, so they must
// exist.
func ValidateFiles(m Manifest, files map[string]string) error {
	if m.SpecialSystemPackage {
		return nil
	}
	return internalpack.ValidateFiles(m.Architecture, files)
}

// ValidateSideEffects checks the manifest's side_effects declaration
// against the payload it will be packed with (§5.24), in both
// directions: a payload holding kernel modules must declare depmod, and
// a manifest declaring depmod must hold kernel modules.
//
// Returns advisory findings and an error. The error carries the
// normative failures (depmod is a MUST / MUST NOT); the findings carry
// man-db, which the spec makes a SHOULD because a stale man index
// degrades to a filesystem scan rather than breaking anything. Findings
// are returned even alongside an error, so one run reports everything.
//
// Unlike the layout checks, [Manifest.SpecialSystemPackage] does not
// exempt a package. Special packages stage exotic *layouts*, which is
// why those checks let them through; what maintenance a payload needs
// afterwards is a separate question, and the kernel's module tree is
// exactly the payload that most needs depmod.
func ValidateSideEffects(m Manifest, files map[string]string) ([]string, error) {
	return internalpack.ValidateSideEffectsFiles(m.SideEffects, files)
}

// ValidateSideEffectsPayload is [ValidateSideEffects] over a staged tree
// rather than an explicit file map, the [ValidatePayload] counterpart.
func ValidateSideEffectsPayload(m Manifest, stagedRoot string) ([]string, error) {
	return internalpack.ValidateSideEffectsPayload(m.SideEffects, stagedRoot)
}

// toInternalManifest converts the public manifest into its internal
// on-wire form: each name-keyed array is checked for duplicates (§4.1
// forbids identical names within a field) and sorted into canonical
// order, and sd_overrides is sorted by path (§3.3.5).
func toInternalManifest(m Manifest) (internalmanifest.Manifest, error) {
	// §5.19: default_root is a root reference, never a filesystem path.
	if m.DefaultRoot != "" {
		if err := ValidateRootRef(m.DefaultRoot); err != nil {
			return internalmanifest.Manifest{}, fmt.Errorf("default_root: %w", err)
		}
	}
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
		provides = append(provides, internalmanifest.Provides{
			Name: v.Name, Version: v.Version, Claims: convertClaims(v.Claims)})
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
		sd, err := encodeSDOverride(v)
		if err != nil {
			return internalmanifest.Manifest{}, fmt.Errorf("sd_overrides: %s: %w", v.Path, err)
		}
		overrides = append(overrides, internalmanifest.SDOverride{Path: v.Path, SD: sd})
	}
	sort.Slice(overrides, func(i, j int) bool { return overrides[i].Path < overrides[j].Path })

	return internalmanifest.Manifest{
		Name:                 m.Name,
		Version:              m.Version,
		Architecture:         m.Architecture,
		Description:          m.Description,
		License:              m.License,
		Homepage:             m.Homepage,
		DefaultRoot:          m.DefaultRoot,
		SpecialSystemPackage: m.SpecialSystemPackage,
		Dependencies:         deps,
		OptionalDependencies: optDeps,
		Conflicts:            conflicts,
		Provides:             provides,
		Replaces:             replaces,
		SideEffects:          append([]string(nil), m.SideEffects...),
		SDOverrides:          overrides,
		Build: internalmanifest.Build{
			Timestamp:     m.Build.Timestamp,
			FarmID:        m.Build.FarmID,
			SourceRef:     m.Build.SourceRef,
			SourcePackage: m.Build.SourcePackage,
			RecipeRef:     m.Build.RecipeRef,
			Builder:       m.Build.Builder,
		},
	}, nil
}

// encodeSDOverride turns one override into its on-wire sd value: the
// unpadded base64 of the binary self-relative descriptor (§3.3.5),
// compiling SDDL first when that form was supplied.
func encodeSDOverride(v SDOverride) (string, error) {
	switch {
	case len(v.SD) > 0 && v.SDDL != "":
		return "", fmt.Errorf("SD and SDDL are both set; supply exactly one")
	case len(v.SD) > 0:
		return base64.RawStdEncoding.EncodeToString(v.SD), nil
	case v.SDDL != "":
		d, err := sddl.Parse(v.SDDL)
		if err != nil {
			return "", fmt.Errorf("parse SDDL: %w", err)
		}
		raw, err := d.Marshal()
		if err != nil {
			return "", fmt.Errorf("marshal security descriptor: %w", err)
		}
		return base64.RawStdEncoding.EncodeToString(raw), nil
	default:
		return "", fmt.Errorf("neither SD nor SDDL is set; supply exactly one")
	}
}

func convertDeps(in []Dependency, field string) ([]internalmanifest.Dependency, error) {
	out := make([]internalmanifest.Dependency, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, d := range in {
		if _, dup := seen[d.Name]; dup {
			return nil, fmt.Errorf("%s: duplicate name %q (PSD-009 §4.1 forbids identical names within a field)", field, d.Name)
		}
		seen[d.Name] = struct{}{}
		if d.Root != "" {
			if err := ValidateRootRef(d.Root); err != nil {
				return nil, fmt.Errorf("%s: %s: root: %w", field, d.Name, err)
			}
		}
		out = append(out, internalmanifest.Dependency{
			Name:       d.Name,
			Constraint: d.Constraint,
			Arch:       d.Arch,
			Root:       d.Root,
			Claims:     convertClaims(d.Claims),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// convertClaims adapts the public claim-slot map to the encoder's. It
// returns nil for an empty map, so an entry without claims emits no
// claims key.
func convertClaims(in map[string]ClaimSlot) map[string]internalmanifest.ClaimSlot {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]internalmanifest.ClaimSlot, len(in))
	for slot, s := range in {
		out[slot] = internalmanifest.ClaimSlot{Path: s.Path, Target: s.Target}
	}
	return out
}

// ValidateRootRef checks a root reference against §5.19: a name whose
// segments match [a-z0-9][a-z0-9_-]* joined by ".", never a filesystem
// path. A manifest carrying an invalid reference is invalid.
//
// Exported because pack is the public producer library, and it is the
// only producer-side gate a third party building on it has. Without it a
// `default_root` of "/boot/initramfs" packed, signed and published
// cleanly, and failed at the consumer's install — closed, but far too
// late to be useful to whoever built it.
func ValidateRootRef(s string) error { return consumermanifest.ValidateRootRef(s) }
