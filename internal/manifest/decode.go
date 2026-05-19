package manifest

import (
	"encoding/json"
	"fmt"
)

// schemaVersion is the manifest schema version this build understands
// (§3.3.2). A manifest declaring any other value is rejected.
const schemaVersion = 1

// Resource limits on manifest array lengths (§3.2.7). A manifest whose
// arrays exceed these is rejected.
const (
	maxDependencies = 10_000 // dependencies, optional_dependencies, conflicts, provides
	maxReplaces     = 1_000
	maxSDOverrides  = 100_000
	maxSDOverride   = 64 * 1024 // decoded length of one sd_overrides entry
)

// The wire* types mirror the manifest's JSON shape for decoding. A
// pointer field is one whose absence must be distinguished from a
// present zero value — every required field, so a missing one is
// reported precisely rather than silently defaulting.
type wireManifest struct {
	SchemaVersion        *int              `json:"schema_version"`
	Name                 *string           `json:"name"`
	Version              *string           `json:"version"`
	Architecture         *string           `json:"architecture"`
	Description          string            `json:"description"`
	License              string            `json:"license"`
	Homepage             string            `json:"homepage"`
	Dependencies         *[]wireDependency `json:"dependencies"`
	OptionalDependencies []wireDependency  `json:"optional_dependencies"`
	Conflicts            *[]wireDependency `json:"conflicts"`
	Provides             []wireProvides    `json:"provides"`
	Replaces             []wireReplaces    `json:"replaces"`
	SideEffects          []string          `json:"side_effects"`
	SizeInstalled        *int64            `json:"size_installed"`
	SDOverrides          []wireSDOverride  `json:"sd_overrides"`
	Build                *wireBuild        `json:"build"`
}

type wireDependency struct {
	Name       *string `json:"name"`
	Constraint string  `json:"constraint"`
	Arch       string  `json:"arch"`
}

type wireProvides struct {
	Name    *string `json:"name"`
	Version string  `json:"version"`
}

type wireReplaces struct {
	Name       *string `json:"name"`
	Constraint string  `json:"constraint"`
}

type wireSDOverride struct {
	Path *string `json:"path"`
	SD   *string `json:"sd"`
}

type wireBuild struct {
	Timestamp *string `json:"timestamp"`
	FarmID    *string `json:"farm_id"`
	SourceRef *string `json:"source_ref"`
}

// Decode parses and validates a package manifest from the raw bytes of
// .peipkg/manifest.json (§3.3). Unknown top-level fields are ignored
// for forward compatibility (§3.3.3); any rule violation is reported as
// an error naming the offending field.
func Decode(data []byte) (Manifest, error) {
	var wm wireManifest
	if err := json.Unmarshal(data, &wm); err != nil {
		return Manifest{}, fmt.Errorf("peipkg/manifest: invalid JSON: %w", err)
	}
	return wm.validate()
}

// missingField builds the error for an absent required field.
func missingField(name string) error {
	return fmt.Errorf("peipkg/manifest: missing required field %q", name)
}

// The four Decode*Array functions decode a §4.1 / §4.3 array from its
// raw JSON, applying the same validation a manifest receives. The
// repository layer reuses them: a repository index entry carries the
// dependency, provides, replaces, and side-effect arrays under the
// identical schema (§6.2.3). Empty input — an absent optional array —
// decodes to an empty result.

// DecodeDependencyArray decodes a dependencies-shaped array (§4.1.1).
// field names the array in any error.
func DecodeDependencyArray(field string, data []byte) ([]Dependency, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var wires []wireDependency
	if err := json.Unmarshal(data, &wires); err != nil {
		return nil, fmt.Errorf("peipkg/manifest: decoding %s: %w", field, err)
	}
	return validateDependencies(field, wires)
}

// DecodeProvidesArray decodes a provides array (§4.1.4).
func DecodeProvidesArray(data []byte) ([]Provides, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var wires []wireProvides
	if err := json.Unmarshal(data, &wires); err != nil {
		return nil, fmt.Errorf("peipkg/manifest: decoding provides: %w", err)
	}
	return validateProvides(wires)
}

// DecodeReplacesArray decodes a replaces array (§4.1.5).
func DecodeReplacesArray(data []byte) ([]Replaces, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var wires []wireReplaces
	if err := json.Unmarshal(data, &wires); err != nil {
		return nil, fmt.Errorf("peipkg/manifest: decoding replaces: %w", err)
	}
	return validateReplaces(wires)
}

// DecodeSideEffectArray decodes a side_effects array (§4.3).
func DecodeSideEffectArray(data []byte) ([]SideEffect, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var raw []string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("peipkg/manifest: decoding side_effects: %w", err)
	}
	return validateSideEffects(raw)
}
