package compose

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// licensesPath is where a composed image's aggregate license inventory
// lands, relative to the anchor root. Like the repository configuration
// it is a compose artifact, not package payload: no package owns it, and
// it describes the image as composed (later upgrades on a live system
// are answered by the package database, not this file).
const licensesPath = "usr/share/peios/licenses.json"

type licenseManifest struct {
	SchemaVersion int            `json:"schema_version"`
	Arch          string         `json:"arch"`
	SourceDate    string         `json:"source_date"`
	Packages      []licenseEntry `json:"packages"`
}

type licenseEntry struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Architecture  string `json:"architecture"`
	License       string `json:"license"`
	Homepage      string `json:"homepage,omitempty"`
	SourceRef     string `json:"source_ref,omitempty"`
	SourcePackage string `json:"source_package,omitempty"`
	// Root is the named root the package was assembled into, empty for
	// the anchor — the inventory covers the whole image, nested roots
	// included.
	Root string `json:"root,omitempty"`
}

// writeLicenseManifest emits the aggregate license inventory of every
// package composed into the image: what is installed, under what terms,
// and where each package's corresponding source lives
// (build.source_package). Deterministic: entries sort by (root, name)
// and the only timestamp is the manifest's source_date.
func writeLicenseManifest(out string, m Manifest, fetched []fetchedPackage) error {
	entries := make([]licenseEntry, 0, len(fetched))
	for _, fp := range fetched {
		mf := fp.Pkg.Manifest
		entries = append(entries, licenseEntry{
			Name:          mf.Name,
			Version:       mf.Version.String(),
			Architecture:  mf.Architecture,
			License:       mf.License,
			Homepage:      mf.Homepage,
			SourceRef:     mf.Build.SourceRef,
			SourcePackage: mf.Build.SourcePackage,
			Root:          fp.Locked.Root,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Root != entries[j].Root {
			return entries[i].Root < entries[j].Root
		}
		return entries[i].Name < entries[j].Name
	})
	doc := licenseManifest{
		SchemaVersion: 1,
		Arch:          m.Arch,
		SourceDate:    m.SourceDate.UTC().Format(time.RFC3339),
		Packages:      entries,
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("peipkg/compose: encoding license manifest: %w", err)
	}
	data = append(data, '\n')
	path := filepath.Join(out, filepath.FromSlash(licensesPath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("peipkg/compose: creating license manifest directory: %w", err)
	}
	if err := writeFile(path, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("peipkg/compose: writing license manifest: %w", err)
	}
	return nil
}
