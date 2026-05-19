package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// repoFileExt is the extension of a repository configuration file.
const repoFileExt = ".repo"

// DirProvider is a [Provider] backed by a directory of <name>.repo TOML
// files — the temporary /conf/peipkg/ layout used until the registry
// lands.
type DirProvider struct {
	dir string
}

// NewDirProvider returns a provider reading and writing repository
// configuration under dir.
func NewDirProvider(dir string) *DirProvider {
	return &DirProvider{dir: dir}
}

// wireRepo mirrors the .repo file's flat TOML shape. Priority is a
// pointer so an omitted key is distinguished from a present zero (which
// is invalid) and given the default.
type wireRepo struct {
	BaseURL                string   `toml:"base_url"`
	Priority               *int     `toml:"priority"`
	SignaturePolicy        string   `toml:"signature_policy"`
	TrustAnchors           []string `toml:"trust_anchors"`
	AllowInsecureTransport bool     `toml:"allow_insecure_transport"`
}

// Repositories returns every configured repository, ordered by name. A
// missing configuration directory yields no repositories, not an error.
func (p *DirProvider) Repositories() ([]RepoConfig, error) {
	entries, err := os.ReadDir(p.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("peipkg/config: reading %s: %w", p.dir, err)
	}

	var configs []RepoConfig
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), repoFileExt) {
			continue
		}
		name := strings.TrimSuffix(e.Name(), repoFileExt)
		cfg, err := p.load(name, filepath.Join(p.dir, e.Name()))
		if err != nil {
			return nil, err
		}
		configs = append(configs, cfg)
	}
	sort.Slice(configs, func(i, j int) bool { return configs[i].Name < configs[j].Name })
	return configs, nil
}

// Repository returns one repository by name.
func (p *DirProvider) Repository(name string) (RepoConfig, bool, error) {
	if err := validateRepoName(name); err != nil {
		return RepoConfig{}, false, err
	}
	cfg, err := p.load(name, filepath.Join(p.dir, name+repoFileExt))
	if errors.Is(err, fs.ErrNotExist) {
		return RepoConfig{}, false, nil
	}
	if err != nil {
		return RepoConfig{}, false, err
	}
	return cfg, true, nil
}

// Put creates or replaces a repository's configuration file.
func (p *DirProvider) Put(cfg RepoConfig) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(p.dir, 0o755); err != nil {
		return fmt.Errorf("peipkg/config: creating %s: %w", p.dir, err)
	}
	w := wireRepo{
		BaseURL:                cfg.BaseURL,
		Priority:               &cfg.Priority,
		SignaturePolicy:        string(cfg.SignaturePolicy),
		TrustAnchors:           cfg.TrustAnchors,
		AllowInsecureTransport: cfg.AllowInsecureTransport,
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(w); err != nil {
		return fmt.Errorf("peipkg/config: encoding repository %q: %w", cfg.Name, err)
	}
	path := filepath.Join(p.dir, cfg.Name+repoFileExt)
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("peipkg/config: writing %s: %w", path, err)
	}
	return nil
}

// Remove deletes a repository's configuration file.
func (p *DirProvider) Remove(name string) error {
	if err := validateRepoName(name); err != nil {
		return err
	}
	path := filepath.Join(p.dir, name+repoFileExt)
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("peipkg/config: removing %s: %w", path, err)
	}
	return nil
}

// load decodes and validates one .repo file.
func (p *DirProvider) load(name, path string) (RepoConfig, error) {
	var w wireRepo
	md, err := toml.DecodeFile(path, &w)
	if err != nil {
		return RepoConfig{}, fmt.Errorf("peipkg/config: reading %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return RepoConfig{}, fmt.Errorf("peipkg/config: %s has the unknown key %q",
			path, undecoded[0].String())
	}

	cfg := RepoConfig{
		Name:                   name,
		BaseURL:                w.BaseURL,
		Priority:               defaultPriority,
		SignaturePolicy:        PolicyRequired,
		TrustAnchors:           w.TrustAnchors,
		AllowInsecureTransport: w.AllowInsecureTransport,
	}
	if w.Priority != nil {
		cfg.Priority = *w.Priority
	}
	if w.SignaturePolicy != "" {
		cfg.SignaturePolicy = SignaturePolicy(w.SignaturePolicy)
	}
	if err := cfg.validate(); err != nil {
		return RepoConfig{}, err
	}
	return cfg, nil
}
