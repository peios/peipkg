// Package config reads and writes repository configuration. A
// repository's operator-supplied settings — base URL, priority,
// signature policy, trust anchors — live in a flat TOML file at
// /conf/peipkg/<name>.repo (PSD-009 §6.5).
//
// /conf/peipkg/ is a temporary home: when the Peios registry (LCS)
// lands, repository configuration moves into it. Config is therefore
// reached only through the [Provider] interface, so that migration is
// one contained change; the flat-scalar TOML shape maps one-to-one onto
// Windows-style registry values.
package config

import (
	"fmt"
	"net/url"
	"strings"
)

// defaultPriority is the resolution priority of a repository whose
// .repo file omits the field. Lower numbers win (§6.5.5); 50 leaves
// room on either side for the operator to rank custom repositories.
const defaultPriority = 50

// SignaturePolicy is how strictly a repository's content must be signed
// (§6.5.3).
type SignaturePolicy string

const (
	// PolicyRequired rejects all unsigned content from the repository.
	PolicyRequired SignaturePolicy = "required"
	// PolicyOptional accepts unsigned content with a per-operation
	// warning; signed content is still verified.
	PolicyOptional SignaturePolicy = "optional"
)

// RepoConfig is the operator-supplied configuration of one repository.
type RepoConfig struct {
	// Name is the repository's local handle — the .repo file's stem. It
	// is set by the provider from the filename, not from the file body.
	Name string
	// BaseURL is the repository base, with no trailing slash (§6.4.1).
	BaseURL string
	// Priority orders repositories during resolution; lower wins.
	Priority int
	// SignaturePolicy is the per-repository signing strictness.
	SignaturePolicy SignaturePolicy
	// TrustAnchors are the operator-supplied signing-key fingerprints
	// (64-char lowercase hex) used to bootstrap trust in the descriptor.
	TrustAnchors []string
	// AllowInsecureTransport permits an http:// base URL. It is intended
	// only for trusted local-network development (§6.4.1).
	AllowInsecureTransport bool
	// MinIndexVersion is the operator-supplied minimum acceptable
	// index_version (§6.2.3), distributed out-of-band alongside the
	// trust anchors. The first-add of the repository is refused if its
	// active index is below this value. Zero means no floor.
	MinIndexVersion int64
}

// Provider supplies and stores repository configuration. The
// directory-backed implementation reads /conf/peipkg/*.repo; an
// LCS-backed implementation will replace it when the registry lands.
type Provider interface {
	// Repositories returns every configured repository, ordered by name.
	Repositories() ([]RepoConfig, error)
	// Repository returns one repository by name; found is false if no
	// such repository is configured.
	Repository(name string) (cfg RepoConfig, found bool, err error)
	// Put creates or replaces a repository's configuration.
	Put(cfg RepoConfig) error
	// Remove deletes a repository's configuration. Removing a repository
	// that is not configured is not an error.
	Remove(name string) error
}

// validate checks a RepoConfig against the §6.4 / §6.5 rules.
func (c RepoConfig) validate() error {
	if err := validateRepoName(c.Name); err != nil {
		return err
	}
	if err := validateBaseURL(c.BaseURL, c.AllowInsecureTransport); err != nil {
		return err
	}
	if c.Priority < 1 {
		return fmt.Errorf("peipkg/config: repository %q: priority must be a positive integer", c.Name)
	}
	if c.SignaturePolicy != PolicyRequired && c.SignaturePolicy != PolicyOptional {
		return fmt.Errorf("peipkg/config: repository %q: signature_policy %q is not %q or %q",
			c.Name, c.SignaturePolicy, PolicyRequired, PolicyOptional)
	}
	for _, anchor := range c.TrustAnchors {
		if err := validateFingerprint(anchor); err != nil {
			return fmt.Errorf("peipkg/config: repository %q: trust anchor: %w", c.Name, err)
		}
	}
	if c.MinIndexVersion < 0 {
		return fmt.Errorf("peipkg/config: repository %q: min_index_version must not be negative",
			c.Name)
	}
	return nil
}

// validateRepoName checks a repository's local handle: lowercase
// letters, digits and hyphens, 1-64 characters. The constraint keeps
// the <name>.repo filename unambiguous.
func validateRepoName(name string) error {
	if name == "" || len(name) > 64 {
		return fmt.Errorf("peipkg/config: repository name %q must be 1 to 64 characters", name)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' {
			return fmt.Errorf("peipkg/config: repository name %q has the invalid character %q",
				name, c)
		}
	}
	return nil
}

// validateBaseURL checks a repository base URL against §6.4.1.
func validateBaseURL(base string, allowInsecure bool) error {
	if base == "" {
		return fmt.Errorf("peipkg/config: base_url must not be empty")
	}
	if strings.HasSuffix(base, "/") {
		return fmt.Errorf("peipkg/config: base_url %q must not end with a slash", base)
	}
	u, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("peipkg/config: base_url %q is not a valid URL: %w", base, err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowInsecure {
			return fmt.Errorf("peipkg/config: base_url %q uses http; set "+
				"allow_insecure_transport to permit it", base)
		}
	default:
		return fmt.Errorf("peipkg/config: base_url %q must use http or https", base)
	}
	if u.Host == "" {
		return fmt.Errorf("peipkg/config: base_url %q has no host", base)
	}
	return nil
}

// validateFingerprint checks a trust-anchor fingerprint is 64 lowercase
// hex characters (§5.2.3).
func validateFingerprint(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("fingerprint %q is %d characters, want 64", s, len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return fmt.Errorf("fingerprint %q has a non-lowercase-hex character %q", s, c)
		}
	}
	return nil
}
