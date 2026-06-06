package compose

import (
	"strings"
	"testing"
	"time"

	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/version"
)

const validManifest = `
schema      = 1
arch        = "x86_64"
source_date = "2026-06-01T00:00:00Z"
local_packages = ["./build/out/*.peipkg"]

[[repository]]
name          = "official"
base_url      = "https://pkgs.peios.org"
priority      = 10
trust_anchors = ["ef86709c4b1d8a02e5f3c719d640aa8b7c2e9105f8d3b6470a1c2e9d8b5f3a04"]

[[repository]]
name     = "internal"
base_url = "https://pkg.corp.example"

[[package]]
name    = "base"
version = "*"

[[package]]
name    = "nginx"
version = ">= 1.27, < 1.28"

[[package]]
name       = "openssh"
repository = "official"
`

func TestDecodeManifest(t *testing.T) {
	m, err := DecodeManifest([]byte(validManifest))
	if err != nil {
		t.Fatalf("DecodeManifest: %v", err)
	}

	if m.Arch != "x86_64" {
		t.Errorf("Arch = %q, want x86_64", m.Arch)
	}
	if want := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC); !m.SourceDate.Equal(want) {
		t.Errorf("SourceDate = %v, want %v", m.SourceDate, want)
	}

	if len(m.Repositories) != 2 {
		t.Fatalf("got %d repositories, want 2", len(m.Repositories))
	}
	if r := m.Repositories[0]; r.Name != "official" || r.Priority != 10 ||
		r.SignaturePolicy != config.PolicyRequired || len(r.TrustAnchors) != 1 {
		t.Errorf("repository[0] = %+v", r)
	}
	if r := m.Repositories[1]; r.Priority != defaultPriority {
		t.Errorf("repository[1] priority = %d, want the default %d", r.Priority, defaultPriority)
	}
	if len(m.LocalPackages) != 1 {
		t.Errorf("LocalPackages = %v, want one entry", m.LocalPackages)
	}

	if len(m.Packages) != 3 {
		t.Fatalf("got %d packages, want 3", len(m.Packages))
	}
	// `version = "*"` is the zero constraint — it matches any version.
	if !m.Packages[0].Constraint.Matches(mustVersion(t, "9.9.9-1")) {
		t.Errorf("base: a `*` version should match any version")
	}
	// nginx is bounded to >= 1.27, < 1.28.
	if c := m.Packages[1].Constraint; !c.Matches(mustVersion(t, "1.27.5-1")) ||
		c.Matches(mustVersion(t, "1.28.0-1")) {
		t.Errorf("nginx: constraint %s did not bound versions as expected", c)
	}
	if m.Packages[2].Repository != "official" {
		t.Errorf("openssh: Repository = %q, want official", m.Packages[2].Repository)
	}
}

func TestDecodeManifestErrors(t *testing.T) {
	const pkg = "\n[[package]]\nname = \"a\"\n"
	cases := map[string]struct{ toml, want string }{
		"missing schema": {
			`arch = "x86_64"` + "\n" + `source_date = "2026-06-01T00:00:00Z"` + pkg,
			`missing required key "schema"`},
		"wrong schema": {
			`schema = 2` + "\n" + `arch = "x86_64"` + "\n" +
				`source_date = "2026-06-01T00:00:00Z"` + pkg,
			`schema is 2, want 1`},
		"bad source_date": {
			`schema = 1` + "\n" + `arch = "x86_64"` + "\n" +
				`source_date = "tuesday"` + pkg,
			`not an RFC 3339 timestamp`},
		"unknown key": {
			`schema = 1` + "\n" + `arch = "x86_64"` + "\n" +
				`source_date = "2026-06-01T00:00:00Z"` + "\n" + `colour = "blue"` + pkg,
			`unknown key "colour"`},
		"no packages": {
			`schema = 1` + "\n" + `arch = "x86_64"` + "\n" +
				`source_date = "2026-06-01T00:00:00Z"` + "\n",
			`requests no packages`},
		"duplicate package": {
			`schema = 1` + "\n" + `arch = "x86_64"` + "\n" +
				`source_date = "2026-06-01T00:00:00Z"` + pkg + pkg,
			`requested more than once`},
		"package names unknown repository": {
			`schema = 1` + "\n" + `arch = "x86_64"` + "\n" +
				`source_date = "2026-06-01T00:00:00Z"` + "\n" +
				`[[package]]` + "\n" + `name = "a"` + "\n" + `repository = "ghost"` + "\n",
			`names repository "ghost"`},
		"bad version constraint": {
			`schema = 1` + "\n" + `arch = "x86_64"` + "\n" +
				`source_date = "2026-06-01T00:00:00Z"` + "\n" +
				`[[package]]` + "\n" + `name = "a"` + "\n" + `version = ">>> 1"` + "\n",
			`invalid constraint`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeManifest([]byte(tc.toml))
			if err == nil {
				t.Fatalf("DecodeManifest accepted invalid input")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// mustVersion parses a version string or fails the test.
func mustVersion(t *testing.T, s string) version.Version {
	t.Helper()
	v, err := version.Parse(s)
	if err != nil {
		t.Fatalf("version.Parse(%q): %v", s, err)
	}
	return v
}
