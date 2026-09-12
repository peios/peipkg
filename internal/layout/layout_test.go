package layout_test

import (
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/layout"
)

func TestForbidden(t *testing.T) {
	forbidden := []string{
		"lcl/policy/autorun.d/pwn.sh",
		"/lcl/policy/autorun.d/pwn.sh",
		"lcl/policy/./autorun.d/x",
		"lcl/foo/../policy/x",
		"lcl/policy/x",
	}
	for _, p := range forbidden {
		if err := layout.Check(p); err == nil {
			t.Errorf("Check(%q) allowed content under /lcl/policy", p)
		} else if !strings.Contains(err.Error(), "/lcl/policy") {
			t.Errorf("Check(%q) = %v, want it to name the tree", p, err)
		}
	}

	// An empty directory carries no content and so grants no authority.
	// fsbase mints lcl/policy/autorun.d and lcl/policy/autoapply.d as
	// empty-directory payload entries — laying that skeleton down is
	// exactly the job §5.14 describes special system packages as
	// existing for — so a rule that refused them would refuse the base
	// filesystem.
	for _, p := range []string{"lcl/policy", "lcl/policy/autorun.d", "lcl/policy/autoapply.d"} {
		if err := layout.CheckEntry(p, true); err != nil {
			t.Errorf("CheckEntry(%q, dir) = %v, want an empty directory permitted", p, err)
		}
		if err := layout.CheckEntry(p, false); err == nil && p != "lcl/policy" {
			t.Errorf("CheckEntry(%q, file) allowed a file where a directory is meant", p)
		}
	}

	// A prefix must not match a sibling that merely starts with the same
	// characters, and the rest of /lcl is ordinary operator territory —
	// off the permitted-destination list, but not this rule's business.
	allowed := []string{
		"lcl/policyholder/x",
		"lcl/policies/x",
		"lcl/conf/peipkg/official.repo",
		"usr/bin/nginx",
		"/run/foo.sock",
	}
	for _, p := range allowed {
		if err := layout.Check(p); err != nil {
			t.Errorf("Check(%q) = %v, want it allowed here", p, err)
		}
	}
}

func TestCheckClaimPath(t *testing.T) {
	// §5.23: §5.14's destinations, /run/, and the root-level /init.
	for _, p := range []string{
		"/usr/sbin/registryd", "/usr/lib/debug/x", "/var/x", "/run/x.sock", "/init",
	} {
		if err := layout.CheckClaimPath(p); err != nil {
			t.Errorf("CheckClaimPath(%q) = %v, want it allowed", p, err)
		}
	}
	rejected := map[string]string{
		"/etc/passwd":             "outside every permitted",
		"/run":                    "outside every permitted",
		"/init/x":                 "outside every permitted",
		"/usr/x":                  "outside every permitted",
		"/lcl/policy/autorun.d/x": "/lcl/policy",
		"usr/bin/x":               "absolute",
		"/":                       "no path component",
		"/usr/bin/x/":             "empty component",
		"/usr/bin/../etc/x":       `".." component`,
		"/usr/bin/a\\b":           "backslash",
		"/usr/bin/a\x1fb":         "control byte",
		"/usr/bin/é":             "NFC",
		"/usr/bin/" + long(256):   "component",
		"/usr/bin/" + deep(4096):  "limit is 4096",
		"/usr/bin/" + nested(256): "components, the limit is 256",
	}
	for p, want := range rejected {
		err := layout.CheckClaimPath(p)
		if err == nil {
			t.Errorf("CheckClaimPath(%q) allowed, want rejection mentioning %q", p, want)
		} else if !strings.Contains(err.Error(), want) {
			t.Errorf("CheckClaimPath(%q) = %v, want it to mention %q", p, err, want)
		}
	}

	// A target is a payload path of the declaring package: the two
	// claim-only locations are not destinations it can ship to.
	for _, p := range []string{"/run/x", "/init", "/etc/x", "/lcl/policy/x"} {
		if err := layout.CheckClaimTarget(p); err == nil {
			t.Errorf("CheckClaimTarget(%q) allowed, want rejection", p)
		}
	}
	if err := layout.CheckClaimTarget("/usr/sbin/loregd"); err != nil {
		t.Errorf("CheckClaimTarget(/usr/sbin/loregd) = %v, want it allowed", err)
	}
}

func long(n int) string   { return strings.Repeat("a", n) }
func deep(n int) string   { return strings.Repeat("a/", n/2) + "x" }
func nested(n int) string { return strings.Repeat("a/", n) + "x" }
