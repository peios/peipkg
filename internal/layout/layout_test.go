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
