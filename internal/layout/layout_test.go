package layout_test

import (
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/layout"
)

func TestForbidden(t *testing.T) {
	forbidden := []string{
		"lcl/policy",
		"lcl/policy/",
		"lcl/policy/autorun.d/pwn.sh",
		"/lcl/policy/autorun.d/pwn.sh",
		"lcl/policy/./autorun.d/x",
		"lcl/foo/../policy/x",
		"/lcl/policy",
	}
	for _, p := range forbidden {
		if err := layout.Check(p); err == nil {
			t.Errorf("Check(%q) allowed a path under /lcl/policy", p)
		} else if !strings.Contains(err.Error(), "/lcl/policy") {
			t.Errorf("Check(%q) = %v, want it to name the tree", p, err)
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
