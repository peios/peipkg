package pack

import (
	"strings"
	"testing"
)

func TestValidateClaimTargets(t *testing.T) {
	files := map[string]string{
		"usr/sbin/prelude": "/stage/prelude",
		"usr/bin/seed-sd":  "/stage/seed-sd",
	}

	// A provider target that the package ships passes.
	owned := []Provides{{Name: "init", Claims: map[string]ClaimSlot{
		"bin": {Target: "/usr/sbin/prelude", Path: "/init"}}}}
	if err := ValidateClaimTargets(owned, files); err != nil {
		t.Errorf("owned target rejected: %v", err)
	}

	// A target the package does not ship is a packaging bug.
	bad := []Provides{{Name: "init", Claims: map[string]ClaimSlot{
		"bin": {Target: "/usr/sbin/notshipped"}}}}
	err := ValidateClaimTargets(bad, files)
	if err == nil {
		t.Fatal("unowned target accepted")
	}
	if !strings.Contains(err.Error(), "notshipped") {
		t.Errorf("error should name the offending target, got: %v", err)
	}

	// A path-only slot (no target — consumer side or provider default path)
	// owns nothing and must not be checked.
	pathOnly := []Provides{{Name: "x", Claims: map[string]ClaimSlot{
		"s": {Path: "/usr/bin/x"}}}}
	if err := ValidateClaimTargets(pathOnly, files); err != nil {
		t.Errorf("path-only slot rejected: %v", err)
	}
}
