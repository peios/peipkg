package pack

import "testing"

func TestValidateVersion(t *testing.T) {
	for _, s := range []string{"1.0-1", "2:1.26.2-3", "2026a-1", "0.0.0-localdev-1"} {
		if err := ValidateVersion(s); err != nil {
			t.Errorf("ValidateVersion(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range []string{"", "1.0", "1.0-", "1.0-x", ":1.0-1", "1 .0-1"} {
		if err := ValidateVersion(s); err == nil {
			t.Errorf("ValidateVersion(%q) = nil, want an error", s)
		}
	}
}
