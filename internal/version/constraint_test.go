package version_test

import (
	"testing"

	"github.com/peios/peipkg/internal/version"
)

func TestParseConstraintValid(t *testing.T) {
	for _, s := range []string{
		">= 3.0-1",
		">=3.0-1, <4.0-1",
		"1.26.2-3", // a bare version is an `=` constraint
		"= 1.0-1",
		"!= 2.0-1",
		">= 3.0",            // §2.2.8: a constraint operand may omit the revision
		"> 1.0-1 , < 2.0-1", // whitespace around operators and commas is ignored
	} {
		if _, err := version.ParseConstraint(s); err != nil {
			t.Errorf("ParseConstraint(%q): unexpected error: %v", s, err)
		}
	}
}

func TestParseConstraintInvalid(t *testing.T) {
	for _, s := range []string{
		"",                // no expression at all
		">=",              // operator with no version
		">= , < 4.0-1",    // empty expression
		">= not!aversion", // operand is not a valid version
		"3.0-1,",          // trailing comma leaves an empty expression
	} {
		if c, err := version.ParseConstraint(s); err == nil {
			t.Errorf("ParseConstraint(%q) should have failed, got %v", s, c)
		}
	}
}

func TestConstraintMatches(t *testing.T) {
	mustConstraint := func(s string) version.Constraint {
		t.Helper()
		c, err := version.ParseConstraint(s)
		if err != nil {
			t.Fatalf("ParseConstraint(%q): %v", s, err)
		}
		return c
	}
	cases := []struct {
		constraint string
		version    string
		want       bool
	}{
		{">= 3.0-1", "3.5-1", true},
		{">= 3.0-1", "3.0-1", true},
		{">= 3.0-1", "2.9-1", false},
		{">= 3.0-1, < 4.0-1", "3.5-1", true},
		{">= 3.0-1, < 4.0-1", "4.0-1", false},
		{">= 3.0-1, < 4.0-1", "2.0-1", false},
		{"1.26.2-3", "1.26.2-3", true},  // a bare version pins exactly,
		{"1.26.2-3", "1.26.2-4", false}, // ... including the revision
		{"!= 2.0-1", "2.1-1", true},
		{"!= 2.0-1", "2.0-1", false},
		{">= 3.0", "3.0-1", true}, // a revision-less operand ignores the revision
		{">= 3.0", "3.5-9", true},
		{">= 3.0", "2.9-1", false},
		{"= 3.0", "3.0-1", true}, // `= 3.0` matches any revision of upstream 3.0
		{"= 3.0", "3.0-99", true},
		{"= 3.0", "3.1-1", false},
	}
	for _, tc := range cases {
		t.Run(tc.constraint+" / "+tc.version, func(t *testing.T) {
			got := mustConstraint(tc.constraint).Matches(mustParse(t, tc.version))
			if got != tc.want {
				t.Errorf("(%q).Matches(%q) = %v, want %v",
					tc.constraint, tc.version, got, tc.want)
			}
		})
	}
}

func TestZeroConstraintMatchesEverything(t *testing.T) {
	var unconstrained version.Constraint
	for _, s := range []string{"1.0-1", "99:0.0.0-1", "1.0~rc-1"} {
		if !unconstrained.Matches(mustParse(t, s)) {
			t.Errorf("the zero Constraint should match %q", s)
		}
	}
}

func TestConstraintString(t *testing.T) {
	c, err := version.ParseConstraint(">=3.0-1,<4.0-1")
	if err != nil {
		t.Fatalf("ParseConstraint: %v", err)
	}
	if got, want := c.String(), ">= 3.0-1, < 4.0-1"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	var zero version.Constraint
	if got := zero.String(); got != "any" {
		t.Errorf("zero Constraint String() = %q, want %q", got, "any")
	}
}
