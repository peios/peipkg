package sdstamp_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/manifest"
	"github.com/peios/peipkg/internal/sdstamp"
)

func overrides(pairs ...string) sdstamp.Overrides {
	var list []manifest.SDOverride
	for i := 0; i < len(pairs); i += 2 {
		list = append(list, manifest.SDOverride{Path: pairs[i], SD: []byte(pairs[i+1])})
	}
	return sdstamp.New(list)
}

// TestPathsAreSorted: §5.20 rule 2's report is only usable if it is
// stable, and ApplyWith stamps in the same order it reports.
func TestPathsAreSorted(t *testing.T) {
	o := overrides("usr/share/z", "z", "home", "h", "tmp", "t")
	got := o.Paths()
	want := []string{"home", "tmp", "usr/share/z"}
	if len(got) != len(want) {
		t.Fatalf("Paths() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Paths()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestApplyWithStampsEveryOverride is the ordinary path: each override's
// bytes reach the object the consumer located for it.
func TestApplyWithStampsEveryOverride(t *testing.T) {
	o := overrides("home", "home descriptor", "tmp", "tmp descriptor")
	stamped := map[string]string{}
	err := o.ApplyWith(
		func(path string) (string, bool) { return "/root/" + path, true },
		func(path string, sd []byte) error { stamped[path] = string(sd); return nil })
	if err != nil {
		t.Fatalf("ApplyWith: %v", err)
	}
	if stamped["/root/home"] != "home descriptor" || stamped["/root/tmp"] != "tmp descriptor" {
		t.Errorf("stamped = %v", stamped)
	}
}

// TestApplyWithFailsOnAnUnmaterialisedEntry: an override the consumer
// cannot locate is an error rather than a skip. The archive layer has
// already proved the entry exists, so a miss means the consumer and the
// manifest disagree — and continuing would leave the entry wearing an
// inherited descriptor, which is the silent drop §5.20 forbids.
func TestApplyWithFailsOnAnUnmaterialisedEntry(t *testing.T) {
	o := overrides("home", "home descriptor")
	err := o.ApplyWith(
		func(string) (string, bool) { return "", false },
		func(string, []byte) error { t.Fatal("stamped despite the miss"); return nil })
	if err == nil {
		t.Fatal("ApplyWith succeeded with an unmaterialised entry")
	}
	if !strings.Contains(err.Error(), "home") {
		t.Errorf("error does not name the entry: %v", err)
	}
}

// TestApplyWithPropagatesAStampFailure: a rejected descriptor must reach
// the caller so the transaction can roll back (§5.20's failure rule).
func TestApplyWithPropagatesAStampFailure(t *testing.T) {
	o := overrides("home", "home descriptor")
	sentinel := errors.New("the kernel refused it")
	err := o.ApplyWith(
		func(path string) (string, bool) { return path, true },
		func(string, []byte) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("ApplyWith error = %v, want it to wrap %v", err, sentinel)
	}
}

// TestEmptyOverridesStampNothing: the overwhelming majority of packages
// declare none, and for them inheritance is the whole mechanism.
func TestEmptyOverridesStampNothing(t *testing.T) {
	o := sdstamp.New(nil)
	if o.Len() != 0 {
		t.Errorf("Len() = %d, want 0", o.Len())
	}
	err := o.ApplyWith(
		func(string) (string, bool) { t.Fatal("located something"); return "", false },
		func(string, []byte) error { t.Fatal("stamped something"); return nil })
	if err != nil {
		t.Fatalf("ApplyWith: %v", err)
	}
}
