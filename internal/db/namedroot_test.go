package db_test

import (
	"testing"
)

func TestNamedRootRegisterAndLookup(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()

	if _, found, err := d.NamedRoot(ctx, "initramfs"); err != nil || found {
		t.Fatalf("lookup of an unregistered root: found=%v err=%v", found, err)
	}

	if err := d.SetNamedRoot(ctx, "initramfs", "boot/initramfs"); err != nil {
		t.Fatalf("SetNamedRoot: %v", err)
	}
	path, found, err := d.NamedRoot(ctx, "initramfs")
	if err != nil || !found {
		t.Fatalf("lookup after register: found=%v err=%v", found, err)
	}
	if path != "boot/initramfs" {
		t.Errorf("registered path: got %q, want %q", path, "boot/initramfs")
	}
}

func TestNamedRootReregisterReplaces(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()

	if err := d.SetNamedRoot(ctx, "initramfs", "boot/old"); err != nil {
		t.Fatalf("SetNamedRoot: %v", err)
	}
	if err := d.SetNamedRoot(ctx, "initramfs", "boot/new"); err != nil {
		t.Fatalf("SetNamedRoot (replace): %v", err)
	}
	path, _, err := d.NamedRoot(ctx, "initramfs")
	if err != nil {
		t.Fatalf("NamedRoot: %v", err)
	}
	if path != "boot/new" {
		t.Errorf("re-registering should replace: got %q, want %q", path, "boot/new")
	}

	roots, err := d.NamedRoots(ctx)
	if err != nil {
		t.Fatalf("NamedRoots: %v", err)
	}
	if len(roots) != 1 {
		t.Errorf("re-register left %d rows, want 1", len(roots))
	}
}

func TestNamedRootDelete(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()

	// Deleting an unregistered name is not an error.
	if err := d.DeleteNamedRoot(ctx, "absent"); err != nil {
		t.Fatalf("DeleteNamedRoot of an absent name: %v", err)
	}

	if err := d.SetNamedRoot(ctx, "initramfs", "boot/initramfs"); err != nil {
		t.Fatalf("SetNamedRoot: %v", err)
	}
	if err := d.DeleteNamedRoot(ctx, "initramfs"); err != nil {
		t.Fatalf("DeleteNamedRoot: %v", err)
	}
	if _, found, err := d.NamedRoot(ctx, "initramfs"); err != nil || found {
		t.Errorf("root still present after delete: found=%v err=%v", found, err)
	}
}

func TestNamedRootsOrderedByName(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()

	for name, path := range map[string]string{
		"initramfs": "boot/initramfs",
		"recovery":  "boot/recovery",
		"alt":       "alt",
	} {
		if err := d.SetNamedRoot(ctx, name, path); err != nil {
			t.Fatalf("SetNamedRoot %q: %v", name, err)
		}
	}
	roots, err := d.NamedRoots(ctx)
	if err != nil {
		t.Fatalf("NamedRoots: %v", err)
	}
	got := make([]string, len(roots))
	for i, r := range roots {
		got[i] = r.Name
	}
	want := []string{"alt", "initramfs", "recovery"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("NamedRoots order: got %v, want %v", got, want)
		}
	}
	if roots[0].CreatedAt.IsZero() {
		t.Error("CreatedAt was not populated")
	}
}
