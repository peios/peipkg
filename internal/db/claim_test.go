package db_test

import (
	"testing"

	"github.com/peios/peipkg/internal/db"
)

func TestClaimHolderRoundTrip(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()

	if err := d.InsertPackage(ctx, samplePackage("loregd")); err != nil {
		t.Fatalf("InsertPackage: %v", err)
	}
	if err := d.SetClaimHolder(ctx, "registryd", "loregd"); err != nil {
		t.Fatalf("SetClaimHolder: %v", err)
	}
	holder, found, err := d.ClaimHolder(ctx, "registryd")
	if err != nil || !found || holder != "loregd" {
		t.Fatalf("ClaimHolder: got %q found=%v err=%v", holder, found, err)
	}

	// Re-granting replaces the holder.
	if err := d.InsertPackage(ctx, samplePackage("altregd")); err != nil {
		t.Fatalf("InsertPackage altregd: %v", err)
	}
	if err := d.SetClaimHolder(ctx, "registryd", "altregd"); err != nil {
		t.Fatalf("SetClaimHolder regrant: %v", err)
	}
	if holder, _, _ := d.ClaimHolder(ctx, "registryd"); holder != "altregd" {
		t.Errorf("holder after regrant: got %q, want altregd", holder)
	}
}

func TestClaimHolderRequiresInstalledPackage(t *testing.T) {
	d, _ := newTestDB(t)
	// holder foreign-keys to package(name): an unknown holder is rejected.
	if err := d.SetClaimHolder(t.Context(), "registryd", "ghost"); err == nil {
		t.Fatal("SetClaimHolder with no such package should fail")
	}
}

func TestClaimLinksCascadeOnHolderRemoval(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()

	if err := d.InsertPackage(ctx, samplePackage("loregd")); err != nil {
		t.Fatalf("InsertPackage: %v", err)
	}
	if err := d.SetClaimHolder(ctx, "registryd", "loregd"); err != nil {
		t.Fatalf("SetClaimHolder: %v", err)
	}
	links := []db.ClaimLink{
		{Path: "/usr/sbin/registryd", Role: "registryd", Slot: "binary", Target: "/usr/sbin/loregd"},
		{Path: "/run/registryd.sock", Role: "registryd", Slot: "control", Target: "/usr/sbin/loregd-ctl"},
	}
	if err := d.InsertClaimLinks(ctx, links); err != nil {
		t.Fatalf("InsertClaimLinks: %v", err)
	}
	got, err := d.ClaimLinksForRole(ctx, "registryd")
	if err != nil || len(got) != 2 {
		t.Fatalf("ClaimLinksForRole: got %+v err=%v", got, err)
	}

	// Deleting the holder package cascades through claim_holder to
	// claim_link, leaving the role unheld and its links gone.
	if err := d.DeletePackage(ctx, "loregd"); err != nil {
		t.Fatalf("DeletePackage: %v", err)
	}
	if _, found, _ := d.ClaimHolder(ctx, "registryd"); found {
		t.Error("role should be unheld after holder removal")
	}
	if links, _ := d.ClaimLinks(ctx); len(links) != 0 {
		t.Errorf("claim links should be gone after holder removal, got %+v", links)
	}
}

func TestClaimLinkPathIsUnique(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	if err := d.InsertPackage(ctx, samplePackage("loregd")); err != nil {
		t.Fatalf("InsertPackage: %v", err)
	}
	if err := d.SetClaimHolder(ctx, "registryd", "loregd"); err != nil {
		t.Fatalf("SetClaimHolder: %v", err)
	}
	first := []db.ClaimLink{{Path: "/usr/sbin/registryd", Role: "registryd", Slot: "binary", Target: "/usr/sbin/loregd"}}
	if err := d.InsertClaimLinks(ctx, first); err != nil {
		t.Fatalf("first InsertClaimLinks: %v", err)
	}
	dup := []db.ClaimLink{{Path: "/usr/sbin/registryd", Role: "registryd", Slot: "binary", Target: "/usr/bin/other"}}
	if err := d.InsertClaimLinks(ctx, dup); err == nil {
		t.Fatal("a second link at the same path should fail")
	}
}
