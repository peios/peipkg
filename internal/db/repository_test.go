package db_test

import (
	"slices"
	"testing"
	"time"

	"github.com/peios/peipkg/internal/db"
)

// sampleRepository builds a representative repository-state row.
func sampleRepository(name string) db.Repository {
	return db.Repository{
		Name:                name,
		HighestIndexVersion: 42,
		GeneratedAtFloor:    1_700_000_000,
		LastRefreshAt:       time.Unix(1_700_000_500, 0),
		TrustKeys:           `[{"fingerprint":"ef86"}]`,
	}
}

// assertSameRepository compares two repository rows, treating the
// timestamp by instant rather than struct identity.
func assertSameRepository(t *testing.T, got, want db.Repository) {
	t.Helper()
	if got.Name != want.Name || got.HighestIndexVersion != want.HighestIndexVersion ||
		got.GeneratedAtFloor != want.GeneratedAtFloor || got.TrustKeys != want.TrustKeys {
		t.Errorf("repository mismatch:\n got %+v\nwant %+v", got, want)
	}
	if !got.LastRefreshAt.Equal(want.LastRefreshAt) {
		t.Errorf("LastRefreshAt: got %v, want %v", got.LastRefreshAt, want.LastRefreshAt)
	}
}

func TestRepositoryUpsertInsertsThenUpdates(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	repo := sampleRepository("official")

	if err := d.UpsertRepository(ctx, repo); err != nil {
		t.Fatalf("UpsertRepository (insert): %v", err)
	}
	got, found, err := d.GetRepository(ctx, "official")
	if err != nil || !found {
		t.Fatalf("GetRepository after insert: found=%v err=%v", found, err)
	}
	assertSameRepository(t, got, repo)

	// A second upsert of the same name replaces the row.
	repo.HighestIndexVersion = 99
	repo.TrustKeys = `[{"fingerprint":"aa00"}]`
	if err := d.UpsertRepository(ctx, repo); err != nil {
		t.Fatalf("UpsertRepository (update): %v", err)
	}
	got, _, err = d.GetRepository(ctx, "official")
	if err != nil {
		t.Fatalf("GetRepository after update: %v", err)
	}
	assertSameRepository(t, got, repo)
}

func TestRepositoryNeverRefreshed(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	// A repository with no refresh recorded: zero LastRefreshAt.
	if err := d.UpsertRepository(ctx, db.Repository{Name: "fresh"}); err != nil {
		t.Fatalf("UpsertRepository: %v", err)
	}
	got, _, err := d.GetRepository(ctx, "fresh")
	if err != nil {
		t.Fatalf("GetRepository: %v", err)
	}
	if !got.LastRefreshAt.IsZero() {
		t.Errorf("LastRefreshAt: got %v, want the zero Time (never refreshed)", got.LastRefreshAt)
	}
}

func TestGetMissingRepository(t *testing.T) {
	d, _ := newTestDB(t)
	if _, found, err := d.GetRepository(t.Context(), "absent"); err != nil || found {
		t.Errorf("GetRepository of an absent repository: found=%v err=%v", found, err)
	}
}

func TestListRepositoriesIsOrderedByName(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	for _, name := range []string{"universe", "official", "backports"} {
		if err := d.UpsertRepository(ctx, sampleRepository(name)); err != nil {
			t.Fatalf("UpsertRepository %q: %v", name, err)
		}
	}
	repos, err := d.ListRepositories(ctx)
	if err != nil {
		t.Fatalf("ListRepositories: %v", err)
	}
	got := make([]string, len(repos))
	for i, r := range repos {
		got[i] = r.Name
	}
	if want := []string{"backports", "official", "universe"}; !slices.Equal(got, want) {
		t.Errorf("ListRepositories order: got %v, want %v", got, want)
	}
}

func TestDeleteRepository(t *testing.T) {
	d, _ := newTestDB(t)
	ctx := t.Context()
	if err := d.UpsertRepository(ctx, sampleRepository("doomed")); err != nil {
		t.Fatalf("UpsertRepository: %v", err)
	}
	if err := d.DeleteRepository(ctx, "doomed"); err != nil {
		t.Fatalf("DeleteRepository: %v", err)
	}
	if _, found, err := d.GetRepository(ctx, "doomed"); err != nil || found {
		t.Errorf("repository still present after delete: found=%v err=%v", found, err)
	}
	// Deleting an absent repository is not an error.
	if err := d.DeleteRepository(ctx, "never-existed"); err != nil {
		t.Errorf("DeleteRepository of an absent repository: %v", err)
	}
}
