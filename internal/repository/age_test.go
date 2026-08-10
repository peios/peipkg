package repository_test

import (
	"testing"
	"time"

	"github.com/peios/peipkg/internal/config"
	"github.com/peios/peipkg/internal/repository"
)

func TestMaxTrustedAge(t *testing.T) {
	if got := repository.MaxTrustedAge(config.RepoConfig{}); got != 30*24*time.Hour {
		t.Errorf("default MaxTrustedAge = %s, want 720h", got)
	}
	if got := repository.MaxTrustedAge(config.RepoConfig{MaxTrustedAgeDays: 60}); got != 60*24*time.Hour {
		t.Errorf("configured MaxTrustedAge = %s, want 1440h", got)
	}
}

// TestTrustAgeLifecycle walks the §6.5.4 age check through its states:
// fresh after add, stale once aged past the maximum, unaffected by a
// frozen refresh (which deliberately keeps the old refresh time), and
// fresh again after a refresh that makes progress.
func TestTrustAgeLifecycle(t *testing.T) {
	pub, priv := keypair(t)
	store := newTestStore(t)
	cacheDir := t.TempDir()
	cfg := testConfig(pub)
	ctx := t.Context()

	client := repository.NewClient(
		publishRepo(t, pub, priv, 1, "2026-05-19T00:00:00Z"), store, cacheDir)
	if err := client.Add(ctx, cfg); err != nil {
		t.Fatalf("Add: %v", err)
	}

	now := time.Now()
	if _, stale, err := client.TrustAge(ctx, cfg, now); err != nil || stale {
		t.Fatalf("freshly added repository: stale=%v, err=%v", stale, err)
	}

	// Age the recorded trust state 31 days past its refresh.
	ageRow := func() {
		row, found, err := store.GetRepository(ctx, cfg.Name)
		if err != nil || !found {
			t.Fatalf("GetRepository: found=%v, err=%v", found, err)
		}
		row.LastRefreshAt = now.Add(-31 * 24 * time.Hour)
		if err := store.UpsertRepository(ctx, row); err != nil {
			t.Fatalf("UpsertRepository: %v", err)
		}
	}
	ageRow()

	age, stale, err := client.TrustAge(ctx, cfg, now)
	if err != nil || !stale {
		t.Fatalf("aged repository: stale=%v, err=%v", stale, err)
	}
	if age < 31*24*time.Hour {
		t.Errorf("aged repository reports age %s, want >= 744h", age)
	}

	// A wider configured maximum makes the same age acceptable.
	wide := cfg
	wide.MaxTrustedAgeDays = 60
	if _, stale, err := client.TrustAge(ctx, wide, now); err != nil || stale {
		t.Errorf("60-day maximum: stale=%v, err=%v", stale, err)
	}

	// A frozen refresh succeeds but must not rejuvenate the trust state:
	// the same index is served, so the refresh time stays where it was.
	if err := client.Refresh(ctx, cfg); err != nil {
		t.Fatalf("frozen Refresh: %v", err)
	}
	if _, stale, err := client.TrustAge(ctx, cfg, now); err != nil || !stale {
		t.Errorf("after frozen refresh: stale=%v, err=%v — a no-progress refresh must not advance the refresh time", stale, err)
	}

	// A refresh that makes progress rejuvenates it.
	progressed := repository.NewClient(
		publishRepo(t, pub, priv, 2, "2026-08-01T00:00:00Z"), store, cacheDir)
	if err := progressed.Refresh(ctx, cfg); err != nil {
		t.Fatalf("progressed Refresh: %v", err)
	}
	if _, stale, err := progressed.TrustAge(ctx, cfg, now); err != nil || stale {
		t.Errorf("after progressed refresh: stale=%v, err=%v", stale, err)
	}

	// A repository with no recorded state is not the age gate's problem.
	ghost := cfg
	ghost.Name = "ghost"
	if age, stale, err := client.TrustAge(ctx, ghost, now); err != nil || stale || age != 0 {
		t.Errorf("unknown repository: age=%s, stale=%v, err=%v; want 0, false, nil", age, stale, err)
	}
}
