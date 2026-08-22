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
		publishRepo(t, pub, priv, 1, indexGeneratedAt(generatedBaseline)), store, cacheDir)
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
		publishRepo(t, pub, priv, 2, indexGeneratedAt(generatedNewer)), store, cacheDir)
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

func TestMaxIndexStaleness(t *testing.T) {
	if got := repository.MaxIndexStaleness(config.RepoConfig{}); got != 90*24*time.Hour {
		t.Errorf("default MaxIndexStaleness = %s, want 2160h", got)
	}
	got := repository.MaxIndexStaleness(config.RepoConfig{MaxIndexStalenessDays: 120})
	if got != 120*24*time.Hour {
		t.Errorf("configured MaxIndexStaleness = %s, want 2880h", got)
	}
}

// TestIndexStalenessIsIndependentOfTrustAge is the whole point of the
// §5.34 check. It builds the exact repository the spec warns about: one
// that bumps index_version on every publication while stamping an
// ancient generated_at. Such a repository keeps TrustAge satisfied
// forever — the version bump reads as progress, so Refresh advances the
// recorded refresh time — while the metadata it serves is two years old.
func TestIndexStalenessIsIndependentOfTrustAge(t *testing.T) {
	pub, priv := keypair(t)
	store := newTestStore(t)
	cacheDir := t.TempDir()
	cfg := testConfig(pub)
	ctx := t.Context()
	now := time.Now()

	ancient := now.Add(-2 * 365 * 24 * time.Hour).UTC().Format(time.RFC3339)
	client := repository.NewClient(publishRepo(t, pub, priv, 1, ancient), store, cacheDir)
	if err := client.Add(ctx, cfg); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// The repository publishes again: a higher index_version, the same
	// ancient generated_at.
	bumped := repository.NewClient(publishRepo(t, pub, priv, 2, ancient), store, cacheDir)
	if err := bumped.Refresh(ctx, cfg); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// Trusted age is satisfied: the refresh just succeeded.
	if _, stale, err := bumped.TrustAge(ctx, cfg, now); err != nil || stale {
		t.Fatalf("trusted age after a bumping refresh: stale=%v, err=%v", stale, err)
	}
	// Index staleness is not, and that is the hole this check closes.
	age, stale, err := bumped.IndexStaleness(ctx, cfg, now)
	if err != nil {
		t.Fatalf("IndexStaleness: %v", err)
	}
	if !stale {
		t.Fatalf("two-year-old metadata reported fresh (age %s)", age)
	}
	if age < 2*365*24*time.Hour-24*time.Hour {
		t.Errorf("IndexStaleness age = %s, want about 2 years", age)
	}
}

// A recently generated index is not stale, and a configured window
// wider than the index's age makes an otherwise-stale one acceptable.
func TestIndexStalenessRespectsAFreshIndexAndAConfiguredWindow(t *testing.T) {
	pub, priv := keypair(t)
	store := newTestStore(t)
	cacheDir := t.TempDir()
	cfg := testConfig(pub)
	ctx := t.Context()
	now := time.Now()

	recent := now.Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	client := repository.NewClient(publishRepo(t, pub, priv, 1, recent), store, cacheDir)
	if err := client.Add(ctx, cfg); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, stale, err := client.IndexStaleness(ctx, cfg, now); err != nil || stale {
		t.Fatalf("day-old index: stale=%v, err=%v", stale, err)
	}

	// 100 days old: past the 90-day default, inside a configured 180.
	old := now.Add(-100 * 24 * time.Hour).UTC().Format(time.RFC3339)
	store2 := newTestStore(t)
	aged := repository.NewClient(publishRepo(t, pub, priv, 1, old), store2, t.TempDir())
	if err := aged.Add(ctx, cfg); err != nil {
		t.Fatalf("Add aged: %v", err)
	}
	if _, stale, err := aged.IndexStaleness(ctx, cfg, now); err != nil || !stale {
		t.Fatalf("100-day-old index under the default: stale=%v, err=%v", stale, err)
	}
	wide := cfg
	wide.MaxIndexStalenessDays = 180
	if _, stale, err := aged.IndexStaleness(ctx, wide, now); err != nil || stale {
		t.Fatalf("100-day-old index under a 180-day window: stale=%v, err=%v", stale, err)
	}
}

// An unknown repository reports not-stale rather than inventing an age:
// the caller's next index access produces the precise "no recorded
// trust state" error, which this gate must not mask.
func TestIndexStalenessOnAnUnknownRepositoryDefersToTheCaller(t *testing.T) {
	pub, priv := keypair(t)
	cfg := testConfig(pub)
	client := repository.NewClient(
		publishRepo(t, pub, priv, 1, time.Now().UTC().Format(time.RFC3339)),
		newTestStore(t), t.TempDir())

	age, stale, err := client.IndexStaleness(t.Context(), cfg, time.Now())
	if err != nil || stale || age != 0 {
		t.Fatalf("unknown repository: age=%s, stale=%v, err=%v", age, stale, err)
	}
}
