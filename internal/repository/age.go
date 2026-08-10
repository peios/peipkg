package repository

import (
	"context"
	"time"

	"github.com/peios/peipkg/internal/config"
)

// DefaultMaxTrustedAgeDays is the §6.5.4 default maximum trusted age:
// how long a repository's last successful refresh may lie in the past
// before install, upgrade, and downgrade demand a fresh refresh.
const DefaultMaxTrustedAgeDays = 30

// WarnMaxTrustedAgeDays is the §6.5.4 threshold above which a
// configured maximum trusted age draws a per-operation warning — a
// value that high effectively disables the freshness check, and the
// warning keeps that configuration continuously visible.
const WarnMaxTrustedAgeDays = 180

// MaxTrustedAge returns cfg's effective maximum trusted age: the
// configured max_trusted_age_days, or the §6.5.4 default when unset.
func MaxTrustedAge(cfg config.RepoConfig) time.Duration {
	days := cfg.MaxTrustedAgeDays
	if days == 0 {
		days = DefaultMaxTrustedAgeDays
	}
	return time.Duration(days) * 24 * time.Hour
}

// TrustAge reports how long ago repository cfg last refreshed
// successfully, and whether that age exceeds the maximum trusted age
// (§6.5.4). Because a frozen (no-progress) refresh deliberately does
// not advance the recorded refresh time, callers re-check after a
// refresh rather than assuming success implies freshness.
//
// A repository with no recorded trust state reports (0, false, nil):
// the caller's next index access rejects it with the precise
// "no recorded trust state" error, which the age gate must not mask.
func (c *Client) TrustAge(ctx context.Context, cfg config.RepoConfig,
	now time.Time) (age time.Duration, stale bool, err error) {

	row, found, err := c.store.GetRepository(ctx, cfg.Name)
	if err != nil {
		return 0, false, err
	}
	if !found {
		return 0, false, nil
	}
	max := MaxTrustedAge(cfg)
	if row.LastRefreshAt.IsZero() {
		// Defensive: recorded rows always carry a refresh time. Treat a
		// zero value as maximally stale, never as fresh.
		return max + time.Second, true, nil
	}
	age = now.Sub(row.LastRefreshAt)
	return age, age > max, nil
}
