package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// UpsertRepository records a repository's derived state, inserting it on
// first refresh and replacing it on every refresh thereafter.
func (x *queries) UpsertRepository(ctx context.Context, r Repository) error {
	_, err := x.q.ExecContext(ctx,
		`INSERT INTO repository
		   (name, highest_index_version, generated_at_floor, last_refresh_at, trust_keys)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET
		   highest_index_version = excluded.highest_index_version,
		   generated_at_floor    = excluded.generated_at_floor,
		   last_refresh_at       = excluded.last_refresh_at,
		   trust_keys            = excluded.trust_keys`,
		r.Name, r.HighestIndexVersion, r.GeneratedAtFloor,
		nullTime(r.LastRefreshAt), r.TrustKeys)
	if err != nil {
		return fmt.Errorf("peipkg/db: upsert repository %q: %w", r.Name, err)
	}
	return nil
}

// GetRepository returns a repository's derived state. found is false if
// the repository has no recorded state (it has never refreshed).
func (x *queries) GetRepository(ctx context.Context, name string) (repo Repository, found bool, err error) {
	row := x.q.QueryRowContext(ctx,
		`SELECT name, highest_index_version, generated_at_floor, last_refresh_at, trust_keys
		 FROM repository WHERE name = ?`, name)
	repo, err = scanRepository(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Repository{}, false, nil
	}
	if err != nil {
		return Repository{}, false, fmt.Errorf("peipkg/db: get repository %q: %w", name, err)
	}
	return repo, true, nil
}

// ListRepositories returns the derived state of every repository,
// ordered by name.
func (x *queries) ListRepositories(ctx context.Context) ([]Repository, error) {
	rows, err := x.q.QueryContext(ctx,
		`SELECT name, highest_index_version, generated_at_floor, last_refresh_at, trust_keys
		 FROM repository ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("peipkg/db: list repositories: %w", err)
	}
	defer rows.Close()

	var repos []Repository
	for rows.Next() {
		repo, err := scanRepository(rows)
		if err != nil {
			return nil, fmt.Errorf("peipkg/db: list repositories: %w", err)
		}
		repos = append(repos, repo)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("peipkg/db: list repositories: %w", err)
	}
	return repos, nil
}

// DeleteRepository removes a repository's derived state. Deleting a
// repository with no recorded state is not an error.
func (x *queries) DeleteRepository(ctx context.Context, name string) error {
	if _, err := x.q.ExecContext(ctx, "DELETE FROM repository WHERE name = ?", name); err != nil {
		return fmt.Errorf("peipkg/db: delete repository %q: %w", name, err)
	}
	return nil
}

// scanRepository reads one repository row.
func scanRepository(s scanner) (Repository, error) {
	var (
		repo          Repository
		lastRefreshAt sql.NullInt64
	)
	if err := s.Scan(&repo.Name, &repo.HighestIndexVersion, &repo.GeneratedAtFloor,
		&lastRefreshAt, &repo.TrustKeys); err != nil {
		return Repository{}, err
	}
	if lastRefreshAt.Valid {
		repo.LastRefreshAt = time.Unix(lastRefreshAt.Int64, 0)
	}
	return repo, nil
}

// nullTime maps the zero Time to a SQL NULL, and any other time to unix
// epoch seconds.
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.Unix()
}
