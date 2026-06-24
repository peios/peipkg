package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SetNamedRoot registers name -> path in this root's registry, replacing
// any existing mapping for name. path is stored verbatim and is expected
// to be relative to the root that owns this database
// (DESIGN-named-roots.md). The name grammar is enforced by the caller.
func (x *queries) SetNamedRoot(ctx context.Context, name, path string) error {
	_, err := x.q.ExecContext(ctx,
		`INSERT INTO named_root (name, path, created_at) VALUES (?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET path = excluded.path`,
		name, path, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("peipkg/db: register named root %q -> %q: %w", name, path, err)
	}
	return nil
}

// DeleteNamedRoot unregisters name from this root's registry. Removing an
// unregistered name is not an error.
func (x *queries) DeleteNamedRoot(ctx context.Context, name string) error {
	if _, err := x.q.ExecContext(ctx,
		"DELETE FROM named_root WHERE name = ?", name); err != nil {
		return fmt.Errorf("peipkg/db: unregister named root %q: %w", name, err)
	}
	return nil
}

// NamedRoot returns the path registered for name in this root's registry.
// found is false if no such name is registered.
func (x *queries) NamedRoot(ctx context.Context, name string) (path string, found bool, err error) {
	err = x.q.QueryRowContext(ctx,
		"SELECT path FROM named_root WHERE name = ?", name).Scan(&path)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("peipkg/db: get named root %q: %w", name, err)
	}
	return path, true, nil
}

// NamedRoots returns every entry in this root's registry, ordered by name.
func (x *queries) NamedRoots(ctx context.Context) ([]NamedRoot, error) {
	rows, err := x.q.QueryContext(ctx,
		"SELECT name, path, created_at FROM named_root ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("peipkg/db: list named roots: %w", err)
	}
	defer rows.Close()

	var roots []NamedRoot
	for rows.Next() {
		var (
			r         NamedRoot
			createdAt int64
		)
		if err := rows.Scan(&r.Name, &r.Path, &createdAt); err != nil {
			return nil, fmt.Errorf("peipkg/db: list named roots: %w", err)
		}
		r.CreatedAt = time.Unix(createdAt, 0)
		roots = append(roots, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("peipkg/db: list named roots: %w", err)
	}
	return roots, nil
}
