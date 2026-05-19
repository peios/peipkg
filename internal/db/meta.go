package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
)

// Meta reads a value from the meta key/value table. found is false if
// the key is absent.
func (x *queries) Meta(ctx context.Context, key string) (value string, found bool, err error) {
	err = x.q.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = ?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("peipkg/db: read meta %q: %w", key, err)
	}
	return value, true, nil
}

// SetMeta writes a value to the meta table, inserting the key or
// replacing its existing value.
func (x *queries) SetMeta(ctx context.Context, key, value string) error {
	_, err := x.q.ExecContext(ctx,
		`INSERT INTO meta (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value)
	if err != nil {
		return fmt.Errorf("peipkg/db: write meta %q: %w", key, err)
	}
	return nil
}

// SchemaVersion reports the schema version of an open, migrated
// database. It always equals the latest migration this peipkg knows —
// [Open] either migrates up to it or fails with [ErrSchemaTooNew].
func (x *queries) SchemaVersion(ctx context.Context) (int, error) {
	raw, found, err := x.Meta(ctx, "schema_version")
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, fmt.Errorf("peipkg/db: schema version is missing from meta")
	}
	version, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("peipkg/db: schema version %q is not a number: %w", raw, err)
	}
	return version, nil
}
