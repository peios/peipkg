package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// SetClaimHolder records package holder as the holder of role, replacing
// any previous holder (§7.7.5). The holder package must be installed —
// the foreign key to package(name) enforces it.
func (x *queries) SetClaimHolder(ctx context.Context, role, holder string) error {
	_, err := x.q.ExecContext(ctx,
		`INSERT INTO claim_holder (role, holder) VALUES (?, ?)
		 ON CONFLICT(role) DO UPDATE SET holder = excluded.holder`,
		role, holder)
	if err != nil {
		return fmt.Errorf("peipkg/db: set claim holder %q -> %q: %w", role, holder, err)
	}
	return nil
}

// DeleteClaimHolder clears the holder of role, leaving it unheld, and by
// cascade removes the role's claim_link rows. Clearing an unheld role is
// not an error.
func (x *queries) DeleteClaimHolder(ctx context.Context, role string) error {
	if _, err := x.q.ExecContext(ctx,
		"DELETE FROM claim_holder WHERE role = ?", role); err != nil {
		return fmt.Errorf("peipkg/db: delete claim holder %q: %w", role, err)
	}
	return nil
}

// ClaimHolder returns the package holding role. found is false when the
// role is unheld.
func (x *queries) ClaimHolder(ctx context.Context, role string) (holder string, found bool, err error) {
	err = x.q.QueryRowContext(ctx,
		"SELECT holder FROM claim_holder WHERE role = ?", role).Scan(&holder)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("peipkg/db: get claim holder %q: %w", role, err)
	}
	return holder, true, nil
}

// ClaimHolders returns every held role, ordered by role.
func (x *queries) ClaimHolders(ctx context.Context) ([]ClaimHolder, error) {
	rows, err := x.q.QueryContext(ctx,
		"SELECT role, holder FROM claim_holder ORDER BY role")
	if err != nil {
		return nil, fmt.Errorf("peipkg/db: list claim holders: %w", err)
	}
	defer rows.Close()

	var holders []ClaimHolder
	for rows.Next() {
		var h ClaimHolder
		if err := rows.Scan(&h.Role, &h.Holder); err != nil {
			return nil, fmt.Errorf("peipkg/db: list claim holders: %w", err)
		}
		holders = append(holders, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("peipkg/db: list claim holders: %w", err)
	}
	return holders, nil
}

// InsertClaimLinks records the materialised symlinks of one or more
// roles. It fails — rolling back an enclosing [DB.Tx] — if any path is
// already a claim link, the per-path uniqueness the database enforces.
func (x *queries) InsertClaimLinks(ctx context.Context, links []ClaimLink) error {
	if len(links) == 0 {
		return nil
	}
	stmt, err := x.q.PrepareContext(ctx,
		`INSERT INTO claim_link (path, role, slot, target) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("peipkg/db: prepare claim-link insert: %w", err)
	}
	defer stmt.Close()

	for _, l := range links {
		if _, err := stmt.ExecContext(ctx, l.Path, l.Role, l.Slot, l.Target); err != nil {
			return fmt.Errorf("peipkg/db: insert claim link %q (role %q): %w", l.Path, l.Role, err)
		}
	}
	return nil
}

// DeleteClaimLink removes the claim-link row at path. Removing an absent
// link is not an error.
func (x *queries) DeleteClaimLink(ctx context.Context, path string) error {
	if _, err := x.q.ExecContext(ctx,
		"DELETE FROM claim_link WHERE path = ?", path); err != nil {
		return fmt.Errorf("peipkg/db: delete claim link %q: %w", path, err)
	}
	return nil
}

// ClaimLinks returns every materialised claim link, ordered by path —
// the claim layer's view of what is on disk, for reconciliation (§4.4.4).
func (x *queries) ClaimLinks(ctx context.Context) ([]ClaimLink, error) {
	rows, err := x.q.QueryContext(ctx,
		"SELECT path, role, slot, target FROM claim_link ORDER BY path")
	if err != nil {
		return nil, fmt.Errorf("peipkg/db: list claim links: %w", err)
	}
	defer rows.Close()
	return scanClaimLinks(rows)
}

// ClaimLinksForRole returns the materialised links of one role, ordered
// by path.
func (x *queries) ClaimLinksForRole(ctx context.Context, role string) ([]ClaimLink, error) {
	rows, err := x.q.QueryContext(ctx,
		"SELECT path, role, slot, target FROM claim_link WHERE role = ? ORDER BY path", role)
	if err != nil {
		return nil, fmt.Errorf("peipkg/db: list claim links of role %q: %w", role, err)
	}
	defer rows.Close()
	return scanClaimLinks(rows)
}

// scanClaimLinks drains a claim_link result set.
func scanClaimLinks(rows *sql.Rows) ([]ClaimLink, error) {
	var links []ClaimLink
	for rows.Next() {
		var l ClaimLink
		if err := rows.Scan(&l.Path, &l.Role, &l.Slot, &l.Target); err != nil {
			return nil, fmt.Errorf("peipkg/db: scan claim links: %w", err)
		}
		links = append(links, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("peipkg/db: scan claim links: %w", err)
	}
	return links, nil
}
