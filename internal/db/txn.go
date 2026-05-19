package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// BeginTxn opens a transaction in the journal: it inserts a txn row in
// the pending state and returns its id. At most one transaction may be
// pending at a time — if one already is, BeginTxn fails, the
// single-writer rule enforced by the database itself.
//
// journalSchemaVersion records the journal format being written, so a
// later (possibly different) peipkg can tell whether it understands a
// crashed transaction well enough to recover it.
func (x *queries) BeginTxn(ctx context.Context, startedByVersion string, journalSchemaVersion int) (int64, error) {
	result, err := x.q.ExecContext(ctx,
		`INSERT INTO txn (state, started_at, started_by_version, journal_schema_version)
		 VALUES ('pending', ?, ?, ?)`,
		time.Now().Unix(), startedByVersion, journalSchemaVersion)
	if err != nil {
		return 0, fmt.Errorf("peipkg/db: begin txn: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("peipkg/db: begin txn: %w", err)
	}
	return id, nil
}

// FinishTxn moves a pending transaction to a terminal state —
// [TxnCommitted] or [TxnRolledBack] — recording the finish time and the
// human-readable operation summary. It fails if txnID names no pending
// transaction.
func (x *queries) FinishTxn(ctx context.Context, txnID int64, state TxnState, opSummary string) error {
	if state != TxnCommitted && state != TxnRolledBack {
		return fmt.Errorf("peipkg/db: finish txn %d: %q is not a terminal state", txnID, state)
	}
	result, err := x.q.ExecContext(ctx,
		`UPDATE txn SET state = ?, finished_at = ?, op_summary = ?
		 WHERE id = ? AND state = 'pending'`,
		string(state), time.Now().Unix(), opSummary, txnID)
	if err != nil {
		return fmt.Errorf("peipkg/db: finish txn %d: %w", txnID, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("peipkg/db: finish txn %d: %w", txnID, err)
	}
	if affected == 0 {
		return fmt.Errorf("peipkg/db: finish txn %d: no pending transaction with that id", txnID)
	}
	return nil
}

// DeleteTxn removes a transaction and, by cascade, all of its txn_op and
// txn_file rows. It is intended for pruning old terminal transactions
// (`peipkg clean`); deleting the pending transaction would discard the
// crash-recovery journal, so the caller must not. Deleting a
// transaction that does not exist is not an error.
func (x *queries) DeleteTxn(ctx context.Context, txnID int64) error {
	if _, err := x.q.ExecContext(ctx, "DELETE FROM txn WHERE id = ?", txnID); err != nil {
		return fmt.Errorf("peipkg/db: delete txn %d: %w", txnID, err)
	}
	return nil
}

// GetTxn returns one transaction by id. found is false if no such
// transaction exists.
func (x *queries) GetTxn(ctx context.Context, txnID int64) (txn Txn, found bool, err error) {
	row := x.q.QueryRowContext(ctx, selectTxn+" WHERE id = ?", txnID)
	txn, err = scanTxn(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Txn{}, false, nil
	}
	if err != nil {
		return Txn{}, false, fmt.Errorf("peipkg/db: get txn %d: %w", txnID, err)
	}
	return txn, true, nil
}

// PendingTxn returns the single pending transaction — the crash-recovery
// journal entry — if one exists.
func (x *queries) PendingTxn(ctx context.Context) (txn Txn, found bool, err error) {
	row := x.q.QueryRowContext(ctx, selectTxn+" WHERE state = 'pending'")
	txn, err = scanTxn(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Txn{}, false, nil
	}
	if err != nil {
		return Txn{}, false, fmt.Errorf("peipkg/db: read pending txn: %w", err)
	}
	return txn, true, nil
}

// ListTxns returns transactions most-recent first, for `peipkg history`.
// A limit of zero or less returns all transactions.
func (x *queries) ListTxns(ctx context.Context, limit int) ([]Txn, error) {
	query := selectTxn + " ORDER BY id DESC"
	var args []any
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := x.q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("peipkg/db: list txns: %w", err)
	}
	defer rows.Close()

	var txns []Txn
	for rows.Next() {
		txn, err := scanTxn(rows)
		if err != nil {
			return nil, fmt.Errorf("peipkg/db: list txns: %w", err)
		}
		txns = append(txns, txn)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("peipkg/db: list txns: %w", err)
	}
	return txns, nil
}

// InsertTxnOps records the per-package operations of a transaction. The
// txn_id of each op is taken from txnID; any TxnID set on the structs is
// ignored.
func (x *queries) InsertTxnOps(ctx context.Context, txnID int64, ops []TxnOp) error {
	if len(ops) == 0 {
		return nil
	}
	stmt, err := x.q.PrepareContext(ctx,
		`INSERT INTO txn_op
		   (txn_id, seq, package_name, action, from_version, to_version, origin_repo)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("peipkg/db: prepare txn-op insert: %w", err)
	}
	defer stmt.Close()

	for _, op := range ops {
		_, err := stmt.ExecContext(ctx, txnID, op.Seq, op.PackageName, string(op.Action),
			nullString(op.FromVersion), nullString(op.ToVersion), nullString(op.OriginRepo))
		if err != nil {
			return fmt.Errorf("peipkg/db: insert txn op (txn %d, package %q): %w",
				txnID, op.PackageName, err)
		}
	}
	return nil
}

// TxnOps returns a transaction's per-package operations, in apply order.
func (x *queries) TxnOps(ctx context.Context, txnID int64) ([]TxnOp, error) {
	rows, err := x.q.QueryContext(ctx,
		`SELECT txn_id, seq, package_name, action, from_version, to_version, origin_repo
		 FROM txn_op WHERE txn_id = ? ORDER BY seq`, txnID)
	if err != nil {
		return nil, fmt.Errorf("peipkg/db: list ops of txn %d: %w", txnID, err)
	}
	defer rows.Close()

	var ops []TxnOp
	for rows.Next() {
		var (
			op          TxnOp
			action      string
			fromVersion sql.NullString
			toVersion   sql.NullString
			originRepo  sql.NullString
		)
		if err := rows.Scan(&op.TxnID, &op.Seq, &op.PackageName, &action,
			&fromVersion, &toVersion, &originRepo); err != nil {
			return nil, fmt.Errorf("peipkg/db: list ops of txn %d: %w", txnID, err)
		}
		op.Action = OpAction(action)
		op.FromVersion = fromVersion.String
		op.ToVersion = toVersion.String
		op.OriginRepo = originRepo.String
		ops = append(ops, op)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("peipkg/db: list ops of txn %d: %w", txnID, err)
	}
	return ops, nil
}

// InsertTxnFiles records the per-file actions of a transaction — the
// journal's actionable content and backup map. The txn_id of each file
// is taken from txnID; any TxnID set on the structs is ignored. Every
// file's package must already have a [queries.InsertTxnOps] row in the
// same transaction.
func (x *queries) InsertTxnFiles(ctx context.Context, txnID int64, files []TxnFile) error {
	if len(files) == 0 {
		return nil
	}
	stmt, err := x.q.PrepareContext(ctx,
		`INSERT INTO txn_file
		   (txn_id, seq, package_name, final_path, action, staged_path, backup_path)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("peipkg/db: prepare txn-file insert: %w", err)
	}
	defer stmt.Close()

	for _, f := range files {
		_, err := stmt.ExecContext(ctx, txnID, f.Seq, f.PackageName, f.FinalPath,
			string(f.Action), nullString(f.StagedPath), nullString(f.BackupPath))
		if err != nil {
			return fmt.Errorf("peipkg/db: insert txn file %q (txn %d): %w",
				f.FinalPath, txnID, err)
		}
	}
	return nil
}

// TxnFiles returns a transaction's per-file actions, in apply order.
// Crash recovery reverses them; rollback walks them in reverse seq.
func (x *queries) TxnFiles(ctx context.Context, txnID int64) ([]TxnFile, error) {
	rows, err := x.q.QueryContext(ctx,
		`SELECT txn_id, seq, package_name, final_path, action, staged_path, backup_path
		 FROM txn_file WHERE txn_id = ? ORDER BY seq`, txnID)
	if err != nil {
		return nil, fmt.Errorf("peipkg/db: list files of txn %d: %w", txnID, err)
	}
	defer rows.Close()

	var files []TxnFile
	for rows.Next() {
		var (
			f          TxnFile
			action     string
			stagedPath sql.NullString
			backupPath sql.NullString
		)
		if err := rows.Scan(&f.TxnID, &f.Seq, &f.PackageName, &f.FinalPath,
			&action, &stagedPath, &backupPath); err != nil {
			return nil, fmt.Errorf("peipkg/db: list files of txn %d: %w", txnID, err)
		}
		f.Action = FileAction(action)
		f.StagedPath = stagedPath.String
		f.BackupPath = backupPath.String
		files = append(files, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("peipkg/db: list files of txn %d: %w", txnID, err)
	}
	return files, nil
}

// selectTxn is the column list shared by every txn-row query.
const selectTxn = `SELECT id, state, started_at, finished_at, op_summary,
	started_by_version, journal_schema_version FROM txn`

// scanTxn reads one txn row.
func scanTxn(s scanner) (Txn, error) {
	var (
		txn        Txn
		state      string
		startedAt  int64
		finishedAt sql.NullInt64
	)
	if err := s.Scan(&txn.ID, &state, &startedAt, &finishedAt, &txn.OpSummary,
		&txn.StartedByVersion, &txn.JournalSchemaVersion); err != nil {
		return Txn{}, err
	}
	txn.State = TxnState(state)
	txn.StartedAt = time.Unix(startedAt, 0)
	if finishedAt.Valid {
		txn.FinishedAt = time.Unix(finishedAt.Int64, 0)
	}
	return txn, nil
}
