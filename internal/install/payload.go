package install

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/peios/peipkg/internal/db"
	"github.com/peios/peipkg/internal/resolver"
)

// commitPayloadVersion is the on-disk format version of a [commitPayload].
// It travels in the blob so the format can evolve without a journal-schema
// change; a recovery that does not recognise the version refuses to roll
// forward rather than misapply it.
const commitPayloadVersion = 1

// commitPayload is the forward package state a transaction's commit
// applies, persisted at prepare time (for a cross-root transaction) so a
// torn-commit recovery can roll the transaction forward without the
// original in-memory plan. It mirrors exactly what [applyMetadata] and
// [applyClaimMetadata] write at a live commit.
type commitPayload struct {
	Version int         `json:"v"`
	Ops     []payloadOp  `json:"ops"`
	Claims  claimCommit `json:"claims"`
}

// payloadOp is one package operation's committed state. Package and Files
// are nil for a removal.
type payloadOp struct {
	Kind    string           `json:"kind"` // install | upgrade | downgrade | remove
	Name    string           `json:"name"`
	Package *db.Package      `json:"package,omitempty"`
	Files   []db.PackageFile `json:"files,omitempty"`
}

// claimCommit is the claim holder and link state a commit applies, the
// committed shape of a [claimWork].
type claimCommit struct {
	SetHolders map[string]string `json:"set_holders,omitempty"`
	DelHolders []string          `json:"del_holders,omitempty"`
	DelLinks   []string          `json:"del_links,omitempty"`
	InsLinks   []db.ClaimLink    `json:"ins_links,omitempty"`
}

// buildCommitPayload captures, from a prepared transaction's staged
// operations and claim work, the exact forward state its commit applies.
func buildCommitPayload(staged []stagedOp, w claimWork) commitPayload {
	cp := commitPayload{Version: commitPayloadVersion}
	for _, s := range staged {
		op := payloadOp{Kind: opKindString(s.op.Kind), Name: s.op.Name}
		if s.op.Kind != resolver.OpRemove {
			op.Package = s.pkg
			op.Files = s.files
		}
		cp.Ops = append(cp.Ops, op)
	}
	cp.Claims = claimCommit{
		SetHolders: w.setHolders, DelHolders: w.delHolders,
		DelLinks: w.delLinks, InsLinks: w.insLinks,
	}
	return cp
}

func (cp commitPayload) marshal() (string, error) {
	b, err := json.Marshal(cp)
	if err != nil {
		return "", fmt.Errorf("peipkg/install: encoding commit payload: %w", err)
	}
	return string(b), nil
}

func unmarshalCommitPayload(raw string) (commitPayload, error) {
	var cp commitPayload
	if err := json.Unmarshal([]byte(raw), &cp); err != nil {
		return commitPayload{}, fmt.Errorf("peipkg/install: decoding commit payload: %w", err)
	}
	if cp.Version != commitPayloadVersion {
		return commitPayload{}, fmt.Errorf("peipkg/install: commit payload version %d is not "+
			"understood by this peipkg (wants %d)", cp.Version, commitPayloadVersion)
	}
	return cp, nil
}

// applyCommitPayload writes a transaction's forward package state inside a
// commit's SQLite transaction. It reproduces [applyMetadata] followed by
// [applyClaimMetadata] — the live commit's two steps — from the persisted
// payload, for roll-forward recovery.
func applyCommitPayload(ctx context.Context, tx *db.Tx, cp commitPayload) error {
	for _, op := range cp.Ops {
		if op.Kind == opKindString(resolver.OpRemove) {
			if err := tx.DeletePackage(ctx, op.Name); err != nil {
				return err
			}
			continue
		}
		// An upgrade or downgrade replaces the package wholesale; the
		// delete cascades the old package_file rows.
		if op.Kind != opKindString(resolver.OpInstall) {
			if err := tx.DeletePackage(ctx, op.Name); err != nil {
				return err
			}
		}
		if op.Package == nil {
			return fmt.Errorf("peipkg/install: commit payload op %q carries no package row", op.Name)
		}
		if err := tx.InsertPackage(ctx, *op.Package); err != nil {
			return err
		}
		if err := tx.InsertPackageFiles(ctx, op.Files); err != nil {
			return err
		}
	}
	// Claims, in the same order as applyClaimMetadata: holders cleared,
	// then set (satisfying the link -> holder foreign key), then links.
	for _, role := range cp.Claims.DelHolders {
		if err := tx.DeleteClaimHolder(ctx, role); err != nil {
			return err
		}
	}
	for role, holder := range cp.Claims.SetHolders {
		if err := tx.SetClaimHolder(ctx, role, holder); err != nil {
			return err
		}
	}
	for _, path := range cp.Claims.DelLinks {
		if err := tx.DeleteClaimLink(ctx, path); err != nil {
			return err
		}
	}
	return tx.InsertClaimLinks(ctx, cp.Claims.InsLinks)
}

// opKindString is the stable string form of an operation kind used in the
// payload, so the on-disk format does not depend on the resolver's
// internal enum values.
func opKindString(k resolver.OpKind) string {
	switch k {
	case resolver.OpInstall:
		return "install"
	case resolver.OpUpgrade:
		return "upgrade"
	case resolver.OpDowngrade:
		return "downgrade"
	default:
		return "remove"
	}
}
