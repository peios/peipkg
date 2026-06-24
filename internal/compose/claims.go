package compose

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/peios/peipkg/internal/claims"
	"github.com/peios/peipkg/internal/db"
)

// composeClaims resolves the claim holders and the materialised links for a
// freshly composed root (PSD-009 §4.4 / §7.7).
//
// A compose build is the degenerate case of claim reconciliation: it starts
// from nothing — no incumbent holders, no existing links — and installs one
// known, closed package set in a single shot. So there is no incremental
// reconcile to do; it reduces to picking a holder for every provided role and
// deriving the desired links. Every provided role is auto-claimed (compose has
// no notion of an operator declining a claim, and the default install
// behaviour is to claim unheld roles anyway). A role provided by more than one
// package goes to the lexicographically smallest provider, matching peipkg
// install's deterministic tie-break.
func composeClaims(fetched []fetchedPackage) (map[string]string, []claims.Link, error) {
	installed := make([]claims.Installed, 0, len(fetched))
	holders := map[string]string{}
	for _, fp := range fetched {
		installed = append(installed, claims.Installed{
			Name: fp.Locked.Name, Manifest: fp.Pkg.Manifest,
		})
		for _, role := range claims.ProvidedRoles(fp.Pkg.Manifest) {
			if cur, ok := holders[role]; !ok || fp.Locked.Name < cur {
				holders[role] = fp.Locked.Name
			}
		}
	}
	sort.Slice(installed, func(i, j int) bool { return installed[i].Name < installed[j].Name })

	links, err := claims.Desired(installed, holders)
	if err != nil {
		return nil, nil, fmt.Errorf("peipkg/compose: resolving claims: %w", err)
	}
	return holders, links, nil
}

// seedClaims records the resolved holders and links in the package database,
// inside the same transaction that seeds the packages. claim_holder is keyed
// by role; claim_link is keyed by path.
func seedClaims(ctx context.Context, tx *db.Tx, holders map[string]string, links []claims.Link) error {
	roles := make([]string, 0, len(holders))
	for role := range holders {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	for _, role := range roles {
		if err := tx.SetClaimHolder(ctx, role, holders[role]); err != nil {
			return fmt.Errorf("peipkg/compose: recording claim holder %q: %w", role, err)
		}
	}
	if len(links) == 0 {
		return nil
	}
	dbLinks := make([]db.ClaimLink, len(links))
	for i, l := range links {
		dbLinks[i] = db.ClaimLink{Path: l.Path, Role: l.Role, Slot: l.Slot, Target: l.Target}
	}
	if err := tx.InsertClaimLinks(ctx, dbLinks); err != nil {
		return fmt.Errorf("peipkg/compose: recording claim links: %w", err)
	}
	return nil
}

// materializeClaims creates the resolved claim symlinks in the root, after the
// payloads are extracted. Each link's target is written relative to the link's
// own directory, so the composed root is self-contained and relocatable.
// os.Symlink fails if the path already exists, so a claim that collides with a
// real payload file surfaces as an error rather than silently overwriting.
func materializeClaims(root string, links []claims.Link) error {
	for _, l := range links {
		physical := filepath.Join(root, l.Path)
		if err := os.MkdirAll(filepath.Dir(physical), 0o755); err != nil {
			return fmt.Errorf("peipkg/compose: materialising claim %s: %w", l.Path, err)
		}
		// Relative target so the composed root is self-contained — it resolves
		// whether examined here or once it is the live root (see RelativeTarget).
		target, err := claims.RelativeTarget(l)
		if err != nil {
			return err
		}
		if err := os.Symlink(target, physical); err != nil {
			return fmt.Errorf("peipkg/compose: materialising claim %s -> %s: %w",
				l.Path, target, err)
		}
	}
	return nil
}
