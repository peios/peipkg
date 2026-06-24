package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/peios/peipkg/internal/audit"
	"github.com/peios/peipkg/internal/claims"
	"github.com/peios/peipkg/internal/install"
	"github.com/peios/peipkg/internal/manifest"
)

// cmdClaim inspects or changes the holder of a role (§7.7):
//
//	peipkg claim <role>              show the holder, its links, and providers
//	peipkg claim <role> grant <pkg>  make <pkg> the holder of <role>
//	peipkg claim <role> revoke       take away the grant, leaving <role> unheld
func cmdClaim(app *App, args []string) error {
	fs := flags("claim")
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	fs.BoolVar(yes, "y", false, "skip the confirmation prompt")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("claim: a role is required")
	}
	role := pos[0]
	switch {
	case len(pos) == 1:
		return claimStatus(app, role)
	case pos[1] == "grant":
		if len(pos) != 3 {
			return fmt.Errorf("claim: usage: claim <role> grant <package>")
		}
		return claimChange(app, install.ClaimRequest{Role: role, Holder: pos[2]}, *yes)
	case pos[1] == "revoke":
		if len(pos) != 2 {
			return fmt.Errorf("claim: usage: claim <role> revoke")
		}
		return claimChange(app, install.ClaimRequest{Role: role}, *yes)
	default:
		return fmt.Errorf("claim: unknown subcommand %q (want grant or revoke)", pos[1])
	}
}

// claimStatus reports a role's holder, its materialised links, and the
// installed packages eligible to hold it.
func claimStatus(app *App, role string) error {
	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	holder, found, err := store.ClaimHolder(ctx, role)
	if err != nil {
		return err
	}
	if found {
		app.printf("role %s is held by %s\n", role, holder)
	} else {
		app.printf("role %s is unheld\n", role)
	}
	links, err := store.ClaimLinksForRole(ctx, role)
	if err != nil {
		return err
	}
	for _, l := range links {
		app.printf("  %s -> %s\n", l.Path, l.Target)
	}

	pkgs, err := store.ListPackages(ctx)
	if err != nil {
		return err
	}
	var providers []string
	for _, p := range pkgs {
		m, err := manifest.Decode([]byte(p.Manifest))
		if err != nil {
			continue
		}
		if claims.EligibleProvider(m, role) {
			providers = append(providers, p.Name)
		}
	}
	if len(providers) > 0 {
		app.printf("eligible providers: %s\n", strings.Join(providers, ", "))
	}
	return nil
}

// claimChange grants or revokes a role's holder as a standalone
// transaction (§7.7).
func claimChange(app *App, req install.ClaimRequest, yes bool) error {
	ctx := context.Background()
	store, err := app.openDB(ctx)
	if err != nil {
		return err
	}
	defer store.Close()

	if !yes && !app.confirm() {
		app.printf("cancelled\n")
		return nil
	}
	env := install.Env{
		Root: app.paths.root, DB: store, LockPath: app.paths.lockPath,
		PeipkgVersion: peipkgVersion,
	}
	detail := fmt.Sprintf("granted claim %s to %s", req.Role, req.Holder)
	if req.Holder == "" {
		detail = fmt.Sprintf("revoked claim %s", req.Role)
	}

	result, err := install.Claim(ctx, env, req)
	if err != nil {
		app.emit(audit.Event{Type: audit.TypeClaim, TxnID: result.TxnID,
			Outcome: audit.OutcomeRollback, Detail: err.Error()})
		return err
	}
	for _, w := range result.Warnings {
		fmt.Fprintf(app.errOut, "peipkg: warning: %s\n", w)
	}
	app.emit(audit.Event{Type: audit.TypeClaim, TxnID: result.TxnID,
		Outcome: audit.OutcomeSuccess, Detail: detail})
	app.printf("%s\n", detail)
	return nil
}
