package cli

import (
	"github.com/peios/peipkg/internal/audit"
	"github.com/peios/peipkg/internal/resolver"
)

// This file builds peipkg's package audit records (peipkg.evman): one
// record per package an operation touched, typed by what happened to
// that package rather than by the command that ran.

// txnVerb is the command a package transaction serves. It decides which
// of the §5.18 and §5.37 gates apply; it does not decide how the
// packages are audited, which follows each operation's own kind.
type txnVerb uint8

const (
	verbInstall txnVerb = iota
	verbUpgrade         // also a downgrade and an undo
	verbUninstall
)

// opEventType is the record type for one planned operation: a downgrade
// is recorded as an upgrade, the direction shown by its two versions.
func opEventType(k resolver.OpKind) string {
	switch k {
	case resolver.OpInstall:
		return audit.TypePackageInstalled
	case resolver.OpRemove:
		return audit.TypePackageUninstalled
	}
	return audit.TypePackageUpgraded
}

// requestEventType is the record type for one request refused before a
// plan existed.
func requestEventType(k resolver.RequestKind) string {
	switch k {
	case resolver.Install:
		return audit.TypePackageInstalled
	case resolver.Remove:
		return audit.TypePackageUninstalled
	}
	return audit.TypePackageUpgraded
}

// opPackage describes one planned operation's package: the version it
// ends at, or for a removal the version removed, and where it came from.
// A removal has no architecture or source; a local file has no
// repository.
func opPackage(op resolver.Operation) audit.Package {
	p := audit.Package{Name: op.Name}
	if op.Kind == resolver.OpRemove {
		p.Version = op.FromVersion.String()
		return p
	}
	p.Version = op.ToVersion.String()
	if op.Kind == resolver.OpUpgrade || op.Kind == resolver.OpDowngrade {
		p.VersionPrevious = op.FromVersion.String()
	}
	if op.Candidate != nil {
		p.Architecture = op.Candidate.Architecture
		// §7.6.3: the source repository is what an audit consumer
		// correlates a bad install with a compromised repository by.
		// Empty means a local file, and is left out.
		p.Repository = op.Candidate.Repo
	}
	return p
}

// emitPlan writes one record per operation of an executed plan. txnOf
// gives the transaction each operation ran in (0 when none opened); err
// is nil for a committed plan and the failure otherwise.
func (app *App) emitPlan(plan resolver.Plan, txnOf func(resolver.Operation) int64, err error) {
	for _, op := range plan.Operations {
		ev := audit.PackageEvent(opEventType(op.Kind), txnOf(op), opPackage(op))
		app.emit(withOutcome(ev, err))
	}
}

// emitRefused writes one failed record per request refused before any
// transaction opened. A request that names no package, an upgrade of
// everything, gives a record without object.package.name.
func (app *App) emitRefused(reqs []resolver.Request, err error) {
	type key struct {
		kind resolver.RequestKind
		name string
	}
	seen := map[key]bool{}
	for _, req := range reqs {
		k := key{req.Kind, req.Name}
		if seen[k] {
			continue
		}
		seen[k] = true
		ev := audit.PackageEvent(requestEventType(req.Kind), 0,
			audit.Package{Name: req.Name, Version: req.Version.String()})
		app.emit(withOutcome(ev, err))
	}
}

// withOutcome sets a record's outcome from err: success when nil, and
// otherwise failure with peipkg's stable error code as outcome.reason
// and the error text as outcome.detail.
func withOutcome(ev audit.Event, err error) audit.Event {
	if err == nil {
		return ev.Succeeded()
	}
	return ev.Failed(errorCode(err), err.Error())
}
