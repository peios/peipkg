// Package audit emits peipkg's operation audit events into KMES, the
// kernel event subsystem (PSD-009 §7.6).
//
// Emission is best-effort. It is a local kernel call with no
// destination-unreachable failure mode, so a failed emit is surfaced to
// the operator as a warning, never as a fault — the package manager's
// own events are a convenience summary, not the security boundary (the
// kernel's audit of the underlying file operations is). The calling
// operator's identity is not carried in the payload either: the kernel
// stamps it on every emit, where it cannot be forged or suppressed.
package audit

import "time"

// Canonical peipkg event-type strings (§7.6). KMES per-event-type
// access control targets peipkg events through these.
const (
	TypeInstall       = "peipkg.install"
	TypeUpgrade       = "peipkg.upgrade"
	TypeUninstall     = "peipkg.uninstall"
	TypeRefresh       = "peipkg.refresh"
	TypeTxnFailed     = "peipkg.transaction-failed"
	TypeRecovery      = "peipkg.recovery"
	TypeAuthorisation = "peipkg.authorisation"
	TypeRepoAdd       = "peipkg.repo-add"
	TypeRepoRemove    = "peipkg.repo-remove"
	TypeConfigChange  = "peipkg.config-change"
)

// Outcomes an event can report (§7.6).
const (
	OutcomeSuccess   = "success"
	OutcomeRejection = "rejection"
	OutcomeRollback  = "rollback"
)

// PackageRef identifies a package an event concerns.
type PackageRef struct {
	Name         string
	Version      string
	Architecture string
}

// Event is one audit record. Type is a canonical event-type string;
// the remaining fields form the §7.6 event payload.
type Event struct {
	Type      string
	TxnID     int64
	Outcome   string
	Packages  []PackageRef
	Repo      string
	Detail    string
	Timestamp time.Time
}

// Emitter emits audit events. The production implementation is
// KMESEmitter; tests and KMES-less environments use Recorder.
type Emitter interface {
	Emit(Event) error
}

// Recorder is an Emitter that records events in memory rather than
// emitting them — for tests.
type Recorder struct {
	Events []Event
}

// Emit records e.
func (r *Recorder) Emit(e Event) error {
	r.Events = append(r.Events, e)
	return nil
}
