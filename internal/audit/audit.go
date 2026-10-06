// Package audit emits peipkg's audit events into KMES, the kernel event
// subsystem (PSPU §5 §7.6, PGSS §6).
//
// The event types, their fields and their tiers are declared in the
// repository's evman fragment, peipkg.evman, which is installed as
// /usr/share/evman/peipkg.evman. This package is the one place the code
// spells them.
//
// Emission is best-effort. It is a local kernel call with no
// destination-unreachable failure mode, so a failed emit is surfaced to
// the operator as a warning, never as a fault: the package manager's
// own events are a convenience summary, not the security boundary (the
// kernel's audit of the underlying file operations is). Every record
// carries the acting principal as subject.token.sid, which is peipkg's
// own word; the kernel stamps the emitter's token GUID on every emit as
// well, where it cannot be forged or suppressed.
package audit

import (
	"sort"

	"github.com/peios/libp-go/event"
)

// Event types (peipkg.evman). KMES per-event-type access control and the
// emission policy (PGSS §6.9) target peipkg events through these.
const (
	TypePackageInstalled       = "peipkg.package.installed"
	TypePackageUpgraded        = "peipkg.package.upgraded"
	TypePackageUninstalled     = "peipkg.package.uninstalled"
	TypeClaimChanged           = "peipkg.claim.changed"
	TypeRepositoryAdded        = "peipkg.repository.added"
	TypeRepositoryRemoved      = "peipkg.repository.removed"
	TypeRepositoryReconfigured = "peipkg.repository.reconfigured"
	TypeRepositoryRefreshed    = "peipkg.repository.refreshed"
	TypeTransactionRecovered   = "peipkg.transaction.recovered"
	TypeActionAuthorised       = "peipkg.action.authorised"
)

// tiers are each type's tier as peipkg.evman declares it (PGSS §6.8).
// An essential type is always written; any other consults the emission
// policy before its payload is built.
var tiers = map[string]event.Tier{
	TypePackageInstalled:       event.TierEssential,
	TypePackageUpgraded:        event.TierEssential,
	TypePackageUninstalled:     event.TierEssential,
	TypeClaimChanged:           event.TierStandard,
	TypeRepositoryAdded:        event.TierEssential,
	TypeRepositoryRemoved:      event.TierEssential,
	TypeRepositoryReconfigured: event.TierEssential,
	TypeRepositoryRefreshed:    event.TierStandard,
	TypeTransactionRecovered:   event.TierStandard,
	TypeActionAuthorised:       event.TierEssential,
}

// TierOf reports an event type's tier. A type peipkg.evman does not
// declare is treated as standard, so the policy can still switch it off.
func TierOf(eventType string) event.Tier {
	if t, ok := tiers[eventType]; ok {
		return t
	}
	return event.TierStandard
}

// Field paths (PGSS §6.4). A path is encoded as nested maps, one per
// segment.
const (
	FieldSubjectSID          = "subject.token.sid"
	FieldTransactionID       = "transaction.id"
	FieldPackageName         = "object.package.name"
	FieldPackageVersion      = "object.package.version"
	FieldPackageVersionPrev  = "object.package.version-previous"
	FieldPackageArchitecture = "object.package.architecture"
	FieldSourceRepository    = "source.repository.name"
	FieldRepositoryName      = "object.repository.name"
	FieldRepositoryURL       = "object.repository.url"
	FieldClaimRole           = "object.claim.role"
	FieldClaimHolder         = "object.claim.holder"
	FieldFilePath            = "object.file.path"
	FieldConfigName          = "config.name"
	FieldConfigText          = "config.text"
	FieldConfigTextPrevious  = "config.text-previous"
	FieldConfigValue         = "config.value"
	FieldConfigValuePrevious = "config.value-previous"
	FieldOperationName       = "operation.name"
	FieldOperationSucceeded  = "operation.succeeded-count"
	FieldOperationFailed     = "operation.failed-count"
	FieldOutcomeSuccess      = "outcome.success"
	FieldOutcomeReason       = "outcome.reason"
	FieldOutcomeDetail       = "outcome.detail"
)

// The operation.name values of peipkg.action.authorised.
const (
	ActionLowTrustProvides   = "low-trust-provides"
	ActionForeignReplaces    = "foreign-replaces"
	ActionDowngrade          = "downgrade"
	ActionRemoveModifiedFile = "remove-modified-file"
	ActionStaleTrustState    = "stale-trust-state"
	ActionStaleIndex         = "stale-index"
)

// Event is one audit record: its type and its payload fields, keyed by
// path. A field that has no value is absent from Fields, never set to
// an empty string or zero (PGSS §6.5). The setters below enforce that
// for strings and transaction ids.
//
// The acting principal (subject.token.sid) is not set here: the emitter
// adds it, from the token peipkg runs under.
type Event struct {
	Type   string
	Fields map[string]any
}

// New starts an event of the given type with no fields.
func New(eventType string) Event {
	return Event{Type: eventType, Fields: map[string]any{}}
}

// Str sets a string field, or leaves it absent when v is empty.
func (e Event) Str(path, v string) Event {
	if v != "" {
		e.Fields[path] = v
	}
	return e
}

// Uint sets an unsigned integer field.
func (e Event) Uint(path string, v uint64) Event {
	e.Fields[path] = v
	return e
}

// Bool sets a boolean field.
func (e Event) Bool(path string, v bool) Event {
	e.Fields[path] = v
	return e
}

// Bin sets a binary field.
func (e Event) Bin(path string, v []byte) Event {
	e.Fields[path] = v
	return e
}

// Txn sets transaction.id, or leaves it absent when no transaction was
// opened (id 0).
func (e Event) Txn(id int64) Event {
	if id > 0 {
		e.Fields[FieldTransactionID] = uint64(id)
	}
	return e
}

// Succeeded records a successful outcome.
func (e Event) Succeeded() Event {
	return e.Bool(FieldOutcomeSuccess, true)
}

// Failed records a failed outcome: reason is the event's declared
// failure code (outcome.reason), detail the error as the operator saw it
// (outcome.detail). Either may be empty, which leaves it absent.
func (e Event) Failed(reason, detail string) Event {
	return e.Bool(FieldOutcomeSuccess, false).
		Str(FieldOutcomeReason, reason).
		Str(FieldOutcomeDetail, detail)
}

// Get returns a field's value and whether it is present.
func (e Event) Get(path string) (any, bool) {
	v, ok := e.Fields[path]
	return v, ok
}

// Paths lists the event's field paths in sorted order.
func (e Event) Paths() []string {
	out := make([]string, 0, len(e.Fields))
	for p := range e.Fields {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Package is one package's part in a package event.
type Package struct {
	Name            string
	Version         string // installed, moved to, or removed
	VersionPrevious string // moved from, on an upgrade or downgrade
	Architecture    string
	Repository      string // the configured repository it came from
}

// PackageEvent builds a peipkg.package.* record for one package. txnID
// is the transaction the package belonged to, 0 when none opened. The
// outcome is set by the caller.
func PackageEvent(eventType string, txnID int64, p Package) Event {
	return New(eventType).Txn(txnID).
		Str(FieldPackageName, p.Name).
		Str(FieldPackageVersion, p.Version).
		Str(FieldPackageVersionPrev, p.VersionPrevious).
		Str(FieldPackageArchitecture, p.Architecture).
		Str(FieldSourceRepository, p.Repository)
}

// Emitter emits audit events. The production implementation is
// KMESEmitter; tests and KMES-less environments use Recorder.
type Emitter interface {
	Emit(Event) error
}

// Recorder is an Emitter that records events in memory rather than
// emitting them, for tests. It applies no emission policy.
type Recorder struct {
	Events []Event
}

// Emit records e.
func (r *Recorder) Emit(e Event) error {
	r.Events = append(r.Events, e)
	return nil
}

// OfType returns the recorded events of one type, in order.
func (r *Recorder) OfType(eventType string) []Event {
	var out []Event
	for _, e := range r.Events {
		if e.Type == eventType {
			out = append(out, e)
		}
	}
	return out
}
