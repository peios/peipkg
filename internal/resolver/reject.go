package resolver

// RejectReason categorises why a resolution produced no plan (§4.2.5).
type RejectReason int

const (
	// ReasonUnsatisfiable: a dependency no available package satisfies.
	ReasonUnsatisfiable RejectReason = iota
	// ReasonConflict: two packages in the resulting set conflict.
	ReasonConflict
	// ReasonArchMismatch: a planned package is for the wrong architecture.
	ReasonArchMismatch
	// ReasonVersionRegression: an unrequested version would move backward.
	ReasonVersionRegression
	// ReasonCycle: a dependency cycle that ordering cannot break.
	ReasonCycle
	// ReasonRemovalBlocked: a removal is blocked by dependents and
	// cascade was not authorised.
	ReasonRemovalBlocked
	// ReasonTooComplex: resolution exceeded its work limit (§4.2.8).
	ReasonTooComplex
)

// Rejection is a resolution failure. The spec requires the resolver to
// report which condition failed and what was involved (§4.2.5); Reason
// is the machine-readable condition and Detail the human explanation.
type Rejection struct {
	Reason RejectReason
	Detail string
}

func (r *Rejection) Error() string { return "peipkg/resolver: " + r.Detail }
