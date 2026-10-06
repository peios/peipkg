package audit

import (
	"errors"
	"fmt"
	"sync"
	"syscall"

	"github.com/peios/libp-go/errno"
	"github.com/peios/libp-go/event"
	"github.com/peios/libp-go/token"
)

// gate is the emission policy's half of an emit: *event.Policy, or a
// fake in tests.
type gate interface {
	EmitWith(eventType string, tier event.Tier, build func() ([]byte, error)) (bool, error)
}

// KMESEmitter is the production Emitter: it adds the acting principal,
// encodes an event as msgpack and emits it into KMES through the
// kmes_emit system call.
//
// An essential type is always emitted. Any other type consults the
// emission policy (PGSS §6.9) first, through libp-go's event.Policy,
// and its payload is built only when the type is switched on.
//
// On a kernel without KMES (any non-Peios kernel) the system call is
// not implemented; that case is treated as a successful no-op, since
// emission is best-effort with no fail-closed rule. Any other failure,
// such as the caller lacking SeAuditPrivilege, is returned for the
// caller to surface as a warning.
//
// Use NewKMESEmitter; the zero value is not ready.
type KMESEmitter struct {
	send     func(eventType string, payload []byte) error
	openGate func() gate
	userSID  func() ([]byte, error)

	gateOnce sync.Once
	gate     gate

	sidOnce sync.Once
	sid     []byte
	sidErr  error
}

// NewKMESEmitter returns the production emitter. The emission policy is
// opened, and the token read, the first time an event needs them.
func NewKMESEmitter() *KMESEmitter {
	return &KMESEmitter{
		send:     event.Emit,
		openGate: func() gate { return event.OpenPolicy() },
		userSID:  selfUserSID,
	}
}

// selfUserSID reads the user SID of the token peipkg runs under, in its
// binary form (bin.sid).
func selfUserSID() ([]byte, error) {
	tok, err := token.OpenSelf(0, token.Query)
	if err != nil {
		return nil, err
	}
	defer tok.Close()
	sid, err := tok.UserSID()
	if err != nil {
		return nil, err
	}
	return sid.Bytes(), nil
}

// notImplemented reports a system call the kernel does not have. libp-go
// reports a kernel error as its own errno.Errno, which errors.Is does
// not match against syscall.ENOSYS; both are checked, so the no-KMES
// case is recognised whichever form reaches here.
func notImplemented(err error) bool {
	return errors.Is(err, errno.ENOSYS) || errors.Is(err, syscall.ENOSYS)
}

// subject reads the acting principal once per process.
func (k *KMESEmitter) subject() ([]byte, error) {
	k.sidOnce.Do(func() { k.sid, k.sidErr = k.userSID() })
	return k.sid, k.sidErr
}

// Emit adds subject.token.sid to e, encodes it and emits it.
//
// When the token cannot be read the record is still emitted, without
// subject.token.sid, and the failure is returned as a warning: a package
// operation recorded without its principal still says what happened,
// and the kernel-stamped emitter token GUID still identifies who did it.
// When the token syscalls are absent, KMES is too, and nothing is done.
func (k *KMESEmitter) Emit(e Event) error {
	var sidErr error
	build := func() ([]byte, error) {
		fields := make(map[string]any, len(e.Fields)+1)
		for p, v := range e.Fields {
			fields[p] = v
		}
		sid, err := k.subject()
		switch {
		case err == nil:
			fields[FieldSubjectSID] = sid
		case notImplemented(err):
			return nil, err
		default:
			sidErr = err
		}
		return encodePayload(fields)
	}

	var err error
	if tier := TierOf(e.Type); tier == event.TierEssential {
		var payload []byte
		if payload, err = build(); err == nil {
			err = k.send(e.Type, payload)
		}
	} else {
		k.gateOnce.Do(func() { k.gate = k.openGate() })
		_, err = k.gate.EmitWith(e.Type, tier, build)
	}
	if notImplemented(err) {
		return nil // KMES is not present on this kernel: nothing to emit into
	}
	if err != nil {
		return fmt.Errorf("peipkg/audit: emitting %s: %w", e.Type, err)
	}
	if sidErr != nil {
		return fmt.Errorf("peipkg/audit: %s was emitted without %s, because the token "+
			"could not be read: %w", e.Type, FieldSubjectSID, sidErr)
	}
	return nil
}
