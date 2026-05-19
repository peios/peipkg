package audit

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/peios/libp-go/event"
)

// KMESEmitter is the production Emitter: it encodes an event as msgpack
// and emits it into KMES through the kmes_emit system call (§7.6).
//
// On a kernel without KMES — any non-Peios kernel — the system call is
// not implemented; that case is treated as a successful no-op, since
// §7.6 makes emission best-effort with no fail-closed rule. Any other
// failure (for example, the caller lacking the audit privilege) is
// returned for the caller to surface as a warning.
type KMESEmitter struct{}

// Emit encodes e and emits it into KMES.
func (KMESEmitter) Emit(e Event) error {
	err := event.Emit(e.Type, encodeEvent(e))
	if errors.Is(err, syscall.ENOSYS) {
		return nil // KMES is not present on this kernel — nothing to emit into
	}
	if err != nil {
		return fmt.Errorf("peipkg/audit: emitting %s: %w", e.Type, err)
	}
	return nil
}
