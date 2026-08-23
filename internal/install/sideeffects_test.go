package install

import (
	"strings"
	"testing"
)

// Every side-effect command must be addressed through a StrataFS runtime
// view, never through the /usr tree the view stacks over -- a package can
// be installed into /usr, so naming a /usr path would let the payload
// being installed supply the tool that runs after it.
//
// The view is not always /bin: depmod is machine-facing and ships in
// /libexec rather than on PATH. What matters is that the path is absolute
// and is not /usr, not that it is /bin specifically.
func TestSideEffectCommandsUseRuntimeViews(t *testing.T) {
	for effect, argv := range sideEffectCommands {
		if len(argv) == 0 {
			t.Fatalf("%s has no command", effect)
		}
		if !strings.HasPrefix(argv[0], "/") {
			t.Errorf("%s command = %q, want an absolute path", effect, argv[0])
		}
		if strings.HasPrefix(argv[0], "/usr/") {
			t.Errorf("%s bypasses StrataFS runtime view: %q", effect, argv[0])
		}
	}
}
