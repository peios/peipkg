package install

import (
	"strings"
	"testing"
)

func TestSideEffectCommandsUseRuntimeViews(t *testing.T) {
	for effect, argv := range sideEffectCommands {
		if len(argv) == 0 {
			t.Fatalf("%s has no command", effect)
		}
		if !strings.HasPrefix(argv[0], "/bin/") {
			t.Errorf("%s command = %q, want /bin runtime view", effect, argv[0])
		}
		if strings.HasPrefix(argv[0], "/usr/") {
			t.Errorf("%s bypasses StrataFS runtime view: %q", effect, argv[0])
		}
	}
}
