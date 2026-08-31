package manifest_test

import "testing"

// withProvides returns a base manifest whose provides array is set to
// the given entries.
func withProvides(provides ...any) map[string]any {
	m := baseManifest()
	m["provides"] = provides
	return m
}

// withDeps returns a base manifest whose dependencies array is set to
// the given entries (sorted by the caller).
func withDeps(deps ...any) map[string]any {
	m := baseManifest()
	m["dependencies"] = deps
	return m
}

func TestClaimsProviderValid(t *testing.T) {
	m := mustDecode(t, withProvides(
		map[string]any{
			"name": "registryd",
			"claims": map[string]any{
				"binary": map[string]any{"target": "/usr/sbin/loregd"},
			},
		},
	))
	if len(m.Provides) != 1 {
		t.Fatalf("Provides: got %+v", m.Provides)
	}
	slot, ok := m.Provides[0].Claims["binary"]
	if !ok {
		t.Fatalf("Claims: missing binary slot in %+v", m.Provides[0].Claims)
	}
	if slot.Target != "/usr/sbin/loregd" {
		t.Errorf("Target: got %q", slot.Target)
	}
	if slot.Path != "" {
		t.Errorf("Path: got %q, want empty", slot.Path)
	}
}

func TestClaimsProviderDefaultPath(t *testing.T) {
	m := mustDecode(t, withProvides(
		map[string]any{
			"name": "registryd",
			"claims": map[string]any{
				"binary": map[string]any{
					"target": "/usr/sbin/loregd", "path": "/usr/sbin/registryd"},
			},
		},
	))
	slot := m.Provides[0].Claims["binary"]
	if slot.Target != "/usr/sbin/loregd" || slot.Path != "/usr/sbin/registryd" {
		t.Errorf("slot: got %+v", slot)
	}
}

func TestClaimsConsumerValid(t *testing.T) {
	m := mustDecode(t, withDeps(
		map[string]any{
			"name": "registryd",
			"claims": map[string]any{
				"binary": map[string]any{"path": "/usr/sbin/registryd"},
			},
		},
	))
	slot, ok := m.Dependencies[0].Claims["binary"]
	if !ok {
		t.Fatalf("Claims: missing binary slot in %+v", m.Dependencies[0].Claims)
	}
	if slot.Path != "/usr/sbin/registryd" {
		t.Errorf("Path: got %q", slot.Path)
	}
	if slot.Target != "" {
		t.Errorf("Target: got %q, want empty", slot.Target)
	}
}

func TestClaimsConsumerRunPathAllowed(t *testing.T) {
	// A claim path may materialise a runtime handle under /run (§4.4.2).
	mustDecode(t, withDeps(
		map[string]any{
			"name": "logsink",
			"claims": map[string]any{
				"sink": map[string]any{"path": "/run/logsink.sock"},
			},
		},
	))
}

func TestClaimsBypassInstallPathRules(t *testing.T) {
	// Claims deliberately escape the §3.4 install-path subdirectory rules.
	// The kernel-mandated initramfs entry point /init lives at the root, and
	// a provider target may sit anywhere a payload file does (incl. /run).
	mustDecode(t, withProvides(map[string]any{
		"name": "init",
		"claims": map[string]any{
			"bin": map[string]any{"target": "/usr/sbin/prelude", "path": "/init"},
		},
	}))
}

func TestClaimsRejected(t *testing.T) {
	cases := map[string]map[string]any{
		"consumer with target": withDeps(map[string]any{
			"name":   "registryd",
			"claims": map[string]any{"binary": map[string]any{"target": "/usr/sbin/loregd"}},
		}),
		"consumer missing path": withDeps(map[string]any{
			"name":   "registryd",
			"claims": map[string]any{"binary": map[string]any{}},
		}),
		"provider missing target": withProvides(map[string]any{
			"name":   "registryd",
			"claims": map[string]any{"binary": map[string]any{"path": "/usr/sbin/registryd"}},
		}),
		"relative path": withDeps(map[string]any{
			"name":   "registryd",
			"claims": map[string]any{"binary": map[string]any{"path": "usr/sbin/registryd"}},
		}),
		"unclean path": withDeps(map[string]any{
			"name":   "registryd",
			"claims": map[string]any{"binary": map[string]any{"path": "/usr/bin/../bin/registryd"}},
		}),
		"invalid slot name": withDeps(map[string]any{
			"name":   "registryd",
			"claims": map[string]any{"-bad-": map[string]any{"path": "/usr/sbin/registryd"}},
		}),
		// §5.23: claim paths escape the §3.4 subdirectory rules, but not
		// §5.14's absolute one. This route needs no flag and no operator
		// opt-in, which made it the cheaper of the two ways a package
		// could reach /lcl/policy (PEI-380).
		"consumer path under /lcl/policy": withDeps(map[string]any{
			"name":   "registryd",
			"claims": map[string]any{"binary": map[string]any{"path": "/lcl/policy/autorun.d/x"}},
		}),
		"provider target under /lcl/policy": withProvides(map[string]any{
			"name":   "registryd",
			"claims": map[string]any{"binary": map[string]any{"target": "/lcl/policy/autorun.d/x"}},
		}),
		"claim path is /lcl/policy itself": withDeps(map[string]any{
			"name":   "registryd",
			"claims": map[string]any{"binary": map[string]any{"path": "/lcl/policy"}},
		}),
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) { wantReject(t, m) })
	}
}

func TestClaimsRejectedOnConflicts(t *testing.T) {
	// §4.4.2: claims are not permitted on conflicts entries.
	m := baseManifest()
	m["conflicts"] = []any{
		map[string]any{
			"name":   "registryd",
			"claims": map[string]any{"binary": map[string]any{"path": "/usr/sbin/registryd"}},
		},
	}
	wantReject(t, m)
}
