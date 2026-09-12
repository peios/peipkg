package manifest_test

import (
	"strings"
	"testing"
)

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

func TestClaimsDestinationSet(t *testing.T) {
	// §5.23: a claim path lies in a §5.14 permitted destination, under
	// /run/, or at the well-known root-level name /init — and nowhere
	// else. The kernel-mandated initramfs entry point is the one
	// root-level name admitted; a provider target names a payload path,
	// so it gets the §5.14 set alone.
	consumer := func(p string) map[string]any {
		return withDeps(map[string]any{
			"name":   "registryd",
			"claims": map[string]any{"binary": map[string]any{"path": p}},
		})
	}
	provider := func(target, p string) map[string]any {
		slot := map[string]any{"target": target}
		if p != "" {
			slot["path"] = p
		}
		return withProvides(map[string]any{
			"name": "init", "claims": map[string]any{"bin": slot}})
	}

	t.Run("init is admitted", func(t *testing.T) {
		mustDecode(t, provider("/usr/sbin/prelude", "/init"))
	})
	for _, p := range []string{
		"/usr/sbin/registryd", "/usr/bin/x", "/usr/libexec/x", "/usr/lib/x86_64-linux-peios/x",
		"/usr/share/x", "/usr/etc/x", "/var/run/x", "/boot/x", "/hooks/x", "/++/x",
		"/run/logsink.sock", "/run/deep/er/x",
	} {
		t.Run("consumer path "+p, func(t *testing.T) { mustDecode(t, consumer(p)) })
	}

	// Before PEI-381 every one of these validated: the only location
	// rule was /lcl/policy, so a consumer manifest could materialise a
	// link at /etc/passwd.
	outside := []string{
		"/etc/passwd", "/opt/x", "/lcl/conf/x", "/system/x", "/home/x", "/tmp/x",
		"/dev/null", "/usr/local/bin/x", "/usr/src/x", "/usr/x", "/usr",
		"/init/x", "/initrd", "/run", "/runner/x", "/var", "/boot",
	}
	for _, p := range outside {
		t.Run("consumer path "+p, func(t *testing.T) { wantReject(t, consumer(p)) })
		t.Run("provider path "+p, func(t *testing.T) {
			wantReject(t, provider("/usr/sbin/prelude", p))
		})
	}
	// A target is a payload path: the claim-only locations are not for it.
	for _, target := range []string{"/run/x", "/init", "/etc/x"} {
		t.Run("provider target "+target, func(t *testing.T) {
			wantReject(t, provider(target, ""))
		})
	}
}

func TestClaimsPathSyntax(t *testing.T) {
	// §5.23 holds a claim path to the §5.13 syntax and safety rules —
	// the same copy the payload-path validator applies. None of these
	// were checked on a claim path before PEI-381.
	consumer := func(p string) map[string]any {
		return withDeps(map[string]any{
			"name":   "registryd",
			"claims": map[string]any{"binary": map[string]any{"path": p}},
		})
	}
	bad := map[string]string{
		"backslash":         "/usr/bin/a\\b",
		"control byte":      "/usr/bin/a\x01b",
		"DEL":               "/usr/bin/a\x7fb",
		"NUL":               "/usr/bin/a\x00b",
		"not NFC":           "/usr/bin/é",
		"trailing slash":    "/usr/bin/x/",
		"doubled slash":     "/usr/bin//x",
		"dot component":     "/usr/bin/./x",
		"dot-dot component": "/usr/bin/../bin/x",
		"long component":    "/usr/bin/" + strings.Repeat("a", 256),
		"too long":          "/usr/bin/" + strings.Repeat("a/", 2100),
		"too deep":          "/usr/bin/" + strings.Repeat("a/", 255) + "x",
	}
	for name, p := range bad {
		t.Run(name, func(t *testing.T) { wantReject(t, consumer(p)) })
	}
	// The NFC form of the same name, and a component at the limit, pass.
	mustDecode(t, consumer("/usr/bin/é"))
	mustDecode(t, consumer("/usr/bin/"+strings.Repeat("a", 255)))
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
