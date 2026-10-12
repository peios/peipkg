package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/peios/peipkg/internal/audit"
	"github.com/peios/peipkg/internal/signature"
)

func TestInsecureTransportWarnsOnEachOperation(t *testing.T) {
	root := t.TempDir()
	repo := newRepoServer(t, root)
	repo.publish(1, daysAgo(2), "1.0-1")
	warnings := &bytes.Buffer{}
	app := newApp(root, strings.NewReader(""), &bytes.Buffer{}, warnings)
	app.emitter = &audit.Recorder{}
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"add", func() error {
			return cmdRepoAdd(app, []string{"test", repo.srv.URL, "--anchor", signature.Fingerprint(repo.pub), "--insecure"})
		}},
		{"refresh", func() error { return cmdRefresh(app, nil) }},
		{"install", func() error { return cmdInstall(app, []string{"widget", "--yes"}) }},
		{"repeat-refresh", func() error { return cmdRefresh(app, nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			warnings.Reset()
			if err := tc.run(); err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(warnings.String(), `repository "test" allows insecure transport`); got == 0 {
				t.Errorf("got %d transport warnings: %q", got, warnings.String())
			}
		})
	}
	// The warning describes the configured allowance even with cached data.
	cfg, found, err := app.configProvider().Repository("test")
	if err != nil || !found {
		t.Fatalf("configuration: found=%v err=%v", found, err)
	}
	cfg.AllowInsecureTransport = false
	cfg.BaseURL = "https://repo.example.test"
	if err := app.configProvider().Put(cfg); err != nil {
		t.Fatal(err)
	}
	warnings.Reset()
	if err := cmdInstall(app, []string{"widget", "--dry-run"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(warnings.String(), "insecure transport") {
		t.Errorf("disabled allowance warned: %q", warnings.String())
	}
}

func TestInsecureTransportWarningPrecedesFailedFetch(t *testing.T) {
	root := t.TempDir()
	repo := newRepoServer(t, root)
	// No index has been published, so this trust ceremony will fail.
	code, events := drive(t, root, "", "repo", "add", "test", repo.srv.URL, "--anchor", signature.Fingerprint(repo.pub), "--insecure")
	if code == 0 {
		t.Fatal("add unexpectedly succeeded")
	}
	if len(events) < 2 || events[0]["event"] != "warning" || !strings.Contains(events[0]["text"].(string), `repository "test" allows insecure transport`) {
		t.Fatalf("failed add lacked initial transport warning: %v", events)
	}
}
