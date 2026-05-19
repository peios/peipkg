package install

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// assertContent fails unless the file at path holds exactly want.
func assertContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != want {
		t.Errorf("%s: content is %q, want %q", path, got, want)
	}
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("%s should not exist (err %v)", path, err)
	}
}

func TestTempPath(t *testing.T) {
	if got := tempPath("/usr/bin/nginx", stagedMarker, 7); got != "/usr/bin/nginx.peipkg-staged-7" {
		t.Errorf("tempPath: got %q", got)
	}
	// A long base name is truncated to keep the component within 255 bytes.
	long := "/usr/bin/" + string(make([]byte, 300))
	got := tempPath(long, backupMarker, 1)
	if base := filepath.Base(got); len(base) > maxComponent {
		t.Errorf("tempPath did not truncate: component is %d bytes", len(base))
	}
}

func TestCommitCreate(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "nginx")
	staged := tempPath(final, stagedMarker, 1)
	writeFile(t, staged, "new content")

	op := fileOp{finalPath: final, action: actionCreate, stagedPath: staged}
	if err := commitOps([]fileOp{op}); err != nil {
		t.Fatalf("commitOps: %v", err)
	}
	assertContent(t, final, "new content")
	assertAbsent(t, staged)
}

func TestCommitReplace(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "app.conf")
	staged := tempPath(final, stagedMarker, 1)
	backup := tempPath(final, backupMarker, 1)
	writeFile(t, final, "old content")
	writeFile(t, staged, "new content")

	op := fileOp{finalPath: final, action: actionReplace, stagedPath: staged, backupPath: backup}
	if err := commitOps([]fileOp{op}); err != nil {
		t.Fatalf("commitOps: %v", err)
	}
	assertContent(t, final, "new content")
	assertContent(t, backup, "old content") // the displaced file is backed up, not destroyed
	assertAbsent(t, staged)
}

func TestCommitRemove(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "obsolete")
	backup := tempPath(final, backupMarker, 1)
	writeFile(t, final, "doomed content")

	op := fileOp{finalPath: final, action: actionRemove, backupPath: backup}
	if err := commitOps([]fileOp{op}); err != nil {
		t.Fatalf("commitOps: %v", err)
	}
	assertAbsent(t, final)
	assertContent(t, backup, "doomed content")
}

func TestRollbackCreateBeforeCommit(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "nginx")
	staged := tempPath(final, stagedMarker, 1)
	writeFile(t, staged, "staged content")

	op := fileOp{finalPath: final, action: actionCreate, stagedPath: staged}
	if err := rollbackOps([]fileOp{op}); err != nil {
		t.Fatalf("rollbackOps: %v", err)
	}
	assertAbsent(t, staged)
	assertAbsent(t, final)
}

func TestRollbackCreateAfterCommit(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "nginx")
	staged := tempPath(final, stagedMarker, 1)
	writeFile(t, staged, "content")

	op := fileOp{finalPath: final, action: actionCreate, stagedPath: staged}
	if err := commitOps([]fileOp{op}); err != nil {
		t.Fatalf("commitOps: %v", err)
	}
	if err := rollbackOps([]fileOp{op}); err != nil {
		t.Fatalf("rollbackOps: %v", err)
	}
	assertAbsent(t, final) // a committed create is undone — nothing existed before
}

func TestRollbackReplaceAfterCommit(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "app.conf")
	staged := tempPath(final, stagedMarker, 1)
	backup := tempPath(final, backupMarker, 1)
	writeFile(t, final, "original")
	writeFile(t, staged, "replacement")

	op := fileOp{finalPath: final, action: actionReplace, stagedPath: staged, backupPath: backup}
	if err := commitOps([]fileOp{op}); err != nil {
		t.Fatalf("commitOps: %v", err)
	}
	if err := rollbackOps([]fileOp{op}); err != nil {
		t.Fatalf("rollbackOps: %v", err)
	}
	assertContent(t, final, "original") // the original is restored from backup
	assertAbsent(t, backup)
}

func TestRollbackRemoveAfterCommit(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "obsolete")
	backup := tempPath(final, backupMarker, 1)
	writeFile(t, final, "content")

	op := fileOp{finalPath: final, action: actionRemove, backupPath: backup}
	if err := commitOps([]fileOp{op}); err != nil {
		t.Fatalf("commitOps: %v", err)
	}
	if err := rollbackOps([]fileOp{op}); err != nil {
		t.Fatalf("rollbackOps: %v", err)
	}
	assertContent(t, final, "content") // the removed file is restored
}

func TestRollbackIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "app.conf")
	staged := tempPath(final, stagedMarker, 1)
	backup := tempPath(final, backupMarker, 1)
	writeFile(t, final, "original")
	writeFile(t, staged, "replacement")

	op := fileOp{finalPath: final, action: actionReplace, stagedPath: staged, backupPath: backup}
	if err := commitOps([]fileOp{op}); err != nil {
		t.Fatalf("commitOps: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := rollbackOps([]fileOp{op}); err != nil {
			t.Fatalf("rollbackOps (pass %d): %v", i, err)
		}
	}
	assertContent(t, final, "original")
}

func TestLockIsExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")

	first, err := Acquire(path)
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	if _, err := Acquire(path); err == nil {
		t.Error("a second Acquire should fail while the lock is held")
	}
	if err := first.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	again, err := Acquire(path)
	if err != nil {
		t.Fatalf("Acquire after Release: %v", err)
	}
	_ = again.Release()
}
