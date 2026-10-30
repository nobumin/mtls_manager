//go:build unix

package flock

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// ロックファイルは umask に関わらず 0644 にする（root の mtlsctl と mtls-ca の両方が開けるように）。
func TestLockFileIsReadableByOthers(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	path := filepath.Join(t.TempDir(), "eab.json")
	unlock, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	fi, err := os.Stat(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("ロックファイルの権限 = %o", fi.Mode().Perm())
	}
}
