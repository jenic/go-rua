package shellutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"go-rua/internal/paths"
	"go-rua/internal/sandbox"
)

func TestShellcheckHappyPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "PKGBUILD")
	if err := os.WriteFile(target, []byte("pkgname=('demo')\npkgver=1\npkgrel=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Stub sandbox to succeed without actually running shellcheck
	sandbox.SetExecCommandForTests(func(name string, arg ...string) *exec.Cmd {
		return exec.Command("bash", "-lc", "true")
	})
	defer sandbox.SetExecCommandForTests(exec.Command)
	if err := Shellcheck(target, paths.Paths{}); err != nil {
		t.Fatalf("Shellcheck returned error: %v", err)
	}
}

func TestNamcapHappyPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "PKGBUILD")
	if err := os.WriteFile(target, []byte("pkgname=('demo')\npkgver=1\npkgrel=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sandbox.SetExecCommandForTests(func(name string, arg ...string) *exec.Cmd {
		return exec.Command("bash", "-lc", "true")
	})
	defer sandbox.SetExecCommandForTests(exec.Command)
	if err := Namcap(dir, paths.Paths{}); err != nil {
		t.Fatalf("Namcap returned error: %v", err)
	}
}
