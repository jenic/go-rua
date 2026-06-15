package build

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"go-rua/internal/paths"
	"go-rua/internal/sandbox"
)

func TestBuildDirectoryFlagsAndBwrapEnv(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=('x')\npkgver=1\npkgrel=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := paths.Paths{ConfigDir: t.TempDir(), CacheBuildDir: t.TempDir(), DataCheckedTars: t.TempDir()}
	// Stub execution to just succeed
	sandbox.SetExecCommandForTests(func(name string, arg ...string) *exec.Cmd {
		return exec.Command("bash", "-lc", "true")
	})
	defer sandbox.SetExecCommandForTests(exec.Command)
	// Warn path via PKGEXT
	t.Setenv("PKGEXT", ".pkg.tar.foobar")
	// Respect RUA_ALWAYS_BWRAP then RUA_NO_BWRAP (no assertion; just execute both branches)
	t.Setenv("RUA_ALWAYS_BWRAP", "1")
	if err := BuildDirectory(dir, p, false, true, true); err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Setenv("RUA_ALWAYS_BWRAP", "")
	t.Setenv("RUA_NO_BWRAP", "1")
	if err := BuildDirectory(dir, p, true, false, false); err != nil {
		t.Fatalf("err: %v", err)
	}

	// GNUPGHOME path branch
	t.Setenv("GNUPGHOME", t.TempDir())
	if err := BuildDirectory(dir, p, true, false, true); err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestRunShell(t *testing.T) {
	dir := t.TempDir()
	sandbox.SetExecCommandForTests(func(name string, arg ...string) *exec.Cmd { return exec.Command("bash", "-lc", "true") })
	defer sandbox.SetExecCommandForTests(exec.Command)
	if err := RunShell(dir); err != nil {
		t.Fatalf("RunShell err: %v", err)
	}
}
