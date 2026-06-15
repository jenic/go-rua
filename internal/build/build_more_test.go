package build

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
		return exec.Command("/bin/true")
	})
	defer sandbox.SetExecCommandForTests(exec.Command)
	// Warn path via PKGEXT
	t.Setenv("PKGEXT", ".pkg.tar.foobar")
	// Respect RUA_ALWAYS_BWRAP then explicit weak-offline RUA_NO_BWRAP.
	t.Setenv("RUA_ALWAYS_BWRAP", "1")
	if err := BuildDirectory(dir, p, false, true, true); err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Setenv("RUA_ALWAYS_BWRAP", "")
	t.Setenv("RUA_NO_BWRAP", "1")
	t.Setenv("RUA_ALLOW_WEAK_OFFLINE", "1")
	if err := BuildDirectory(dir, p, true, false, false); err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestBuildDirectoryOfflineNoBwrapRequiresExplicitWeakOffline(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=('x')\npkgver=1\npkgrel=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := paths.Paths{ConfigDir: t.TempDir(), CacheBuildDir: t.TempDir(), DataCheckedTars: t.TempDir()}
	t.Setenv("RUA_NO_BWRAP", "1")
	if err := BuildDirectory(dir, p, true, false, false); err == nil || !strings.Contains(err.Error(), "requires bubblewrap") {
		t.Fatalf("expected bubblewrap requirement error, got %v", err)
	}
}

func TestBuildDirectoryMainSandboxExcludesGPGHome(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=('x')\npkgver=1\npkgrel=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := paths.Paths{ConfigDir: t.TempDir(), CacheBuildDir: t.TempDir(), DataCheckedTars: t.TempDir()}
	gnupg := t.TempDir()
	t.Setenv("GNUPGHOME", gnupg)
	capture := filepath.Join(t.TempDir(), "sandbox.json")
	sandbox.SetExecCommandForTests(func(name string, arg ...string) *exec.Cmd {
		return exec.Command("/bin/sh", "-c", `printf '%s' "$RUA_SANDBOX_CFG" > "$1"`, "sh", capture)
	})
	defer sandbox.SetExecCommandForTests(exec.Command)

	if err := BuildDirectory(dir, p, false, false, true); err != nil {
		t.Fatalf("BuildDirectory error: %v", err)
	}
	b, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	var cfg sandbox.Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	allRO := strings.Join(append(append([]string{}, cfg.RO...), cfg.ROX...), "\x00")
	if strings.Contains(allRO, gnupg) {
		t.Fatalf("main build sandbox must not include GNUPGHOME, cfg=%+v", cfg)
	}
}

func TestRunShell(t *testing.T) {
	dir := t.TempDir()
	sandbox.SetExecCommandForTests(func(name string, arg ...string) *exec.Cmd { return exec.Command("/bin/true") })
	defer sandbox.SetExecCommandForTests(exec.Command)
	if err := RunShell(dir); err != nil {
		t.Fatalf("RunShell err: %v", err)
	}
}
