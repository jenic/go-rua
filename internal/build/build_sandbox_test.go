package build

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"go-rua/internal/paths"
	"go-rua/internal/sandbox"
)

func TestBuildDirectoryMissingPKGBUILD(t *testing.T) {
	dir := t.TempDir()
	p := paths.MustInitNoMakepkgChecks()
	if err := BuildDirectory(dir, p, true, false, false); err == nil {
		t.Fatalf("expected error when PKGBUILD missing")
	}
}

func TestPrefetchSourcesUsesStatic(t *testing.T) {
	dir := t.TempDir()
	// write .SRCINFO to trigger static path selection
	if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), []byte("pkgbase = demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// stub sandbox to succeed; we don't validate args deeply here
	sandbox.SetExecCommandForTests(func(name string, arg ...string) *exec.Cmd {
		return exec.Command("bash", "-lc", "true")
	})
	defer sandbox.SetExecCommandForTests(exec.Command)
	p := paths.MustInitNoMakepkgChecks()
	if err := prefetchSources(dir, p, true); err != nil {
		t.Fatalf("prefetchSources err: %v", err)
	}
}
