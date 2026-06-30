package build

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go-rua/internal/paths"
	"go-rua/internal/sandbox"
)

func TestBuildDirectoryMissingPKGBUILD(t *testing.T) {
	dir := t.TempDir()
	p := paths.Paths{ConfigDir: t.TempDir(), CacheBuildDir: t.TempDir(), DataCheckedTars: t.TempDir()}
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
		return exec.Command("/bin/true")
	})
	defer sandbox.SetExecCommandForTests(exec.Command)
	p := paths.Paths{ConfigDir: t.TempDir(), CacheBuildDir: t.TempDir(), DataCheckedTars: t.TempDir()}
	if err := prefetchSources(dir, p, true); err != nil {
		t.Fatalf("prefetchSources err: %v", err)
	}
	for _, want := range []string{"makepkg", "--nosign", "--verifysource", "-p", "PKGBUILD.static"} {
		if !stringSliceContains(sandboxArgs, want) {
			t.Fatalf("prefetch sandbox args missing %q: %v", want, sandboxArgs)
		}
	}
}

func TestPrefetchSourcesFailsWhenStaticPKGBUILDGenerationFails(t *testing.T) {
	dir := t.TempDir()
	longLine := strings.Repeat("a", 70*1024)
	if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), []byte(longLine), 0o644); err != nil {
		t.Fatal(err)
	}
	p := paths.Paths{ConfigDir: t.TempDir(), CacheBuildDir: t.TempDir(), DataCheckedTars: t.TempDir()}
	err := prefetchSources(dir, p, true)
	if err == nil || !strings.Contains(err.Error(), "generate static PKGBUILD") {
		t.Fatalf("expected static PKGBUILD error, got %v", err)
	}
}

func stringSliceContains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
