package install

import (
	"os"
	"path/filepath"
	"testing"
)

func restoreInstallSeams(t *testing.T) {
	t.Helper()
	oldRun, oldRunC, oldRunCQ := runFn, runCFn, runCQFn
	oldShell, oldBuild, oldTar := runShell, buildDirectoryFn, tarCheck
	oldPacman, oldAudit, oldFormat := pacmanInstallLocalWithMode, sourceAuditFn, formatSourceAuditFn
	oldShellAudit, oldFormatShellAudit := shellAuditFn, formatShellAuditFn
	t.Cleanup(func() {
		runFn = oldRun
		runCFn = oldRunC
		runCQFn = oldRunCQ
		runShell = oldShell
		buildDirectoryFn = oldBuild
		tarCheck = oldTar
		pacmanInstallLocalWithMode = oldPacman
		sourceAuditFn = oldAudit
		formatSourceAuditFn = oldFormat
		shellAuditFn = oldShellAudit
		formatShellAuditFn = oldFormatShellAudit
	})
}

func TestParsePkgNameFromTar(t *testing.T) {
	cases := map[string]string{
		"foo-1.2-3-x86_64.pkg.tar.zst":     "foo",
		"bar-beta-1.0-1-x86_64.pkg.tar.xz": "bar-beta",
		"baz-1.0.0-2-aarch64.pkg.tar":      "baz",
		"pkg-1-1-any.pkg.tar.gz":           "pkg",
		"invalid-name.pkg":                 "",
		"onlyname.pkg.tar.zst":             "",
	}
	for in, want := range cases {
		if got := parsePkgNameFromTar(in); got != want {
			t.Fatalf("parsePkgNameFromTar(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestFilterArtifactsByWhitelist(t *testing.T) {
	files := []string{
		"/tmp/foo-1.0-1-x86_64.pkg.tar.zst",
		"/tmp/bar-2.0-2-x86_64.pkg.tar.xz",
		"/tmp/other.txt",
	}
	out := filterArtifactsByWhitelist(files, []string{"foo"})
	if len(out) != 1 || filepath.Base(out[0]) != "foo-1.0-1-x86_64.pkg.tar.zst" {
		t.Fatalf("unexpected filter result: %v", out)
	}
}

func TestMoveCrossDeviceSimple(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	dst := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := moveCrossDevice(src, dst); err != nil {
		t.Fatalf("moveCrossDevice error: %v", err)
	}
	if _, err := os.Stat(src); err == nil {
		t.Fatalf("src should be gone after move")
	}
	b, err := os.ReadFile(dst)
	if err != nil || string(b) != "x" {
		t.Fatalf("dst wrong content: %q, err=%v", string(b), err)
	}
}
