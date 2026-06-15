package build

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadWrapArgs(t *testing.T) {
	dir := t.TempDir()
	wad := filepath.Join(dir, "wrap_args.d")
	if err := os.MkdirAll(wad, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "# comment\nro:/etc\nrox:/opt/bin\nrw:/var/cache\nrwx:/tmp\ninvalid\n  ro: /space path \n"
	if err := os.WriteFile(filepath.Join(wad, "a.conf"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	ro, rox, rw, rwx := readWrapArgs(dir)
	join := func(ss []string) string { return strings.Join(ss, ",") }
	if !strings.Contains(join(ro), "/etc") {
		t.Fatalf("expected ro contains /etc, got %v", ro)
	}
	if !strings.Contains(join(rox), "/opt/bin") {
		t.Fatalf("expected rox contains /opt/bin, got %v", rox)
	}
	if !strings.Contains(join(rw), "/var/cache") {
		t.Fatalf("expected rw contains /var/cache, got %v", rw)
	}
	if !strings.Contains(join(rwx), "/tmp") {
		t.Fatalf("expected rwx contains /tmp, got %v", rwx)
	}
	// space is kept as-is (consumer decides how to handle)
	if !strings.Contains(join(ro), "/space path") {
		t.Fatalf("expected space path kept: %v", ro)
	}
}

func TestWriteStaticPKGBUILDFromSRCINFO(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("only needs linux path semantics")
	}
	dir := t.TempDir()
	srcinfo := `pkgbase = demo\n pkgname = demo\n pkgver = 1.2\n pkgrel = 3\n source = http://example.com/a.tar.gz\n sha256sums = deadbeef\n`
	if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), []byte(srcinfo), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "PKGBUILD.static")
	if err := writeStaticPKGBUILDFromSRCINFO(dir, dst); err != nil {
		t.Fatalf("writeStaticPKGBUILDFromSRCINFO error: %v", err)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.HasPrefix(s, "#!/bin/bash") {
		t.Fatalf("PKGBUILD header missing: %q", s)
	}
}

func TestCopyTreeCopiesDotfilesAndSymlinks(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "dst")
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, ".dot"), []byte("dot"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "f.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sub/f.txt", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "")
	if err := CopyTree(src, dst); err != nil {
		t.Fatalf("CopyTree error: %v", err)
	}
	if fi, err := os.Stat(dst); err != nil || !fi.IsDir() {
		t.Fatalf("destination root not created: %v", err)
	} else if got := fi.Mode().Perm(); got != 0o700 {
		t.Fatalf("destination root permissions = %o, want 700", got)
	}
	if fi, err := os.Stat(filepath.Join(dst, "sub")); err != nil || !fi.IsDir() {
		t.Fatalf("subdirectory not copied: %v", err)
	} else if got := fi.Mode().Perm(); got != 0o755 {
		t.Fatalf("subdirectory permissions = %o, want copied 755", got)
	}
	if b, err := os.ReadFile(filepath.Join(dst, ".dot")); err != nil || string(b) != "dot" {
		t.Fatalf("dotfile not copied: %q %v", string(b), err)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "sub", "f.txt")); err != nil || string(b) != "hello" {
		t.Fatalf("nested file not copied: %q %v", string(b), err)
	}
	if link, err := os.Readlink(filepath.Join(dst, "link")); err != nil || link != "sub/f.txt" {
		t.Fatalf("symlink not preserved: %q %v", link, err)
	}
}
