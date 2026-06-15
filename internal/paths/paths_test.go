package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMustInitNoMakepkgChecksAndDirs(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	p := MustInitNoMakepkgChecks()
	if p.ConfigDir == "" || p.CacheBuildDir == "" || p.DataCheckedTars == "" {
		t.Fatalf("paths should not be empty: %+v", p)
	}
	// All should be absolute
	for _, v := range []string{p.ConfigDir, p.CacheBuildDir, p.DataCheckedTars} {
		if !filepath.IsAbs(v) {
			t.Fatalf("expected absolute path, got %q", v)
		}
		if fi, err := os.Stat(v); err != nil || !fi.IsDir() {
			t.Fatalf("expected dir exists: %q: %v", v, err)
		} else if got := fi.Mode().Perm(); got != 0o700 {
			t.Fatalf("expected private dir permissions for %q, got %o", v, got)
		}
	}

	// Subdir helpers create directories
	r := p.ReviewDir("pkgbase1")
	if fi, err := os.Stat(r); err != nil || !fi.IsDir() {
		t.Fatalf("ReviewDir should create dir: %v", err)
	} else if got := fi.Mode().Perm(); got != 0o700 {
		t.Fatalf("ReviewDir permissions = %o, want 700", got)
	}
	b := p.BuildDir("pkgbase1")
	if fi, err := os.Stat(b); err != nil || !fi.IsDir() {
		t.Fatalf("BuildDir should create dir: %v", err)
	} else if got := fi.Mode().Perm(); got != 0o700 {
		t.Fatalf("BuildDir permissions = %o, want 700", got)
	}
	c := p.CheckedTarsDir("pkgbase1")
	if fi, err := os.Stat(c); err != nil || !fi.IsDir() {
		t.Fatalf("CheckedTarsDir should create dir: %v", err)
	} else if got := fi.Mode().Perm(); got != 0o700 {
		t.Fatalf("CheckedTarsDir permissions = %o, want 700", got)
	}
}

func TestGetenvDefault(t *testing.T) {
	t.Setenv("FOO", "bar")
	if got := getenvDefault("FOO", "zzz"); got != "bar" {
		t.Fatalf("getenvDefault prefers env: %q", got)
	}
	if got := getenvDefault("NOPE", "zzz"); got != "zzz" {
		t.Fatalf("getenvDefault fallback: %q", got)
	}
}
