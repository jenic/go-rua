package main

import (
	"path/filepath"
	"testing"
)

func TestBuildEnv(t *testing.T) {
	t.Setenv("FOO", "bar")
	env := buildEnv([]string{"FOO", "PATH=/custom", "BAZ=qux"})
	// Expect FOO value carried, PATH exactly as provided, and BAZ exactly
	has := func(kv string) bool {
		for _, e := range env {
			if e == kv {
				return true
			}
		}
		return false
	}
	if !has("FOO=bar") || !has("PATH=/custom") || !has("BAZ=qux") {
		t.Fatalf("unexpected env: %v", env)
	}
}

func TestApplyLandlockStub(t *testing.T) {
	// Ensure paths exist or not; stub ignores real enforcement
	d := t.TempDir()
	cfg := struct {
		RO, ROX, RW, RWX                            []string
		Env                                         []string
		BestEffort, UnrestrictedFS, UnrestrictedNet bool
		UseBubblewrap                               bool
		SeccompDenylist                             bool
	}{
		RO:  []string{"/etc", d},
		ROX: []string{"/usr", "/bin"},
		RW:  []string{"/dev/null"},
		RWX: []string{filepath.Join(d, "rw")},
	}
	if err := applyLandlock(cfg); err != nil {
		t.Fatalf("applyLandlock stub should not error: %v", err)
	}
}
