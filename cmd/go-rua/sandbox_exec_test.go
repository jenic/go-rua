package main

import (
	"fmt"
	"os"
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

func TestSandboxExecMissingConfigExits(t *testing.T) {
	// Override osExit to capture code
	oldExit := osExitFn
	defer func() { osExitFn = oldExit }()
	var code int
	osExitFn = func(c int) { panic(fmt.Sprintf("exit:%d", c)) }
	// Ensure env has no config
	t.Setenv("RUA_SANDBOX_CFG", "")
	defer func() { _ = recover() }()
	sandboxExec()
	_ = code
}

func TestSandboxExecSeccompOnlyPathResolution(t *testing.T) {
	// Setup seams to capture syscallExec inputs
	called := false
	oldSyscall := syscallExecFn
	oldLook := lookPathFn
	oldExit := osExitFn
	syscallExecFn = func(prog string, args []string, env []string) error {
		called = true
		if prog != "/bin/echo" {
			t.Fatalf("unexpected prog: %s", prog)
		}
		if len(args) < 2 || args[1] != "ok" {
			t.Fatalf("unexpected args: %v", args)
		}
		return nil
	}
	lookPathFn = func(file string) (string, error) { return "/bin/echo", nil }
	osExitFn = func(c int) { t.Fatalf("unexpected exit %d", c) }
	defer func() { syscallExecFn = oldSyscall; lookPathFn = oldLook; osExitFn = oldExit }()

	// Build config with seccomp-only
	cfg := `{"Env":["PATH=/bin"],"SeccompDenylist":true}`
	t.Setenv("RUA_SANDBOX_CFG", cfg)
	t.Setenv("RUA_SECCOMP_ONLY", "1")
	// Bypass seccomp
	oldSec := applySeccompDenylistFn
	applySeccompDenylistFn = func() error { return nil }
	defer func() { applySeccompDenylistFn = oldSec }()
	// Provide command in os.Args
	oldArgs := os.Args
	os.Args = []string{"go-rua", "sandbox-exec", "echo", "ok"}
	defer func() { os.Args = oldArgs }()
	sandboxExec()
	if !called {
		t.Fatalf("syscallExec not called")
	}
}

func TestSandboxExecBubblewrapPath(t *testing.T) {
	// Simulate bwrap present and capture invocation
	oldLook := lookPathFn
	lookPathFn = func(f string) (string, error) {
		if f == "bwrap" {
			return "/usr/bin/bwrap", nil
		}
		return f, nil
	}
	defer func() { lookPathFn = oldLook }()
	called := false
	oldSys := syscallExecFn
	syscallExecFn = func(prog string, args []string, env []string) error {
		called = true
		if args[0] != "bwrap" {
			t.Fatalf("expected bwrap, got %v", args)
		}
		found := false
		for _, e := range env {
			if e == "RUA_SECCOMP_ONLY=1" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected RUA_SECCOMP_ONLY in env")
		}
		return nil
	}
	defer func() { syscallExecFn = oldSys }()
	oldExit := osExitFn
	osExitFn = func(c int) { t.Fatalf("unexpected exit %d", c) }
	defer func() { osExitFn = oldExit }()
	oldArgs := os.Args
	os.Args = []string{"go-rua", "sandbox-exec", "/bin/true"}
	defer func() { os.Args = oldArgs }()
	cfg := `{"Env":["PATH=/bin"],"UseBubblewrap":true,"UnrestrictedNet":false}`
	t.Setenv("RUA_SANDBOX_CFG", cfg)
	sandboxExec()
	if !called {
		t.Fatalf("bwrap path not executed")
	}
}

func TestSandboxExecLandlockAndSeccomp(t *testing.T) {
	oldAL := applyLandlockFn
	applyLandlockFn = func(_ struct {
		RO, ROX, RW, RWX                            []string
		Env                                         []string
		BestEffort, UnrestrictedFS, UnrestrictedNet bool
		UseBubblewrap                               bool
		SeccompDenylist                             bool
	}) error {
		return nil
	}
	defer func() { applyLandlockFn = oldAL }()
	oldSec := applySeccompDenylistFn
	applySeccompDenylistFn = func() error { return nil }
	defer func() { applySeccompDenylistFn = oldSec }()
	oldArgs := os.Args
	os.Args = []string{"go-rua", "sandbox-exec", "/bin/true"}
	defer func() { os.Args = oldArgs }()
	oldSys := syscallExecFn
	syscallExecFn = func(prog string, args []string, env []string) error { return nil }
	defer func() { syscallExecFn = oldSys }()
	oldExit := osExitFn
	osExitFn = func(c int) { t.Fatalf("unexpected exit %d", c) }
	defer func() { osExitFn = oldExit }()
	cfg := `{"Env":["PATH=/bin"],"UnrestrictedFS":false,"UseBubblewrap":false,"SeccompDenylist":true}`
	t.Setenv("RUA_SANDBOX_CFG", cfg)
	sandboxExec()
}
