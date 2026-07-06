package sandbox

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestRunAndRunCaptureHook(t *testing.T) {
	var capturedArgs []string
	SetExecCommandForTests(func(name string, arg ...string) *exec.Cmd {
		capturedArgs = append([]string{name}, arg...)
		// Build a tiny shell that exits 0 or echoes for CombinedOutput
		// We’ll return a command that just exits 0; CombinedOutput path will be set below.
		cmd := exec.Command("bash", "-lc", "true")
		return cmd
	})
	defer SetExecCommandForTests(exec.Command)

	// Run records env
	cfg := Config{}
	if err := Run(cfg, []string{"echo", "ok"}); err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if len(capturedArgs) == 0 || !strings.Contains(strings.Join(capturedArgs, " "), "sandbox-exec") {
		t.Fatalf("expected sandbox-exec in args: %v", capturedArgs)
	}

	// Now test RunCapture to ensure it returns stdout content
	SetExecCommandForTests(func(name string, arg ...string) *exec.Cmd {
		capturedArgs = append([]string{name}, arg...)
		// Make the child print a known string
		return exec.Command("bash", "-lc", "printf 'hello'")
	})
	out, _, err := RunCapture(cfg, []string{"echo", "hi"})
	if err != nil || out != "hello" {
		t.Fatalf("RunCapture unexpected: out=%q err=%v", out, err)
	}
}

func TestRunUsesExecutablePath(t *testing.T) {
	oldExecutable := executableFn
	executableFn = func() (string, error) { return "/usr/local/bin/go-rua", nil }
	defer func() { executableFn = oldExecutable }()

	var capturedName string
	SetExecCommandForTests(func(name string, arg ...string) *exec.Cmd {
		capturedName = name
		return exec.Command("bash", "-lc", "true")
	})
	defer SetExecCommandForTests(exec.Command)

	if err := Run(Config{}, []string{"echo", "ok"}); err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if capturedName != "/usr/local/bin/go-rua" {
		t.Fatalf("sandbox launcher = %q, want resolved executable path", capturedName)
	}
}

func TestRunFallsBackToArgsZero(t *testing.T) {
	oldExecutable := executableFn
	executableFn = func() (string, error) { return "", errors.New("no executable") }
	defer func() { executableFn = oldExecutable }()

	var capturedName string
	SetExecCommandForTests(func(name string, arg ...string) *exec.Cmd {
		capturedName = name
		return exec.Command("bash", "-lc", "true")
	})
	defer SetExecCommandForTests(exec.Command)

	if err := Run(Config{}, []string{"echo", "ok"}); err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if capturedName == "" {
		t.Fatalf("expected fallback launcher path")
	}
}
