package sandbox

import (
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
