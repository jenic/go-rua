package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"go-rua/internal/term"
)

func TestMainProcessEntryExit(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		version    string
		wantCode   int
		wantStdout []string
		wantStderr []string
	}{
		{
			name:       "no args prints usage and exits two",
			wantCode:   2,
			wantStdout: []string{"go-rua: AUR helper", "Usage:", "Commands:"},
		},
		{
			name:       "unknown command prints error usage and exits two",
			args:       []string{"bogus"},
			wantCode:   2,
			wantStdout: []string{"go-rua: AUR helper", "Usage:"},
			wantStderr: []string{"unknown command: bogus"},
		},
		{
			name:       "version command prints version",
			args:       []string{"version"},
			version:    "1.2.3-test",
			wantStdout: []string{"1.2.3-test"},
		},
		{
			name:       "version alias prints version",
			args:       []string{"--version"},
			version:    "alias-version",
			wantStdout: []string{"alias-version"},
		},
		{
			name:       "help command prints usage",
			args:       []string{"help"},
			wantStdout: []string{"go-rua: AUR helper", "Usage:", "go-rua help <command>", "Global options:"},
		},
		{
			name:       "help alias prints usage",
			args:       []string{"--help"},
			wantStdout: []string{"go-rua: AUR helper", "Commands:"},
		},
		{
			name:       "help topic dispatches to command usage",
			args:       []string{"help", "install"},
			wantStdout: []string{"Review, build, stage, and install AUR packages.", "Usage:", "go-rua install", "--install-repo-deps", "Review controls:", "Examples:"},
		},
		{
			name:       "command help flag prints detailed help",
			args:       []string{"upgrade", "--help"},
			wantStdout: []string{"Review, build, and install available AUR upgrades.", "--printonly", "Exit status:", "go-rua upgrade --plan"},
		},
		{
			name:       "version command has dedicated help",
			args:       []string{"version", "--help"},
			wantStdout: []string{"Print the go-rua version.", "Usage:", "go-rua version", "Examples:"},
		},
		{
			name:       "removed install flag is a usage error",
			args:       []string{"install", "--install", "yay"},
			wantCode:   2,
			wantStdout: []string{"flag provided but not defined: -install", "go-rua install [options]"},
		},
		{
			name:       "removed upgrade flag is a usage error",
			args:       []string{"upgrade", "--apply"},
			wantCode:   2,
			wantStdout: []string{"flag provided but not defined: -apply", "go-rua upgrade [options]"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, code := runMainProcess(t, "main", tt.version, tt.args...)
			if code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, stdout, stderr)
			}
			for _, want := range tt.wantStdout {
				if !strings.Contains(stdout, want) {
					t.Fatalf("stdout missing %q\nstdout:\n%s\nstderr:\n%s", want, stdout, stderr)
				}
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr, want) {
					t.Fatalf("stderr missing %q\nstdout:\n%s\nstderr:\n%s", want, stdout, stderr)
				}
			}
		})
	}
}

func TestMainProcessColorFlagHandling(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantColor   string
		wantEnabled string
	}{
		{
			name:        "equals form before command",
			args:        []string{"--color=always", "version"},
			wantColor:   "always",
			wantEnabled: "true",
		},
		{
			name:        "split form before command",
			args:        []string{"--color", "never", "version"},
			wantColor:   "never",
			wantEnabled: "false",
		},
		{
			name:      "equals form after command is stripped before dispatch",
			args:      []string{"version", "--color=auto"},
			wantColor: "auto",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, code := runMainProcess(t, "main-color", "color-version", tt.args...)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			if !strings.Contains(stdout, "color-version") {
				t.Fatalf("version output missing after color filtering\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
			}
			if !strings.Contains(stderr, "RUA_COLOR="+tt.wantColor) {
				t.Fatalf("color env not set to %q\nstdout:\n%s\nstderr:\n%s", tt.wantColor, stdout, stderr)
			}
			if tt.wantEnabled != "" && !strings.Contains(stderr, "TERM_ENABLED="+tt.wantEnabled) {
				t.Fatalf("terminal color state = unexpected, want %s\nstdout:\n%s\nstderr:\n%s", tt.wantEnabled, stdout, stderr)
			}
		})
	}
}

func TestMainProcessColorFlagRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "invalid value", args: []string{"--color=rainbow", "version"}, want: "invalid --color value"},
		{name: "missing value", args: []string{"--color"}, want: "--color requires a value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, stderr, code := runMainProcess(t, "main", "color-version", tt.args...)
			if code != 2 {
				t.Fatalf("exit code = %d, want 2\nstderr:\n%s", code, stderr)
			}
			if !strings.Contains(stderr, tt.want) {
				t.Fatalf("stderr missing %q: %q", tt.want, stderr)
			}
		})
	}
}

func TestFatalfProcessExit(t *testing.T) {
	stdout, stderr, code := runMainProcess(t, "fatalf", "", "ignored")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if stdout != "" {
		t.Fatalf("fatalf wrote stdout: %q", stdout)
	}
	if !strings.Contains(stderr, "Error: fatal path: boom") {
		t.Fatalf("fatalf stderr missing message: %q", stderr)
	}
}

func TestMainDispatchesSandboxExec(t *testing.T) {
	oldArgs := os.Args
	oldSyscallExec := syscallExecFn
	oldApplyLandlock := applyLandlockFn
	oldApplySeccomp := applySeccompDenylistFn
	oldExit := osExitFn
	defer func() {
		os.Args = oldArgs
		syscallExecFn = oldSyscallExec
		applyLandlockFn = oldApplyLandlock
		applySeccompDenylistFn = oldApplySeccomp
		osExitFn = oldExit
	}()

	var gotProg string
	var gotArgs []string
	syscallExecFn = func(prog string, args []string, env []string) error {
		gotProg = prog
		gotArgs = append([]string(nil), args...)
		return nil
	}
	applyLandlockFn = func(_ sandboxExecConfig) error {
		t.Fatal("sandbox-exec dispatch should not apply Landlock when UnrestrictedFS is true")
		return nil
	}
	applySeccompDenylistFn = func() error {
		t.Fatal("sandbox-exec dispatch should not apply seccomp without SeccompDenylist")
		return nil
	}
	osExitFn = func(code int) {
		t.Fatalf("unexpected sandbox-exec exit %d", code)
	}
	t.Setenv("RUA_SANDBOX_CFG", `{"Env":["PATH=/bin"],"UnrestrictedFS":true}`)
	os.Args = []string{"go-rua", "sandbox-exec", "/bin/echo", "ok"}

	main()

	if gotProg != "/bin/echo" {
		t.Fatalf("sandbox-exec prog = %q, want /bin/echo", gotProg)
	}
	if len(gotArgs) != 2 || gotArgs[0] != "/bin/echo" || gotArgs[1] != "ok" {
		t.Fatalf("sandbox-exec args = %v, want [/bin/echo ok]", gotArgs)
	}
}

func runMainProcess(t *testing.T, mode, version string, args ...string) (string, string, int) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmdArgs := append([]string{"-test.run=^TestMainProcessHelper$", "--"}, args...)
	cmd := exec.Command(exe, cmdArgs...)
	cmd.Env = append(withoutEnvKey(os.Environ(), "RUA_COLOR"),
		"RUA_PROCESS_HELPER=1",
		"RUA_PROCESS_HELPER_MODE="+mode,
		"RUA_PROCESS_HELPER_VERSION="+version,
		"RUA_COLOR=",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("helper failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
		}
	}
	return stdout.String(), stderr.String(), code
}

func withoutEnvKey(env []string, key string) []string {
	prefix := key + "="
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		if !strings.HasPrefix(entry, prefix) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func TestMainProcessHelper(t *testing.T) {
	if os.Getenv("RUA_PROCESS_HELPER") != "1" {
		t.Skip("process helper only")
	}

	mode := os.Getenv("RUA_PROCESS_HELPER_MODE")
	Version = os.Getenv("RUA_PROCESS_HELPER_VERSION")
	originalArgs := os.Args
	os.Args = []string{"go-rua"}
	for i, arg := range originalArgs {
		if arg == "--" {
			os.Args = append([]string{"go-rua"}, originalArgs[i+1:]...)
			break
		}
	}

	switch mode {
	case "main":
		main()
	case "main-color":
		main()
		fmt.Fprintf(os.Stderr, "RUA_COLOR=%s TERM_ENABLED=%t\n", os.Getenv("RUA_COLOR"), term.Enabled())
	case "fatalf":
		fatalf("fatal path: %s", "boom")
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
}
