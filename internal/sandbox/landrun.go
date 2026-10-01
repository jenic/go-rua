package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

// ReadStream consumes stdout without buffering an entire decompressed archive.
// A failed inspection kills the child; stderr is bounded and never mixed with data.
func ReadStream(cfg Config, argv []string, inspect func(io.Reader) error) error {
	if len(argv) == 0 {
		return fmt.Errorf("sandbox: empty argv")
	}
	payload, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := streamCommandHook(ctx, selfExecutable(), append([]string{"sandbox-exec"}, argv...)...)
	cmd.Env = []string{"RUA_SANDBOX_CFG=" + string(payload)}
	cmd.Stderr = io.Discard
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	err = inspect(stdout)
	if err != nil {
		cancel()
	}
	waitErr := cmd.Wait()
	if err != nil {
		return err
	}
	return waitErr
}

// Config describes sandbox parameters we care about
type Config struct {
	RO               []string // read-only
	ROX              []string // read-only with exec
	RW               []string // read-write
	RWX              []string // read-write with exec
	Env              []string // env var pass-through (KEY or KEY=VALUE)
	WorkDir          string   // working directory for the target process
	BestEffort       bool
	UnrestrictedFS   bool
	UnrestrictedNet  bool // best-effort; may not be enforced by Landlock
	UseBubblewrap    bool // when true, wrap process in bubblewrap; add --unshare-net when UnrestrictedNet=false
	AllowWeakOffline bool // allow offline mode to proceed without bubblewrap network isolation
	SeccompDenylist  bool // apply a minimal seccomp denylist to the target process
}

// execCommandHook allows tests to override process spawning.
var (
	execCommandHook   = exec.Command
	streamCommandHook = exec.CommandContext
	executableFn      = os.Executable
)

// Run executes a command inside a Landlock sandbox via our embedded runner
func Run(cfg Config, argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("sandbox: empty argv")
	}
	payload, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	// Re-enter our own binary with the hidden subcommand "sandbox-exec".
	self := selfExecutable()
	cmd := execCommandHook(self, append([]string{"sandbox-exec"}, argv...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	// Do not inherit env by default; the runner will construct child env from cfg.Env
	cmd.Env = append([]string{}, "RUA_SANDBOX_CFG="+string(payload))
	return cmd.Run()
}

// RunCapture runs a command in the sandbox and returns combined stdout
func RunCapture(cfg Config, argv []string) (string, string, error) {
	if len(argv) == 0 {
		return "", "", fmt.Errorf("sandbox: empty argv")
	}
	payload, err := json.Marshal(cfg)
	if err != nil {
		return "", "", err
	}
	self := selfExecutable()
	cmd := execCommandHook(self, append([]string{"sandbox-exec"}, argv...)...)
	cmd.Env = append([]string{}, "RUA_SANDBOX_CFG="+string(payload))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), "", err
	}
	return string(out), "", nil
}

// SetExecCommandForTests overrides the command runner in tests.
func SetExecCommandForTests(fn func(name string, arg ...string) *exec.Cmd) {
	execCommandHook = fn
}

func selfExecutable() string {
	if exe, err := executableFn(); err == nil && exe != "" {
		return exe
	}
	return os.Args[0]
}
