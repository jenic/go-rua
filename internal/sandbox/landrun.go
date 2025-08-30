package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

// Config describes sandbox parameters we care about
type Config struct {
    RO              []string // read-only
    ROX             []string // read-only with exec
    RW              []string // read-write
    RWX             []string // read-write with exec
    Env             []string // env var pass-through (KEY or KEY=VALUE)
    BestEffort      bool
    UnrestrictedFS  bool
    UnrestrictedNet bool // best-effort; may not be enforced by Landlock
    UseBubblewrap   bool // when true and UnrestrictedNet=false, prefer bwrap --unshare-net
    SeccompDenylist bool // apply a minimal seccomp denylist to the target process
}

// Run executes a command inside a Landlock sandbox via our embedded runner
func Run(cfg Config, argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("sandbox: empty argv")
	}
	payload, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	// Re-enter our own binary with the hidden subcommand "sandbox-exec"
	self := os.Args[0]
	cmd := exec.Command(self, append([]string{"sandbox-exec"}, argv...)...)
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
	self := os.Args[0]
	cmd := exec.Command(self, append([]string{"sandbox-exec"}, argv...)...)
	cmd.Env = append([]string{}, "RUA_SANDBOX_CFG="+string(payload))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), "", err
	}
	return string(out), "", nil
}
