package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	ll "github.com/landlock-lsm/go-landlock/landlock"
)

// sandboxExec is invoked as a hidden subcommand: go-rua sandbox-exec <cmd> [args...]
// It applies a Landlock ruleset (based on RUA_SANDBOX_CFG) and then execs the target.
func sandboxExec() {
	// Parse config from env
	cfgJSON := os.Getenv("RUA_SANDBOX_CFG")
	if cfgJSON == "" {
		fmt.Fprintln(os.Stderr, "sandbox-exec: missing RUA_SANDBOX_CFG")
		os.Exit(97)
	}
	var cfg struct {
		RO              []string
		ROX             []string
		RW              []string
		RWX             []string
		Env             []string
		BestEffort      bool
		UnrestrictedFS  bool
		UnrestrictedNet bool
	}
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-exec: invalid config:", err)
		os.Exit(98)
	}

	args := os.Args[2:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "sandbox-exec: no command provided")
		os.Exit(99)
	}

	// If unrestricted filesystem requested, skip Landlock.
	// Otherwise, construct a ruleset that allows the requested paths.
	if !cfg.UnrestrictedFS {
		if err := applyLandlock(cfg); err != nil {
			if cfg.BestEffort {
				// Print a note but continue
				fmt.Fprintln(os.Stderr, "warning: failed to apply Landlock (best-effort):", err)
			} else {
				fmt.Fprintln(os.Stderr, "sandbox-exec: failed to apply Landlock:", err)
				os.Exit(100)
			}
		}
	}

	// Build sanitized environment for the target
	childEnv := buildEnv(cfg.Env)

	// Resolve the command path if needed
	prog := args[0]
	if !strings.Contains(prog, "/") {
		// Derive PATH from childEnv
		var pathVal string
		for _, e := range childEnv {
			if strings.HasPrefix(e, "PATH=") {
				pathVal = strings.TrimPrefix(e, "PATH=")
			}
		}
		if pathVal == "" {
			pathVal = "/usr/bin:/bin"
		}
		_ = os.Setenv("PATH", pathVal)
		if p, err := exec.LookPath(prog); err == nil {
			prog = p
		}
	} else {
		// make absolute if relative
		if !strings.HasPrefix(prog, "/") {
			if ap, err := filepath.Abs(prog); err == nil {
				prog = ap
			}
		}
	}

	// Replace our process image with the target
	if err := syscallExec(prog, append([]string{prog}, args[1:]...), childEnv); err != nil {
		fmt.Fprintln(os.Stderr, "exec failed:", err)
		os.Exit(101)
	}
}

// applyLandlock constructs and installs a Landlock ruleset based on cfg.
func applyLandlock(cfg struct {
	RO, ROX, RW, RWX                            []string
	Env                                         []string
	BestEffort, UnrestrictedFS, UnrestrictedNet bool
}) error {
	// Determine the superset of filesystem accesses we might grant.
	handled := ll.AccessFSReadFile | ll.AccessFSReadDir |
		ll.AccessFSExecute | ll.AccessFSWriteFile | ll.AccessFSRemoveFile |
		ll.AccessFSRemoveDir | ll.AccessFSMakeChar | ll.AccessFSMakeDir |
		ll.AccessFSMakeReg | ll.AccessFSMakeSock | ll.AccessFSMakeFifo |
		ll.AccessFSMakeBlock | ll.AccessFSMakeSym |
		ll.AccessFSTruncate

	rs, err := ll.NewRuleset(handled)
	if err != nil {
		return err
	}

	// Helper to add a path rule with given allowed access
	add := func(p string, acc ll.AccessFS) error {
		if p == "" {
			return nil
		}
		return rs.AddRule(ll.PathBeneath{Path: p, AllowedAccess: acc})
	}

	// Default allowances similar to a typical baseline
	// Allow read-only access to system dirs and devices
	defaultsRO := []string{"/etc", "/proc", "/sys", "/dev"}
	defaultsROX := []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"}
	defaultsRWX := []string{"/tmp"}

	// Merge defaults with user-provided (Go 1.22+)
	ro := slices.Concat(defaultsRO, cfg.RO)
	rox := slices.Concat(defaultsROX, cfg.ROX)
	rw := slices.Concat([]string(nil), cfg.RW)
	rwx := slices.Concat(defaultsRWX, cfg.RWX)

	roAcc := ll.AccessFSReadFile | ll.AccessFSReadDir
	roxAcc := roAcc | ll.AccessFSExecute
	rwAcc := roAcc | ll.AccessFSWriteFile | ll.AccessFSRemoveFile | ll.AccessFSRemoveDir |
		ll.AccessFSMakeChar | ll.AccessFSMakeDir | ll.AccessFSMakeReg | ll.AccessFSMakeSock |
		ll.AccessFSMakeFifo | ll.AccessFSMakeBlock | ll.AccessFSMakeSym | ll.AccessFSTruncate
	rwxAcc := rwAcc | ll.AccessFSExecute

	// Add rules
	for _, p := range ro {
		if err := add(p, roAcc); err != nil {
			return err
		}
	}
	for _, p := range rox {
		if err := add(p, roxAcc); err != nil {
			return err
		}
	}
	for _, p := range rw {
		if err := add(p, rwAcc); err != nil {
			return err
		}
	}
	for _, p := range rwx {
		if err := add(p, rwxAcc); err != nil {
			return err
		}
	}

	// Finally restrict this process
	return rs.RestrictSelf()
}

// buildEnv constructs the child environment from allowed keys.
func buildEnv(allowed []string) []string {
	out := make([]string, 0, len(allowed)+1)
	// Ensure a minimal PATH if not provided
	hasPATH := false
	for _, e := range allowed {
		if e == "" {
			continue
		}
		if strings.Contains(e, "=") {
			// literal env entry
			if strings.HasPrefix(e, "PATH=") {
				hasPATH = true
			}
			out = append(out, e)
			continue
		}
		val, ok := os.LookupEnv(e)
		if !ok {
			val = ""
		}
		if e == "PATH" {
			hasPATH = true
		}
		out = append(out, e+"="+val)
	}
	if !hasPATH {
		out = append(out, "PATH=/usr/bin:/bin")
	}
	return out
}

// syscallExec performs an execve with given program, args (including argv0), and env.
func syscallExec(prog string, args []string, env []string) error {
	// Ensure argv0 is the program name
	if len(args) == 0 || args[0] != prog {
		args = append([]string{prog}, args[1:]...)
	}
	return syscallExecRaw(prog, args, env)
}
