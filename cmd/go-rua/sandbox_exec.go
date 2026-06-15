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

// seams for testing
var (
	syscallExecFn          = syscallExec
	applySeccompDenylistFn = applySeccompDenylist
	applyLandlockFn        = applyLandlock
	prSetNoNewPrivsFn      = prSetNoNewPrivs
	lookPathFn             = exec.LookPath
	absPathFn              = filepath.Abs
	osExitFn               = os.Exit
)

// sandboxExec is invoked as a hidden subcommand: go-rua sandbox-exec <cmd> [args...]
// It applies a Landlock ruleset (based on RUA_SANDBOX_CFG) and then execs the target.
func sandboxExec() {
	// Parse config from env
	cfgJSON := os.Getenv("RUA_SANDBOX_CFG")
	if cfgJSON == "" {
		fmt.Fprintln(os.Stderr, "sandbox-exec: missing RUA_SANDBOX_CFG")
		osExitFn(97)
	}
	var cfg struct {
		RO              []string
		ROX             []string
		RW              []string
		RWX             []string
		Env             []string
		WorkDir         string
		BestEffort      bool
		UnrestrictedFS  bool
		UnrestrictedNet bool
		UseBubblewrap   bool
		SeccompDenylist bool
	}
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-exec: invalid config:", err)
		osExitFn(98)
	}

	args := os.Args[2:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "sandbox-exec: no command provided")
		osExitFn(99)
	}

	// If this invocation is seccomp-only (launched inside bwrap), apply seccomp and exec target.
	if os.Getenv("RUA_SECCOMP_ONLY") == "1" {
		if cfg.SeccompDenylist {
			if err := applySeccompDenylistFn(); err != nil {
				if cfg.BestEffort {
					fmt.Fprintln(os.Stderr, "warning: failed to apply seccomp (best-effort):", err)
				} else {
					fmt.Fprintln(os.Stderr, "sandbox-exec: failed to apply seccomp:", err)
					osExitFn(102)
				}
			}
		}
		childEnv := buildEnv(cfg.Env)
		prog := args[0]
		if !strings.Contains(prog, "/") {
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
			if p, err := lookPathFn(prog); err == nil {
				prog = p
			}
		} else if !strings.HasPrefix(prog, "/") {
			if ap, err := absPathFn(prog); err == nil {
				prog = ap
			}
		}
		if err := syscallExecFn(prog, append([]string{prog}, args[1:]...), childEnv); err != nil {
			fmt.Fprintln(os.Stderr, "exec failed:", err)
			osExitFn(101)
		}
		return
	}

	// If a working directory is specified, change to it before applying isolation.
	if cfg.WorkDir != "" {
		if err := os.Chdir(cfg.WorkDir); err != nil {
			fmt.Fprintln(os.Stderr, "sandbox-exec: chdir failed:", err)
			osExitFn(96)
		}
	}

	// Decide execution strategy: bubblewrap for net isolation if requested/available, else Landlock-only.
	useBwrap := false
	if cfg.UseBubblewrap {
		if _, err := lookPathFn("bwrap"); err == nil {
			useBwrap = true
		}
	}
	// Apply Landlock only when not using bubblewrap (to avoid interfering with bwrap mounts)
	if !useBwrap && !cfg.UnrestrictedFS {
		if err := applyLandlockFn(cfg); err != nil {
			if cfg.BestEffort {
				fmt.Fprintln(os.Stderr, "warning: failed to apply Landlock (best-effort):", err)
			} else {
				fmt.Fprintln(os.Stderr, "sandbox-exec: failed to apply Landlock:", err)
				osExitFn(100)
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

	// Best-effort: prevent gaining privileges in the child
	// no_new_privs prevents gaining privileges; ignore error on older kernels
	_ = prSetNoNewPrivsFn()

	// Optionally wrap with bubblewrap for network isolation
	if useBwrap {
		bwargs := []string{"bwrap", "--die-with-parent", "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev"}
		if !cfg.UnrestrictedNet {
			bwargs = append([]string{"bwrap", "--die-with-parent", "--unshare-net", "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev"}, bwargs[4:]...)
		}
		// map binds
		for _, p := range cfg.RO {
			bwargs = append(bwargs, "--ro-bind", p, p)
		}
		for _, p := range cfg.ROX {
			bwargs = append(bwargs, "--ro-bind", p, p)
		}
		for _, p := range cfg.RW {
			bwargs = append(bwargs, "--bind", p, p)
		}
		for _, p := range cfg.RWX {
			bwargs = append(bwargs, "--bind", p, p)
		}
		// Inside bwrap, re-enter this binary in seccomp-only mode so that bwrap can perform needed syscalls first.
		self := os.Args[0]
		if !strings.HasPrefix(self, "/") {
			if ap, err := filepath.Abs(self); err == nil {
				self = ap
			}
		}
		bwargs = append(bwargs, "--", self, "sandbox-exec")
		bwargs = append(bwargs, args...)
		// Signal to inner invocation to only apply seccomp
		childEnv = append(childEnv, "RUA_SANDBOX_CFG="+cfgJSON, "RUA_SECCOMP_ONLY=1")
		if err := syscallExecFn(bwargs[0], bwargs, childEnv); err != nil {
			fmt.Fprintln(os.Stderr, "exec failed:", err)
			osExitFn(101)
		}
		return
	}

	// Apply seccomp denylist if requested (no bwrap path)
	if cfg.SeccompDenylist {
		if err := applySeccompDenylistFn(); err != nil {
			if cfg.BestEffort {
				fmt.Fprintln(os.Stderr, "warning: failed to apply seccomp (best-effort):", err)
			} else {
				fmt.Fprintln(os.Stderr, "sandbox-exec: failed to apply seccomp:", err)
				osExitFn(102)
			}
		}
	}
	// Replace our process image with the target (no bwrap)
	if err := syscallExecFn(prog, append([]string{prog}, args[1:]...), childEnv); err != nil {
		fmt.Fprintln(os.Stderr, "exec failed:", err)
		osExitFn(101)
	}
}

// applyLandlock constructs and installs a Landlock ruleset based on cfg.
func applyLandlock(cfg struct {
	RO, ROX, RW, RWX                            []string
	Env                                         []string
	WorkDir                                     string
	BestEffort, UnrestrictedFS, UnrestrictedNet bool
	UseBubblewrap                               bool
	SeccompDenylist                             bool
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
	defaultsRO := []string{"/etc", "/proc", "/sys"}
	// Exec allowed from standard system locations
	defaultsROX := []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"}
	// Writable temp areas commonly used by build tools
	defaultsRWX := []string{"/tmp", "/var/tmp"}
	// Device nodes that often need write access (tty, null) and pseudo terminals/shm
	defaultsRW := []string{"/dev/null", "/dev/tty", "/dev/pts", "/dev/shm"}

	// Merge defaults with user-provided (Go 1.22+)
	ro := slices.Concat(defaultsRO, cfg.RO)
	rox := slices.Concat(defaultsROX, cfg.ROX)
	rw := slices.Concat(defaultsRW, cfg.RW)
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
		if e == "PATH" {
			hasPATH = true
			// Fallback to a sane default when PATH is missing or empty in parent env
			if !ok || val == "" {
				val = "/usr/bin:/bin"
			}
		} else if !ok {
			val = ""
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
