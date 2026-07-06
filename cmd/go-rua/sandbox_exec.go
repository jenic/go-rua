package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
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
	executableFn           = os.Executable
	osExitFn               = os.Exit
)

type sandboxExecConfig struct {
	RO               []string
	ROX              []string
	RW               []string
	RWX              []string
	Env              []string
	WorkDir          string
	BestEffort       bool
	UnrestrictedFS   bool
	UnrestrictedNet  bool
	UseBubblewrap    bool
	AllowWeakOffline bool
	SeccompDenylist  bool
}

type bwrapBind struct {
	flag string
	path string
}

// sandboxExec is invoked as a hidden subcommand: go-rua sandbox-exec <cmd> [args...]
// It applies a Landlock ruleset (based on RUA_SANDBOX_CFG) and then execs the target.
func sandboxExec() {
	// Parse config from env
	cfgJSON := os.Getenv("RUA_SANDBOX_CFG")
	if cfgJSON == "" {
		fmt.Fprintln(os.Stderr, "sandbox-exec: missing RUA_SANDBOX_CFG")
		osExitFn(97)
	}
	var cfg sandboxExecConfig
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox-exec: invalid config:", err)
		osExitFn(98)
	}

	args := os.Args[2:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "sandbox-exec: no command provided")
		osExitFn(99)
	}
	selfPath := selfExecutablePath()

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

	// Build sanitized environment before resolving helper binaries. sandbox-exec
	// itself is launched with only RUA_SANDBOX_CFG, so its process environment
	// may not contain PATH even when the configured child environment should.
	childEnv := buildEnv(cfg.Env)
	pathVal := pathFromEnv(childEnv)
	if pathVal == "" {
		pathVal = "/usr/bin:/bin"
	}
	_ = os.Setenv("PATH", pathVal)

	// Decide execution strategy: bubblewrap for net isolation if requested/available, else Landlock-only.
	useBwrap := false
	bwrapPath := ""
	if cfg.UseBubblewrap {
		if p, err := lookPathFn("bwrap"); err == nil {
			useBwrap = true
			bwrapPath = p
		} else if !cfg.UnrestrictedNet && !cfg.AllowWeakOffline {
			fmt.Fprintln(os.Stderr, "sandbox-exec: offline build requires bubblewrap network isolation; install bwrap or set RUA_ALLOW_WEAK_OFFLINE=1 to accept Landlock-only isolation")
			osExitFn(103)
		} else if !cfg.UnrestrictedNet {
			fmt.Fprintln(os.Stderr, "warning: bubblewrap unavailable; offline build is using Landlock-only isolation without a private network namespace")
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

	// Resolve the command path if needed
	prog := args[0]
	if !strings.Contains(prog, "/") {
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
		// Inside bwrap, re-enter this binary in seccomp-only mode so that bwrap can perform needed syscalls first.
		bwargs := buildBubblewrapArgs(cfg, selfPath, args)
		// Signal to inner invocation to only apply seccomp
		childEnv = append(childEnv, "RUA_SANDBOX_CFG="+cfgJSON, "RUA_SECCOMP_ONLY=1")
		if err := syscallExecFn(bwrapPath, bwargs, childEnv); err != nil {
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

func buildBubblewrapArgs(cfg sandboxExecConfig, self string, targetArgs []string) []string {
	bwargs := []string{"bwrap", "--die-with-parent", "--tmpfs", "/"}
	if !cfg.UnrestrictedNet {
		bwargs = append(bwargs, "--unshare-net")
	}
	bwargs = append(bwargs, "--proc", "/proc", "--dev", "/dev", "--dir", "/tmp", "--dir", "/var", "--dir", "/var/tmp")

	var binds []bwrapBind
	addBinds := func(flag string, paths []string) {
		for _, p := range paths {
			p = filepath.Clean(p)
			if p == "." || p == "/" || p == "" || !filepath.IsAbs(p) {
				continue
			}
			binds = append(binds, bwrapBind{flag: flag, path: p})
		}
	}
	addBinds("--ro-bind", slices.Concat([]string{"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", self}, cfg.RO, cfg.ROX))
	addBinds("--bind", slices.Concat(cfg.RW, cfg.RWX))

	for _, d := range parentDirsForBinds(binds) {
		bwargs = append(bwargs, "--dir", d)
	}
	selected := map[string]bwrapBind{}
	order := []string{}
	for _, b := range binds {
		if cur, ok := selected[b.path]; ok {
			if cur.flag == "--ro-bind" && b.flag == "--bind" {
				selected[b.path] = b
			}
			continue
		}
		selected[b.path] = b
		order = append(order, b.path)
	}
	for _, path := range order {
		b := selected[path]
		bwargs = append(bwargs, b.flag, b.path, b.path)
	}
	bwargs = append(bwargs, "--", self, "sandbox-exec")
	return append(bwargs, targetArgs...)
}

func selfExecutablePath() string {
	if exe, err := executableFn(); err == nil && exe != "" {
		return exe
	}
	selfPath := os.Args[0]
	if !strings.HasPrefix(selfPath, "/") {
		if ap, err := absPathFn(selfPath); err == nil {
			selfPath = ap
		}
	}
	return selfPath
}

func parentDirsForBinds(binds []bwrapBind) []string {
	seen := map[string]struct{}{}
	for _, b := range binds {
		for d := filepath.Dir(b.path); d != "." && d != "/" && d != ""; d = filepath.Dir(d) {
			seen[d] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		di := strings.Count(out[i], string(os.PathSeparator))
		dj := strings.Count(out[j], string(os.PathSeparator))
		if di != dj {
			return di < dj
		}
		return out[i] < out[j]
	})
	return out
}

// applyLandlock constructs and installs a Landlock ruleset based on cfg.
func applyLandlock(cfg sandboxExecConfig) error {
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

func pathFromEnv(env []string) string {
	for _, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			return strings.TrimPrefix(e, "PATH=")
		}
	}
	return ""
}

// syscallExec performs an execve with given program, args (including argv0), and env.
func syscallExec(prog string, args []string, env []string) error {
	// Ensure argv0 is the program name
	if len(args) == 0 || args[0] != prog {
		args = append([]string{prog}, args[1:]...)
	}
	return syscallExecRaw(prog, args, env)
}
