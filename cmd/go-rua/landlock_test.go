package main

import (
	"context"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

func TestLandlockGrantPermissions(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, category := range []string{"RO", "ROX", "RW", "RWX"} {
		for _, path := range []string{root, file} {
			t.Run(category+"/"+filepath.Base(path), func(t *testing.T) {
				var cfg sandboxExecConfig
				switch category {
				case "RO":
					cfg.RO = []string{path}
				case "ROX":
					cfg.ROX = []string{path}
				case "RW":
					cfg.RW = []string{path}
				case "RWX":
					cfg.RWX = []string{path}
				}
				grants, err := landlockGrants(cfg)
				if err != nil {
					t.Fatal(err)
				}
				for _, grant := range grants {
					if grant.path != path {
						continue
					}
					x := strings.Contains(category, "X")
					w := strings.Contains(category, "W")
					for _, permission := range []struct {
						bit  uint64
						want bool
					}{
						{unix.LANDLOCK_ACCESS_FS_READ_FILE, true},
						{unix.LANDLOCK_ACCESS_FS_EXECUTE, x},
						{unix.LANDLOCK_ACCESS_FS_WRITE_FILE, w},
						{unix.LANDLOCK_ACCESS_FS_TRUNCATE, w},
						{unix.LANDLOCK_ACCESS_FS_READ_DIR, path == root},
						{unix.LANDLOCK_ACCESS_FS_MAKE_REG, path == root && w},
						{unix.LANDLOCK_ACCESS_FS_REMOVE_FILE, path == root && w},
						{unix.LANDLOCK_ACCESS_FS_REFER, path == root && w},
					} {
						if got := uint64(grant.rights)&permission.bit != 0; got != permission.want {
							t.Fatalf("rights %s: bit %#x = %v, want %v", grant.rights, permission.bit, got, permission.want)
						}
					}
					return
				}
				t.Fatal("configured path missing from grants")
			})
		}
	}
	_, err := landlockGrants(sandboxExecConfig{RW: []string{filepath.Join(root, "missing")}})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing configured path: %v", err)
	}
}

func TestLandlockFailureDispatch(t *testing.T) {
	for _, bestEffort := range []bool{false, true} {
		t.Run(fmt.Sprint(bestEffort), func(t *testing.T) {
			oldApply, oldExec, oldExit, oldPrivs := applyLandlockFn, syscallExecFn, osExitFn, prSetNoNewPrivsFn
			oldArgs, oldStderr := os.Args, os.Stderr
			t.Cleanup(func() {
				applyLandlockFn, syscallExecFn, osExitFn, prSetNoNewPrivsFn = oldApply, oldExec, oldExit, oldPrivs
				os.Args, os.Stderr = oldArgs, oldStderr
			})
			read, write, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer read.Close()
			defer write.Close()
			os.Stderr = write
			applyLandlockFn = func(sandboxExecConfig) error { return errors.New("enforcement unavailable") }
			prSetNoNewPrivsFn = func() error { return nil }
			called := false
			syscallExecFn = func(string, []string, []string) error { called = true; return nil }
			osExitFn = func(code int) { panic(code) }
			os.Args = []string{"go-rua", "sandbox-exec", "/bin/true"}
			t.Setenv("RUA_SANDBOX_CFG", fmt.Sprintf(`{"BestEffort":%t}`, bestEffort))
			t.Setenv("RUA_SECCOMP_ONLY", "")
			var exit any
			func() {
				defer func() { exit = recover() }()
				sandboxExec()
			}()
			write.Close()
			message, err := io.ReadAll(read)
			if err != nil {
				t.Fatal(err)
			}
			if bestEffort {
				if exit != nil || !called || !strings.Contains(string(message), "warning: failed to apply Landlock (best-effort)") {
					t.Fatalf("BestEffort: exit=%v exec=%v stderr=%s", exit, called, message)
				}
			} else if exit != 100 || called || !strings.Contains(string(message), "enforcement unavailable") {
				t.Fatalf("strict: exit=%v exec=%v stderr=%s", exit, called, message)
			}
		})
	}
}

func requireLandlockIntegration(t *testing.T) {
	t.Helper()
	abi, err := llsys.LandlockGetABIVersion()
	if err != nil || abi < 3 {
		if os.Getenv("RUA_REQUIRE_LANDLOCK_TESTS") == "1" {
			t.Fatalf("Landlock ABI >= 3 required, got %d: %v", abi, err)
		}
		t.Skipf("Landlock ABI >= 3 required, got %d: %v", abi, err)
	}
}

func landlockFixture(t *testing.T) (string, sandboxExecConfig) {
	t.Helper()
	base := os.Getenv("RUA_LANDLOCK_TEST_ROOT")
	if base == "" {
		base = filepath.Join("..", "..", ".gocache-tests")
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	base, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	base, err = filepath.Abs(base)
	if err != nil {
		t.Fatal(err)
	}
	defaults, err := landlockGrants(sandboxExecConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range defaults {
		path, err := filepath.EvalSymlinks(grant.path)
		if err != nil {
			t.Fatal(err)
		}
		if rel, err := filepath.Rel(path, base); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			message := fmt.Sprintf("fixture root %s is already allowed by default path %s; set RUA_LANDLOCK_TEST_ROOT outside default grants", base, path)
			if os.Getenv("RUA_REQUIRE_LANDLOCK_TESTS") == "1" {
				t.Fatal(message)
			}
			t.Skip(message)
		}
	}
	root, err := os.MkdirTemp(base, "landlock-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	program, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"ro", "rox", "rw", "rwx", "other-rw", "denied"} {
		path := filepath.Join(root, dir)
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "file"), []byte("data"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "program"), program, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"rofile", "rwfile", "move", "link", "escape", "gain", "remove"} {
		path := filepath.Join(root, name)
		if name != "rofile" && name != "rwfile" {
			path = filepath.Join(root, "rw", name)
		}
		if err := os.WriteFile(path, []byte("data"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	probe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cfg := sandboxExecConfig{
		RO:              []string{filepath.Join(root, "ro"), filepath.Join(root, "rofile")},
		ROX:             []string{filepath.Join(root, "rox"), probe},
		RW:              []string{filepath.Join(root, "rw"), filepath.Join(root, "other-rw"), filepath.Join(root, "rwfile")},
		RWX:             []string{filepath.Join(root, "rwx")},
		UnrestrictedNet: true,
	}
	return root, cfg
}

func TestLandlockIntegrationEnforcement(t *testing.T) {
	requireLandlockIntegration(t)
	for _, backend := range []string{"library", "cli"} {
		t.Run(backend, func(t *testing.T) {
			binary := os.Getenv("RUA_LANDLOCK_TEST_BINARY")
			if backend == "cli" && binary == "" {
				if os.Getenv("RUA_REQUIRE_LANDLOCK_TESTS") == "1" {
					t.Fatal("RUA_LANDLOCK_TEST_BINARY must name the rebuilt CLI")
				}
				t.Skip("built CLI exercised by make integration-landlock")
			}
			root, cfg := landlockFixture(t)
			probe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			for _, action := range []string{
				"read-ro", "read-rofile", "read-rox", "read-denied",
				"write-ro", "write-rox", "truncate-ro", "exec-ro",
				"write-rw", "truncate-rw", "create-rw", "remove-rw", "mkdir-rw", "exec-rw",
				"exec-rox", "exec-rwx", "write-rwx", "write-rwfile", "device",
				"move", "link", "escape", "gain", "threads", "inheritance",
			} {
				t.Run(action, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					mode := "restrict"
					if backend == "cli" {
						mode = "operations"
					}
					cfg.Env = []string{"RUA_LANDLOCK_PROBE=" + mode, "RUA_LANDLOCK_FIXTURE=" + root, "RUA_LANDLOCK_ACTION=" + action}
					payload, err := json.Marshal(cfg)
					if err != nil {
						t.Fatal(err)
					}
					var cmd *exec.Cmd
					if backend == "cli" {
						cmd = exec.CommandContext(ctx, binary, "sandbox-exec", probe, "-test.run=^TestLandlockProbe$", "-test.v")
						cmd.Env = []string{"RUA_SANDBOX_CFG=" + string(payload)}
					} else {
						cmd = exec.CommandContext(ctx, probe, "-test.run=^TestLandlockProbe$", "-test.v")
						cmd.Env = append(cfg.Env, "RUA_SANDBOX_CFG="+string(payload))
					}
					output, err := cmd.CombinedOutput()
					if err != nil || !strings.Contains(string(output), "LANDLOCK_PROBE_PASS") {
						t.Fatalf("real enforcement probe failed: %v\n%s", err, output)
					}
				})
			}
		})
	}
}

// No restriction is ever installed in the parent test process. The parent
// owns fixtures and cleanup; the helper opens tested files after enforcement.
func TestLandlockProbe(t *testing.T) {
	mode := os.Getenv("RUA_LANDLOCK_PROBE")
	if mode == "" {
		t.Skip("subprocess helper only")
	}
	root, action := os.Getenv("RUA_LANDLOCK_FIXTURE"), os.Getenv("RUA_LANDLOCK_ACTION")
	var worker chan error
	if mode == "restrict" {
		var cfg sandboxExecConfig
		if err := json.Unmarshal([]byte(os.Getenv("RUA_SANDBOX_CFG")), &cfg); err != nil {
			t.Fatal(err)
		}
		if _, err := os.ReadFile(filepath.Join(root, "denied", "file")); err != nil {
			t.Fatalf("fixture is inaccessible before Landlock: %v", err)
		}
		ready, start := make(chan struct{}), make(chan struct{})
		worker = make(chan error, 1)
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			close(ready)
			<-start
			_, err := os.ReadFile(filepath.Join(root, "denied", "file"))
			worker <- err
		}()
		<-ready
		if err := applyLandlock(cfg); err != nil {
			t.Fatal(err)
		}
		close(start)
	}
	err, denied := landlockProbeAction(root, action)
	if denied {
		if !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM) && !errors.Is(err, unix.EXDEV) {
			t.Fatalf("%s should be denied, got %v", action, err)
		}
	} else if err != nil {
		t.Fatalf("%s should succeed, got %v", action, err)
	}
	if worker != nil {
		if err := <-worker; !errors.Is(err, unix.EACCES) {
			t.Fatalf("pre-existing OS thread was not restricted: %v", err)
		}
	}
	fmt.Println("LANDLOCK_PROBE_PASS")
}

func landlockProbeAction(root, action string) (error, bool) {
	path := func(dir, name string) string { return filepath.Join(root, dir, name) }
	switch action {
	case "read-rofile":
		_, err := os.ReadFile(filepath.Join(root, "rofile"))
		return err, false
	case "write-rwfile":
		return os.WriteFile(filepath.Join(root, "rwfile"), []byte("changed"), 0600), false
	case "read-ro", "read-rox", "read-denied":
		dir := strings.TrimPrefix(action, "read-")
		_, err := os.ReadFile(path(dir, "file"))
		return err, dir == "denied"
	case "write-ro", "write-rox", "write-rw", "write-rwx":
		dir := strings.TrimPrefix(action, "write-")
		return os.WriteFile(path(dir, "file"), []byte("changed"), 0600), dir == "ro" || dir == "rox"
	case "truncate-ro", "truncate-rw":
		dir := strings.TrimPrefix(action, "truncate-")
		return os.Truncate(path(dir, "file"), 0), dir == "ro"
	case "exec-ro", "exec-rox", "exec-rw", "exec-rwx":
		dir := strings.TrimPrefix(action, "exec-")
		cmd := exec.Command(path(dir, "program"))
		// /bin/true can be a multicall executable that dispatches on argv[0].
		cmd.Args[0] = "true"
		output, err := cmd.CombinedOutput()
		if err != nil {
			err = fmt.Errorf("execute probe: %w (%s)", err, output)
		}
		return err, dir == "ro" || dir == "rw"
	case "create-rw":
		return os.WriteFile(path("rw", "created"), []byte("data"), 0600), false
	case "remove-rw":
		return os.Remove(path("rw", "remove")), false
	case "mkdir-rw":
		return os.Mkdir(path("rw", "newdir"), 0700), false
	case "move":
		return os.Rename(path("rw", "move"), path("other-rw", "moved")), false
	case "link":
		return os.Link(path("rw", "link"), path("other-rw", "linked")), false
	case "escape":
		return os.Rename(path("rw", "escape"), path("denied", "escaped")), true
	case "gain":
		return os.Rename(path("rw", "gain"), path("rwx", "gained")), true
	case "device":
		return os.WriteFile("/dev/null", []byte("data"), 0600), false
	case "threads":
		results := make(chan error, 4)
		for range 4 {
			go func() {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				_, err := os.ReadFile(path("denied", "file"))
				results <- err
			}()
		}
		for range 4 {
			if err := <-results; !errors.Is(err, unix.EACCES) {
				return fmt.Errorf("Go thread escaped policy: %v", err), false
			}
		}
		return nil, false
	case "inheritance":
		probe, err := os.Executable()
		if err != nil {
			return err, false
		}
		cmd := exec.Command(probe, "-test.run=^TestLandlockProbe$", "-test.v")
		cmd.Env = []string{"RUA_LANDLOCK_PROBE=operations", "RUA_LANDLOCK_FIXTURE=" + root, "RUA_LANDLOCK_ACTION=read-denied"}
		output, err := cmd.CombinedOutput()
		if err == nil && !strings.Contains(string(output), "LANDLOCK_PROBE_PASS") {
			err = fmt.Errorf("child did not confirm inherited denial: %s", output)
		}
		return err, false
	default:
		return fmt.Errorf("unknown probe action %q", action), false
	}
}

func TestLandlockIntegrationProvenance(t *testing.T) {
	binary := os.Getenv("RUA_LANDLOCK_TEST_BINARY")
	if binary == "" {
		if os.Getenv("RUA_REQUIRE_LANDLOCK_TESTS") == "1" {
			t.Fatal("RUA_LANDLOCK_TEST_BINARY must name the rebuilt CLI")
		}
		t.Skip("built CLI exercised by make integration-landlock")
	}
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if info.GoVersion != runtime.Version() {
		t.Fatalf("binary compiler %q must match verified go.mod test compiler %q", info.GoVersion, runtime.Version())
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/landlock-lsm/go-landlock" {
			if dep.Version != "v0.0.0-20250303204525-1544bccde3a3" || dep.Sum != "h1:zcMi8R8vP0WrrXlFMNUBpDy/ydo3sTnCcUPowq1XmSc=" || dep.Replace != nil {
				t.Fatalf("built binary must contain pinned upstream Landlock, got %+v", dep)
			}
			return
		}
	}
	t.Fatal("built binary has no Landlock dependency")
}
