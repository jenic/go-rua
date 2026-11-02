package shellutil

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go-rua/internal/paths"
	"go-rua/internal/sandbox"
)

func TestNamcapPacmanDatabaseIsReadOnly(t *testing.T) {
	for _, kind := range []string{"directory", "recipe", "archive"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			name := "PKGBUILD"
			if kind == "archive" {
				name = "fixture-1-1-any.pkg.tar.zst"
			}
			target := filepath.Join(dir, name)
			if err := os.WriteFile(target, []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			capture := filepath.Join(t.TempDir(), "config.json")
			sandbox.SetExecCommandForTests(func(_ string, args ...string) *exec.Cmd {
				if !slices.Equal(args, []string{"sandbox-exec", "namcap", target}) {
					t.Fatalf("unexpected command: %v", args)
				}
				return exec.Command("/bin/sh", "-c", `printf '%s' "$RUA_SANDBOX_CFG" > "$1"`, "sh", capture)
			})
			t.Cleanup(func() { sandbox.SetExecCommandForTests(exec.Command) })
			input := target
			if kind == "directory" {
				input = dir
			}
			if err := Namcap(input, paths.Paths{}); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(capture)
			if err != nil {
				t.Fatal(err)
			}
			var cfg sandbox.Config
			if err := json.Unmarshal(data, &cfg); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(cfg.RO, "/var/lib/pacman") || !slices.Contains(cfg.RO, dir) {
				t.Fatalf("namcap must read the pacman database and target directory: %+v", cfg)
			}
			if len(cfg.RW) != 0 || len(cfg.RWX) != 0 || slices.Contains(cfg.ROX, "/var/lib/pacman") || cfg.BestEffort || cfg.UnrestrictedFS {
				t.Fatalf("namcap must retain strict read-only access: %+v", cfg)
			}
		})
	}
}

func TestNamcapDiagnosticsPreservesOutputAndExitStatus(t *testing.T) {
	for _, status := range []int{0, 1, 2} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "PKGBUILD")
			if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			sandbox.SetExecCommandForTests(func(_ string, _ ...string) *exec.Cmd {
				return exec.Command("/bin/sh", "-c", `printf 'fixture W: diagnostic\n'; printf 'stderr diagnostic\n' >&2; exit "$1"`, "sh", strconv.Itoa(status))
			})
			t.Cleanup(func() { sandbox.SetExecCommandForTests(exec.Command) })
			out, err := NamcapDiagnostics(file)
			if !strings.Contains(out, "fixture W: diagnostic") || !strings.Contains(out, "stderr diagnostic") {
				t.Fatalf("missing diagnostics: %q", out)
			}
			if status == 0 {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != status {
				t.Fatalf("exit status changed: %v", err)
			}
		})
	}
}
