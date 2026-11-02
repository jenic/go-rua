package install

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"go-rua/internal/sandbox"
)

func TestGuidedNamcapReadsPacmanDatabase(t *testing.T) {
	tools := t.TempDir()
	if err := os.WriteFile(filepath.Join(tools, "namcap"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools)
	for _, artifact := range []bool{false, true} {
		t.Run(map[bool]string{false: "recipe", true: "artifact"}[artifact], func(t *testing.T) {
			dir := t.TempDir()
			name := "PKGBUILD"
			if artifact {
				name = "fixture-1-1-any.pkg.tar.zst"
			}
			file := filepath.Join(dir, name)
			if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			capture := filepath.Join(t.TempDir(), "config.json")
			sandbox.SetExecCommandForTests(func(_ string, args ...string) *exec.Cmd {
				if !slices.Equal(args, []string{"sandbox-exec", "namcap", file}) {
					t.Fatalf("unexpected namcap command: %v", args)
				}
				return exec.Command("/bin/sh", "-c", `printf '%s' "$RUA_SANDBOX_CFG" > "$1"`, "sh", capture)
			})
			t.Cleanup(func() { sandbox.SetExecCommandForTests(exec.Command) })
			target := file
			if !artifact {
				target = dir
			}
			guidedLint(target, artifact)
			data, err := os.ReadFile(capture)
			if err != nil {
				t.Fatal(err)
			}
			var cfg sandbox.Config
			if err := json.Unmarshal(data, &cfg); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(cfg.RO, "/var/lib/pacman") {
				t.Fatalf("guided namcap must read pacman database: %+v", cfg)
			}
			if len(cfg.RW) != 0 || len(cfg.RWX) != 0 || cfg.BestEffort || cfg.UnrestrictedFS {
				t.Fatalf("guided namcap must retain strict read-only access: %+v", cfg)
			}
		})
	}
}
