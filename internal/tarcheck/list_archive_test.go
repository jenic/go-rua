package tarcheck

import (
	"os/exec"
	"strings"
	"testing"

	"go-rua/internal/sandbox"
)

func TestListArchiveParsesEntriesAndInstall(t *testing.T) {
	// Stub sandbox to emit fake tar outputs
	sandbox.SetExecCommandForTests(func(name string, arg ...string) *exec.Cmd {
		// arg[0] == "sandbox-exec"; the rest include our argv
		joined := strings.Join(arg, " ")
		if strings.Contains(joined, "-tvf") {
			// mode, user, size-ish, date fields, then path (match regex in code)
			out := "-rwxr-xr-x user 0 grp time usr/bin/app\n-rwsr-xr-x user 0 grp time usr/bin/suid\n-rw-r--r-- user 0 grp time .INSTALL\n"
			script := "cat <<'EOF'\n" + out + "EOF\n"
			return exec.Command("bash", "-lc", script)
		}
		if strings.Contains(joined, "-xOf") {
			return exec.Command("bash", "-lc", "printf 'install script'")
		}
		return exec.Command("bash", "-lc", "true")
	})
	defer sandbox.SetExecCommandForTests(exec.Command)

	entries, install, err := listArchive("/tmp/dummy.pkg.tar.zst")
	if err != nil {
		t.Fatalf("listArchive error: %v", err)
	}
	if install != "install script" {
		t.Fatalf("expected install script, got %q", install)
	}
	if len(entries) == 0 {
		t.Fatalf("expected entries parsed")
	}
}
