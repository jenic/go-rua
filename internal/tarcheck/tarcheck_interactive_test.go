package tarcheck

import (
	"bytes"
	"os/exec"
	"testing"

	"go-rua/internal/sandbox"
)

func TestTarCheckInteractiveMenuPaths(t *testing.T) {
	// Feed inputs to cover E, L, F, S, I, T, then O to finish
	SetInputForTests(bytes.NewBufferString("e\nl\nf\ns\ni\nt\no\n"))
	defer SetInputForTests(nil)

	// Stub tar and shell
	sandbox.SetExecCommandForTests(func(name string, arg ...string) *exec.Cmd {
		// Always respond with a listing first, then INSTALL/shell
		joined := ""
		if len(arg) > 0 {
			for _, a := range arg {
				joined += a + " "
			}
		}
		if bytes.Contains([]byte(joined), []byte("-tvf")) {
			out := "-rwxr-xr-x user 0 grp time usr/bin/app\n-rwsr-xr-x user 0 grp time usr/bin/suid\n-rw-r--r-- user 0 grp time .INSTALL\n"
			return exec.Command("bash", "-lc", "cat <<'EOF'\n"+out+"EOF")
		}
		if bytes.Contains([]byte(joined), []byte("-xOf")) {
			return exec.Command("bash", "-lc", "printf install-script")
		}
		// shell
		return exec.Command("bash", "-lc", "true")
	})
	defer sandbox.SetExecCommandForTests(exec.Command)

	if err := TarCheck("/tmp/dummy.pkg.tar.zst"); err != nil {
		t.Fatalf("TarCheck error: %v", err)
	}
}
