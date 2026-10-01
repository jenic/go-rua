package shellutil

import (
	"go-rua/internal/sandbox"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestShellcheckDiagnosticsDistinguishesToolFailure(t *testing.T) {
	for _, kind := range []string{"clean", "finding", "runner failure"} {
		t.Run(kind, func(t *testing.T) {
			sandbox.SetExecCommandForTests(func(name string, args ...string) *exec.Cmd {
				if !strings.Contains(strings.Join(args, " "), "--format=json") {
					t.Fatal("structured output not requested")
				}
				switch kind {
				case "clean":
					return exec.Command("sh", "-c", "printf '[]'")
				case "finding":
					return exec.Command("sh", "-c", `printf '[{"line":9,"column":2,"level":"warning","code":2034,"message":"unused"}]'; exit 1`)
				default:
					return exec.Command("sh", "-c", "printf 'sandbox initialization failed'; exit 1")
				}
			})
			defer sandbox.SetExecCommandForTests(exec.Command)
			p := filepath.Join(t.TempDir(), "PKGBUILD")
			os.WriteFile(p, []byte("pkgname=app\n"), 0600)
			findings, err := ShellcheckDiagnostics(p)
			if (err != nil) != (kind == "runner failure") {
				t.Fatal(err)
			}
			if kind == "finding" && (len(findings) != 1 || findings[0].Line != 2) {
				t.Fatal(findings)
			}
		})
	}
}
