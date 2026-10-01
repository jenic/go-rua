package shellutil

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"go-rua/internal/sandbox"
)

type Diagnostic struct {
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Level   string `json:"level"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ShellcheckDiagnostics uses the existing wrapper and requires machine-readable
// output so sandbox/launch failures cannot be mistaken for lint findings.
func ShellcheckDiagnostics(target string) ([]Diagnostic, error) {
	b, err := os.ReadFile(target)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "go-rua-lint-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "PKGBUILD.wrapper.sh")
	if err := os.WriteFile(file, []byte(strings.ReplaceAll(shellcheckWrapper, "%PKGBUILD%", string(b))), 0600); err != nil {
		return nil, err
	}
	cfg := sandbox.Config{RO: []string{"/etc", dir}, ROX: []string{"/usr", "/bin", "/lib", "/lib64"}}
	out, _, runErr := sandbox.RunCapture(cfg, []string{"shellcheck", "--norc", "--format=json", file})
	if runErr != nil {
		if exit, ok := runErr.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
			return nil, fmt.Errorf("shellcheck execution failed: %w: %s", runErr, out)
		}
	}
	var diagnostics []Diagnostic
	if err := json.Unmarshal([]byte(out), &diagnostics); err != nil {
		return nil, fmt.Errorf("invalid shellcheck diagnostic output: %w: %s", err, out)
	}
	if runErr != nil && len(diagnostics) == 0 {
		return nil, fmt.Errorf("shellcheck failed without diagnostics")
	}
	prefix, _, _ := strings.Cut(shellcheckWrapper, "%PKGBUILD%")
	for i := range diagnostics {
		diagnostics[i].Line -= strings.Count(prefix, "\n")
		if diagnostics[i].Line < 1 {
			diagnostics[i].Line = 1
		}
	}
	return diagnostics, nil
}
