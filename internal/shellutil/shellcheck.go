package shellutil

import (
	"os"
	"path/filepath"
	"strings"

	"go-rua/internal/paths"
	"go-rua/internal/sandbox"
)

// Shellcheck runs shellcheck on target PKGBUILD using a wrapper that defines PKGBUILD variables.
func Shellcheck(target string, p paths.Paths) error {
	if _, err := os.Stat(target); err != nil {
		return err
	}
	content, err := os.ReadFile(target)
	if err != nil {
		return err
	}
	// Create a temporary file with the wrapper + inlined PKGBUILD content
	tmpDir, err := os.MkdirTemp("", "go-rua-shellcheck-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	wrapped := strings.ReplaceAll(shellcheckWrapper, "%PKGBUILD%", string(content))
	tmpFile := filepath.Join(tmpDir, "PKGBUILD.wrapper.sh")
	if err := os.WriteFile(tmpFile, []byte(wrapped), 0o600); err != nil {
		return err
	}

	// Sandbox: readonly bind the wrapper location; executables from system
	ro := []string{"/etc", tmpDir}
	rox := []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"}
	cfg := sandbox.Config{RO: ro, ROX: rox}

	return sandbox.Run(cfg, []string{"shellcheck", "--norc", tmpFile})
}
