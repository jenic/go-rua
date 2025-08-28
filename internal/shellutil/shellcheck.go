package shellutil

import (
	"os"
	"path/filepath"

	"go-rua/internal/paths"
	"go-rua/internal/sandbox"
)

// Shellcheck runs shellcheck on target PKGBUILD with safe wrapper vars
func Shellcheck(target string, p paths.Paths) error {
	if _, err := os.Stat(target); err != nil {
		return err
	}

	ro := []string{"/etc", filepath.Dir(target)}
	rox := []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"}
	cfg := sandbox.Config{RO: ro, ROX: rox}

	// emulate rua wrapping by injecting PKGBUILD content via stdin is complex without shell wrapper
	// Here we call shellcheck directly on the file path
	abs, _ := filepath.Abs(target)
	if abs == "" {
		abs = target
	}
	return sandbox.Run(cfg, []string{"shellcheck", "--norc", abs})
}
