package shellutil

import (
	"os"
	"path/filepath"

	"go-rua/internal/paths"
	"go-rua/internal/sandbox"
)

// Namcap runs namcap on a PKGBUILD (or path) in a sandbox
func Namcap(target string, p paths.Paths) error {
	if fi, err := os.Stat(target); err == nil && fi.IsDir() {
		target = filepath.Join(target, "PKGBUILD")
	}
	if _, err := os.Stat(target); err != nil {
		return err
	}

	ro := []string{"/etc", filepath.Dir(target)}
	rox := []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"}
	cfg := sandbox.Config{RO: ro, ROX: rox}
	abs, _ := filepath.Abs(target)
	if abs == "" {
		abs = target
	}
	return sandbox.Run(cfg, []string{"namcap", abs})
}
