package shellutil

import (
	"os"
	"path/filepath"

	"go-rua/internal/paths"
	"go-rua/internal/sandbox"
)

// Namcap runs namcap with read-only access to its input and pacman database.
func Namcap(target string, p paths.Paths) error {
	cfg, args, err := namcapCommand(target)
	if err != nil {
		return err
	}
	return sandbox.Run(cfg, args)
}

// NamcapDiagnostics captures namcap output with the same permissions as Namcap.
// Command exit errors are preserved so callers can distinguish lint findings.
func NamcapDiagnostics(target string) (string, error) {
	cfg, args, err := namcapCommand(target)
	if err != nil {
		return "", err
	}
	out, _, err := sandbox.RunCapture(cfg, args)
	return out, err
}

func namcapCommand(target string) (sandbox.Config, []string, error) {
	if fi, err := os.Stat(target); err == nil && fi.IsDir() {
		target = filepath.Join(target, "PKGBUILD")
	}
	if _, err := os.Stat(target); err != nil {
		return sandbox.Config{}, nil, err
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return sandbox.Config{}, nil, err
	}
	// Namcap initializes libalpm even for PKGBUILD checks. Grant its database
	// explicitly rather than widening the sandbox's default filesystem access.
	ro := []string{"/etc", "/var/lib/pacman", filepath.Dir(abs)}
	rox := []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"}
	cfg := sandbox.Config{RO: ro, ROX: rox}
	return cfg, []string{"namcap", abs}, nil
}
