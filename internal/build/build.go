package build

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"go-rua/internal/paths"
	"go-rua/internal/sandbox"
)

// BuildDirectory builds a PKGBUILD directory using a Landlock sandbox
func BuildDirectory(dir string, p paths.Paths, offline, force bool) error {
	if _, err := os.Stat(filepath.Join(dir, "PKGBUILD")); err != nil {
		return fmt.Errorf("PKGBUILD not found in %s: %w", dir, err)
	}

	// Prepare env for makepkg outputs to land in dir
	envs := []string{
		"HOME", // allow HOME value
		"PATH", // needed by toolchains and makepkg
		"FAKEROOTDONTTRYCHOWN=true",
		fmt.Sprintf("PKGDEST=%s", dir),
		fmt.Sprintf("SRCDEST=%s", dir),
		fmt.Sprintf("SRCPKGDEST=%s", dir),
		fmt.Sprintf("LOGDEST=%s", dir),
		fmt.Sprintf("BUILDDIR=%s", dir),
	}

	// allow gnupg reads for signature verification if present
	gnupg := os.Getenv("GNUPGHOME")
	ro := []string{"/etc"}
	rox := []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"}
	rwx := []string{dir}
	if gnupg != "" {
		ro = append(ro, gnupg)
	} else if home, _ := os.UserHomeDir(); home != "" {
		ro = append(ro, filepath.Join(home, ".gnupg"))
	}

	args := []string{"makepkg"}
	if force {
		args = append(args, "--force")
	}
	// makepkg will install deps if allowed; we do not change sudo behavior here
	// Network: if offline requested, keep default (deny); otherwise allow unrestricted network

	// FAKEROOT workaround similar to rua
	args = append(args, "-f")

	cfg := sandbox.Config{
		RO:              ro,
		ROX:             rox,
		RWX:             rwx,
		Env:             envs,
		UnrestrictedNet: !offline,
	}
	return sandbox.Run(cfg, args)
}

// RunShell opens a shell in dir within minimal sandbox (used for review/inspect)
func RunShell(dir string) error {
	sh := os.Getenv("SHELL")
	if sh == "" {
		sh = "/bin/bash"
	}
	cfg := sandbox.Config{
		RO:  []string{"/etc"},
		ROX: []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"},
		RWX: []string{dir},
		Env: []string{"HOME", "PATH"},
	}
	return sandbox.Run(cfg, []string{sh})
}

// Simple helper to copy directory contents (used for build staging)
func CopyTree(src, dst string) error {
	// Use rsync-like behavior via tar | tar to avoid external deps
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	// fallback: cp -a if available
	if _, err := exec.LookPath("cp"); err == nil {
		cmd := exec.Command("bash", "-c", fmt.Sprintf("shopt -s dotglob nullglob && cp -a '%s'/* '%s'/", escape(src), escape(dst)))
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return cmd.Run()
	}
	return fmt.Errorf("copy not implemented; please ensure 'cp' exists")
}

func escape(s string) string { return strings.ReplaceAll(s, "'", "'\\''") }
