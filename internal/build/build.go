package build

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"go-rua/internal/paths"
	"go-rua/internal/sandbox"
)

// BuildDirectory builds a PKGBUILD directory using a Landlock/bwrap sandbox.
// If seccomp is false, the seccomp denylist is not applied.
func BuildDirectory(dir string, p paths.Paths, offline, force bool, seccomp bool) error {
	if _, err := os.Stat(filepath.Join(dir, "PKGBUILD")); err != nil {
		return fmt.Errorf("PKGBUILD not found in %s: %w", dir, err)
	}
	// Warn on unsupported PKGEXT if explicitly set in env (best-effort)
	if v := os.Getenv("PKGEXT"); v != "" {
		switch v {
		case ".pkg.tar", ".pkg.tar.xz", ".pkg.tar.gz", ".pkg.tar.gzip", ".pkg.tar.zst", ".pkg.tar.zstd":
			// ok
		default:
			// Color only if available
			msg := fmt.Sprintf("Warning: PKGEXT=%s may be unsupported by tarcheck; artifacts might not be analyzed.\n", v)
			fmt.Fprint(os.Stderr, msg)
		}
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

	ro := []string{"/etc"}
	rox := []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"}
	rwx := []string{dir}

	// Prefer bubblewrap to enforce network isolation when offline, unless disabled
	useBwrap := false
	allowWeakOffline := false
	if v := os.Getenv("RUA_ALWAYS_BWRAP"); v == "1" || strings.ToLower(v) == "true" {
		useBwrap = true
	} else if offline {
		if v := os.Getenv("RUA_ALLOW_WEAK_OFFLINE"); v == "1" || strings.ToLower(v) == "true" {
			allowWeakOffline = true
		}
		if v := os.Getenv("RUA_NO_BWRAP"); v == "1" || strings.ToLower(v) == "true" {
			if !allowWeakOffline {
				return fmt.Errorf("offline build requires bubblewrap network isolation; unset RUA_NO_BWRAP or set RUA_ALLOW_WEAK_OFFLINE=1 to accept Landlock-only isolation")
			}
			useBwrap = false
		} else {
			useBwrap = true
		}
	}
	// If offline, prefetch sources using .SRCINFO/static PKGBUILD, then build offline
	if offline {
		if err := prefetchSources(dir, p, seccomp); err != nil {
			return err
		}
	}

	args := []string{"makepkg"}
	if force {
		args = append(args, "--force")
	}
	// makepkg will install deps if allowed; we do not change sudo behavior here
	// Network: if offline requested, keep default (deny); otherwise allow unrestricted network

	// FAKEROOT workaround similar to rua
	args = append(args, "-f")
	// Allow user-defined binds from wrap_args.d
	roAdd, roxAdd, rwAdd, rwxAdd := readWrapArgs(p.ConfigDir)

	cfg := sandbox.Config{
		RO:               append(ro, roAdd...),
		ROX:              append(rox, roxAdd...),
		RW:               rwAdd,
		RWX:              append(rwx, rwxAdd...),
		Env:              envs,
		WorkDir:          dir,
		UnrestrictedNet:  !offline,
		UseBubblewrap:    useBwrap,
		AllowWeakOffline: allowWeakOffline,
		SeccompDenylist:  seccomp,
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
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dst, 0o700); err != nil {
		return err
	}
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		mode := info.Mode()
		if mode&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			_ = os.Remove(target)
			return os.Symlink(link, target)
		}
		if d.IsDir() {
			return os.MkdirAll(target, mode.Perm())
		}
		if !mode.IsRegular() {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := copyRegularFile(path, target, mode.Perm()); err != nil {
			return err
		}
		return os.Chtimes(target, info.ModTime(), info.ModTime())
	})
}

func copyRegularFile(src, dst string, perm fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, perm)
}

// prefetchSources downloads sources ahead of an offline build using .SRCINFO
// If .SRCINFO exists, generate a minimal static PKGBUILD and run `makepkg -f --verifysource -p PKGBUILD.static`
// otherwise fall back to `makepkg -f --verifysource` on PKGBUILD. Runs with network access enabled.
func prefetchSources(dir string, p paths.Paths, seccomp bool) error {
	// Prepare env
	envs := []string{
		"HOME",
		"PATH",
		"FAKEROOTDONTTRYCHOWN=true",
		fmt.Sprintf("PKGDEST=%s", dir),
		fmt.Sprintf("SRCDEST=%s", dir),
		fmt.Sprintf("SRCPKGDEST=%s", dir),
		fmt.Sprintf("LOGDEST=%s", dir),
		fmt.Sprintf("BUILDDIR=%s", dir),
	}
	ro := []string{"/etc", dir}
	rox := []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"}
	rwx := []string{dir}

	args := []string{"makepkg", "-f", "--verifysource"}
	// If .SRCINFO present, generate PKGBUILD.static
	if _, err := os.Stat(filepath.Join(dir, ".SRCINFO")); err == nil {
		static := filepath.Join(dir, "PKGBUILD.static")
		if err := writeStaticPKGBUILDFromSRCINFO(dir, static); err != nil {
			return fmt.Errorf("generate static PKGBUILD from .SRCINFO: %w", err)
		}
		args = append(args, "-p", "PKGBUILD.static")
	}
	cfg := sandbox.Config{
		RO:              ro,
		ROX:             rox,
		RWX:             rwx,
		Env:             envs,
		WorkDir:         dir,
		UnrestrictedNet: true,
		SeccompDenylist: seccomp,
	}
	return sandbox.Run(cfg, args)
}

// writeStaticPKGBUILDFromSRCINFO parses .SRCINFO and writes a minimal PKGBUILD to dst.
func writeStaticPKGBUILDFromSRCINFO(dir, dst string) error {
	f, err := os.Open(filepath.Join(dir, ".SRCINFO"))
	if err != nil {
		return err
	}
	defer f.Close()
	// Collect keys -> values
	m := map[string][]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// lines are typically like: key = value, optionally with indentation
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if key == "pkgbase" || key == "pkgdesc" || key == "url" || key == "arch" ||
			key == "pkgver" || key == "pkgrel" || key == "epoch" || key == "pkgname" ||
			strings.HasPrefix(key, "source") || strings.HasSuffix(key, "sums") || strings.HasPrefix(key, "validpgpkeys") {
			m[key] = append(m[key], val)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	// Helper: array assignment
	arr := func(name string, vals []string) string {
		if len(vals) == 0 {
			return ""
		}
		b := &strings.Builder{}
		fmt.Fprintf(b, "%s=(", name)
		for i, v := range vals {
			if i > 0 {
				b.WriteByte(' ')
			}
			fmt.Fprintf(b, "'%s'", strings.ReplaceAll(v, "'", "'\\''"))
		}
		b.WriteString(")\n")
		return b.String()
	}
	scalar := func(name string, vals []string) string {
		if len(vals) == 0 {
			return ""
		}
		return fmt.Sprintf("%s='%s'\n", name, strings.ReplaceAll(vals[0], "'", "'\\''"))
	}
	scalarKeys := []string{"pkgbase", "pkgver", "pkgrel", "epoch", "pkgdesc", "url"}
	arrayKeys := []string{
		"pkgname", "arch", "license",
		"source", "source_aarch64", "source_i686", "source_x86_64",
		"validpgpkeys",
		"md5sums", "sha1sums", "sha224sums", "sha256sums", "sha384sums", "sha512sums", "b2sums",
		"md5sums_aarch64", "md5sums_i686", "md5sums_x86_64",
		"sha1sums_aarch64", "sha1sums_i686", "sha1sums_x86_64",
		"sha224sums_aarch64", "sha224sums_i686", "sha224sums_x86_64",
		"sha256sums_aarch64", "sha256sums_i686", "sha256sums_x86_64",
		"sha384sums_aarch64", "sha384sums_i686", "sha384sums_x86_64",
		"sha512sums_aarch64", "sha512sums_i686", "sha512sums_x86_64",
		"b2sums_aarch64", "b2sums_i686", "b2sums_x86_64",
	}
	b := &strings.Builder{}
	b.WriteString("# Generated from .SRCINFO for source verification only.\n")
	for _, k := range scalarKeys {
		if vals, ok := m[k]; ok {
			b.WriteString(scalar(k, vals))
		}
	}
	for _, k := range arrayKeys {
		if vals, ok := m[k]; ok {
			b.WriteString(arr(k, vals))
		}
	}
	return os.WriteFile(dst, []byte(b.String()), 0o644)
}

// readWrapArgs parses ~/.config/rua/wrap_args.d entries to include additional binds.
// Supported line formats per file: ro:/path, rox:/path, rw:/path, rwx:/path, comments with # and blank lines ignored.
func readWrapArgs(configDir string) (ro []string, rox []string, rw []string, rwx []string) {
	d := filepath.Join(configDir, "wrap_args.d")
	entries, err := os.ReadDir(d)
	if err != nil {
		return
	}
	parse := func(line string) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			return
		}
		var kind, path string
		if i := strings.Index(line, ":"); i > 0 {
			kind = line[:i]
			path = strings.TrimSpace(line[i+1:])
		}
		if path == "" {
			return
		}
		switch kind {
		case "ro":
			ro = append(ro, path)
		case "rox":
			rox = append(rox, path)
		case "rw":
			rw = append(rw, path)
		case "rwx":
			rwx = append(rwx, path)
		}
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		_ = func(ent fs.DirEntry) error {
			b, err := os.ReadFile(filepath.Join(d, ent.Name()))
			if err != nil {
				return nil
			}
			for _, ln := range strings.Split(string(b), "\n") {
				parse(ln)
			}
			return nil
		}(e)
	}
	return
}
