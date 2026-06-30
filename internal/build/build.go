package build

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"go-rua/internal/paths"
	"go-rua/internal/sandbox"
)

const sandboxGPGHomeDir = ".rua-gnupg"

var (
	prepareSandboxGPGHomeFn = prepareSandboxGPGHome
	packageSigningConfigFn  = packageSigningConfig
	signPackageFn           = signPackage
	gpgCommandFn            = exec.Command
)

type signingConfig struct {
	Enabled bool
	GPGKey  string
}

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

	gpgHome, err := prepareSandboxGPGHomeFn(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to prepare sandbox GPG keyring: %v\n", err)
	}
	envs := makepkgEnv(dir, gpgHome)

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
		if err := prefetchSourcesWithGPGHome(dir, p, seccomp, gpgHome); err != nil {
			return err
		}
	}

	args := []string{"makepkg", "--nosign"}
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
	if err := sandbox.Run(cfg, args); err != nil {
		return err
	}
	signing := packageSigningConfigFn()
	if !signing.Enabled {
		return nil
	}
	tars, err := packageArtifacts(dir)
	if err != nil {
		return err
	}
	for _, tar := range tars {
		if err := signPackageFn(tar, signing.GPGKey); err != nil {
			return fmt.Errorf("sign package %s: %w", filepath.Base(tar), err)
		}
	}
	return nil
}

func makepkgEnv(dir, gpgHome string) []string {
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
	if gpgHome != "" {
		envs = append(envs, fmt.Sprintf("GNUPGHOME=%s", gpgHome))
	}
	return envs
}

func prepareSandboxGPGHome(dir string) (string, error) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		return "", nil
	}
	export := exec.Command(gpg, "--batch", "--export")
	pubkeys, err := export.Output()
	if err != nil {
		return "", fmt.Errorf("export public keys: %w", err)
	}
	if len(bytes.TrimSpace(pubkeys)) == 0 {
		return "", nil
	}
	gpgHome := filepath.Join(dir, sandboxGPGHomeDir)
	if err := os.RemoveAll(gpgHome); err != nil {
		return "", err
	}
	if err := os.MkdirAll(gpgHome, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(gpgHome, 0o700); err != nil {
		return "", err
	}
	importCmd := exec.Command(gpg, "--batch", "--homedir", gpgHome, "--import")
	importCmd.Stdin = bytes.NewReader(pubkeys)
	if out, err := importCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("import public keys: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return gpgHome, nil
}

func packageArtifacts(dir string) ([]string, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var tars []string
	for _, f := range files {
		name := f.Name()
		if f.IsDir() || strings.HasSuffix(name, ".sig") {
			continue
		}
		if isPackageArtifact(name) {
			tars = append(tars, filepath.Join(dir, name))
		}
	}
	sort.Strings(tars)
	return tars, nil
}

func isPackageArtifact(name string) bool {
	for _, suffix := range []string{".pkg.tar", ".pkg.tar.xz", ".pkg.tar.gz", ".pkg.tar.gzip", ".pkg.tar.zst", ".pkg.tar.zstd"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

func signPackage(path, gpgKey string) error {
	args := []string{"--yes", "--detach-sign", "--no-armor"}
	if gpgKey != "" {
		args = append(args, "--local-user", gpgKey)
	}
	args = append(args, path)
	cmd := gpgCommandFn("gpg", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func packageSigningConfig() signingConfig {
	paths := makepkgConfigPaths()
	var enabled *bool
	gpgKey := ""
	for _, path := range paths {
		cfg, ok := parseMakepkgConfig(path)
		if !ok {
			continue
		}
		if cfg.signingSet {
			v := cfg.signingEnabled
			enabled = &v
		}
		if cfg.gpgKey != "" {
			gpgKey = cfg.gpgKey
		}
	}
	if enabled == nil {
		return signingConfig{}
	}
	return signingConfig{Enabled: *enabled, GPGKey: gpgKey}
}

func makepkgConfigPaths() []string {
	if custom := os.Getenv("MAKEPKG_CONF"); custom != "" {
		return []string{custom}
	}
	paths := []string{"/etc/makepkg.conf"}
	if entries, err := os.ReadDir("/etc/makepkg.conf.d"); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".conf") {
				paths = append(paths, filepath.Join("/etc/makepkg.conf.d", entry.Name()))
			}
		}
		sort.Strings(paths[1:])
	}
	if home := os.Getenv("HOME"); home != "" {
		paths = append(paths, filepath.Join(home, ".makepkg.conf"))
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			paths = append(paths, filepath.Join(xdg, "pacman", "makepkg.conf"))
		} else {
			paths = append(paths, filepath.Join(home, ".config", "pacman", "makepkg.conf"))
		}
	}
	return paths
}

type parsedMakepkgConfig struct {
	signingSet     bool
	signingEnabled bool
	gpgKey         string
}

func parseMakepkgConfig(path string) (parsedMakepkgConfig, bool) {
	f, err := os.Open(path)
	if err != nil {
		return parsedMakepkgConfig{}, false
	}
	defer f.Close()
	cfg := parsedMakepkgConfig{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(stripShellComment(sc.Text()))
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch key {
		case "BUILDENV":
			if enabled, ok := parseBuildenvSign(val); ok {
				cfg.signingSet = true
				cfg.signingEnabled = enabled
			}
		case "SIGNPKG":
			if enabled, ok := parseBoolSetting(val); ok {
				cfg.signingSet = true
				cfg.signingEnabled = enabled
			}
		case "GPGKEY":
			cfg.gpgKey = unquoteShellValue(val)
		}
	}
	return cfg, sc.Err() == nil
}

func parseBuildenvSign(val string) (bool, bool) {
	val = strings.TrimSpace(val)
	val = strings.TrimPrefix(val, "(")
	val = strings.TrimSuffix(val, ")")
	fields := strings.Fields(val)
	for _, field := range fields {
		field = unquoteShellValue(field)
		switch field {
		case "sign":
			return true, true
		case "!sign":
			return false, true
		}
	}
	return false, false
}

func parseBoolSetting(val string) (bool, bool) {
	switch strings.ToLower(unquoteShellValue(val)) {
	case "1", "y", "yes", "true", "on":
		return true, true
	case "0", "n", "no", "false", "off":
		return false, true
	default:
		return false, false
	}
}

func unquoteShellValue(val string) string {
	val = strings.TrimSpace(val)
	if len(val) >= 2 {
		if (val[0] == '\'' && val[len(val)-1] == '\'') || (val[0] == '"' && val[len(val)-1] == '"') {
			return val[1 : len(val)-1]
		}
	}
	return val
}

func stripShellComment(line string) string {
	var quote rune
	escaped := false
	for i, r := range line {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == '#' {
			return line[:i]
		}
	}
	return line
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
	return prefetchSourcesWithGPGHome(dir, p, seccomp, "")
}

func prefetchSourcesWithGPGHome(dir string, p paths.Paths, seccomp bool, gpgHome string) error {
	envs := makepkgEnv(dir, gpgHome)
	ro := []string{"/etc", dir}
	rox := []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"}
	rwx := []string{dir}

	args := []string{"makepkg", "--nosign", "-f", "--verifysource"}
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
		if key == "pkgbase" || key == "pkgdesc" || key == "url" || key == "arch" || key == "license" ||
			key == "pkgver" || key == "pkgrel" || key == "epoch" || key == "pkgname" ||
			strings.HasPrefix(key, "source") || isChecksumKey(key) || strings.HasPrefix(key, "validpgpkeys") {
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

func isChecksumKey(key string) bool {
	for _, prefix := range []string{"md5sums", "sha1sums", "sha224sums", "sha256sums", "sha384sums", "sha512sums", "b2sums"} {
		if key == prefix || strings.HasPrefix(key, prefix+"_") {
			return true
		}
	}
	return false
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
