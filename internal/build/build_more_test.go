package build

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go-rua/internal/paths"
	"go-rua/internal/sandbox"
)

func TestBuildDirectoryFlagsAndBwrapEnv(t *testing.T) {
	stubPrepareSandboxGPGHome(t, func(string) (string, error) { return "", nil })
	stubPackageSigningConfig(t, signingConfig{})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=('x')\npkgver=1\npkgrel=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := paths.Paths{ConfigDir: t.TempDir(), CacheBuildDir: t.TempDir(), DataCheckedTars: t.TempDir()}
	// Stub execution to just succeed
	sandbox.SetExecCommandForTests(func(name string, arg ...string) *exec.Cmd {
		return exec.Command("/bin/true")
	})
	defer sandbox.SetExecCommandForTests(exec.Command)
	// Warn path via PKGEXT
	t.Setenv("PKGEXT", ".pkg.tar.foobar")
	// Respect RUA_ALWAYS_BWRAP then explicit weak-offline RUA_NO_BWRAP.
	t.Setenv("RUA_ALWAYS_BWRAP", "1")
	if err := BuildDirectory(dir, p, false, true, true); err != nil {
		t.Fatalf("err: %v", err)
	}
	t.Setenv("RUA_ALWAYS_BWRAP", "")
	t.Setenv("RUA_NO_BWRAP", "1")
	t.Setenv("RUA_ALLOW_WEAK_OFFLINE", "1")
	if err := BuildDirectory(dir, p, true, false, false); err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestBuildDirectoryOfflineNoBwrapRequiresExplicitWeakOffline(t *testing.T) {
	stubPrepareSandboxGPGHome(t, func(string) (string, error) { return "", nil })
	stubPackageSigningConfig(t, signingConfig{})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=('x')\npkgver=1\npkgrel=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := paths.Paths{ConfigDir: t.TempDir(), CacheBuildDir: t.TempDir(), DataCheckedTars: t.TempDir()}
	t.Setenv("RUA_NO_BWRAP", "1")
	if err := BuildDirectory(dir, p, true, false, false); err == nil || !strings.Contains(err.Error(), "requires bubblewrap") {
		t.Fatalf("expected bubblewrap requirement error, got %v", err)
	}
}

func TestBuildDirectoryMainSandboxExcludesGPGHome(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=('x')\npkgver=1\npkgrel=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := paths.Paths{ConfigDir: t.TempDir(), CacheBuildDir: t.TempDir(), DataCheckedTars: t.TempDir()}
	gnupg := t.TempDir()
	t.Setenv("GNUPGHOME", gnupg)
	sandboxGPGHome := filepath.Join(dir, sandboxGPGHomeDir)
	stubPrepareSandboxGPGHome(t, func(string) (string, error) { return sandboxGPGHome, nil })
	stubPackageSigningConfig(t, signingConfig{})
	capture := filepath.Join(t.TempDir(), "sandbox.json")
	sandbox.SetExecCommandForTests(func(name string, arg ...string) *exec.Cmd {
		return exec.Command("/bin/sh", "-c", `printf '%s' "$RUA_SANDBOX_CFG" > "$1"`, "sh", capture)
	})
	defer sandbox.SetExecCommandForTests(exec.Command)

	if err := BuildDirectory(dir, p, false, false, true); err != nil {
		t.Fatalf("BuildDirectory error: %v", err)
	}
	b, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	var cfg sandbox.Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	allRO := strings.Join(append(append([]string{}, cfg.RO...), cfg.ROX...), "\x00")
	if strings.Contains(allRO, gnupg) {
		t.Fatalf("main build sandbox must not include GNUPGHOME, cfg=%+v", cfg)
	}
	if envValue(cfg.Env, "GNUPGHOME") != sandboxGPGHome {
		t.Fatalf("main build sandbox GNUPGHOME = %q, want %q; cfg=%+v", envValue(cfg.Env, "GNUPGHOME"), sandboxGPGHome, cfg)
	}
}

func TestBuildDirectoryNoSignInSandboxThenSignsArtifactsOnHost(t *testing.T) {
	stubPrepareSandboxGPGHome(t, func(string) (string, error) { return "", nil })
	stubPackageSigningConfig(t, signingConfig{Enabled: true, GPGKey: "ABC123"})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=('x')\npkgver=1\npkgrel=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(dir, "x-1-1-any.pkg.tar.zst")
	p := paths.Paths{ConfigDir: t.TempDir(), CacheBuildDir: t.TempDir(), DataCheckedTars: t.TempDir()}

	var sandboxArgs []string
	sandbox.SetExecCommandForTests(func(name string, arg ...string) *exec.Cmd {
		sandboxArgs = append([]string{name}, arg...)
		if err := os.WriteFile(pkg, []byte("pkg"), 0o644); err != nil {
			t.Fatal(err)
		}
		return exec.Command("/bin/true")
	})
	defer sandbox.SetExecCommandForTests(exec.Command)

	var signedPath, signedKey string
	stubSignPackage(t, func(path, gpgKey string) error {
		signedPath = path
		signedKey = gpgKey
		return os.WriteFile(path+".sig", []byte("sig"), 0o644)
	})

	if err := BuildDirectory(dir, p, false, true, true); err != nil {
		t.Fatalf("BuildDirectory error: %v", err)
	}
	if !contains(sandboxArgs, "--nosign") {
		t.Fatalf("sandboxed makepkg args missing --nosign: %v", sandboxArgs)
	}
	if signedPath != pkg {
		t.Fatalf("signed path = %q, want %q", signedPath, pkg)
	}
	if signedKey != "ABC123" {
		t.Fatalf("signed key = %q, want ABC123", signedKey)
	}
	if _, err := os.Stat(pkg + ".sig"); err != nil {
		t.Fatalf("signature not created: %v", err)
	}
}

func TestSignPackageAllowsInteractivePinentry(t *testing.T) {
	var gotName string
	var gotArgs []string
	stubGPGCommand(t, func(name string, args ...string) *exec.Cmd {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return exec.Command("/bin/true")
	})

	if err := signPackage("/tmp/demo.pkg.tar.zst", "ABC123"); err != nil {
		t.Fatalf("signPackage error: %v", err)
	}
	if gotName != "gpg" {
		t.Fatalf("command = %q, want gpg", gotName)
	}
	if contains(gotArgs, "--batch") {
		t.Fatalf("host package signing must allow normal pinentry; got args %v", gotArgs)
	}
	for _, want := range []string{"--yes", "--detach-sign", "--no-armor", "--local-user", "ABC123", "/tmp/demo.pkg.tar.zst"} {
		if !contains(gotArgs, want) {
			t.Fatalf("signPackage args missing %q: %v", want, gotArgs)
		}
	}
}

func TestRunShell(t *testing.T) {
	dir := t.TempDir()
	sandbox.SetExecCommandForTests(func(name string, arg ...string) *exec.Cmd { return exec.Command("/bin/true") })
	defer sandbox.SetExecCommandForTests(exec.Command)
	if err := RunShell(dir); err != nil {
		t.Fatalf("RunShell err: %v", err)
	}
}

func stubPrepareSandboxGPGHome(t *testing.T, fn func(string) (string, error)) {
	t.Helper()
	old := prepareSandboxGPGHomeFn
	prepareSandboxGPGHomeFn = fn
	t.Cleanup(func() { prepareSandboxGPGHomeFn = old })
}

func stubPackageSigningConfig(t *testing.T, cfg signingConfig) {
	t.Helper()
	old := packageSigningConfigFn
	packageSigningConfigFn = func() signingConfig { return cfg }
	t.Cleanup(func() { packageSigningConfigFn = old })
}

func stubSignPackage(t *testing.T, fn func(string, string) error) {
	t.Helper()
	old := signPackageFn
	signPackageFn = fn
	t.Cleanup(func() { signPackageFn = old })
}

func stubGPGCommand(t *testing.T, fn func(string, ...string) *exec.Cmd) {
	t.Helper()
	old := gpgCommandFn
	gpgCommandFn = fn
	t.Cleanup(func() { gpgCommandFn = old })
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			return strings.TrimPrefix(item, prefix)
		}
	}
	return ""
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
