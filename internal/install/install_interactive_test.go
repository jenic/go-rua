package install

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-rua/internal/aur"
	"go-rua/internal/paths"
	"go-rua/internal/shellaudit"
	"go-rua/internal/sourceaudit"
)

type rtIFunc2 func(*http.Request) (*http.Response, error)

func (f rtIFunc2) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func respI(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewBufferString(body)), Header: make(http.Header)}
}

func TestInstallInteractiveOkPath(t *testing.T) {
	restoreInstallSeams(t)

	// Minimal AUR info
	t.Cleanup(aur.SetHTTPClientForTests(&http.Client{Transport: rtIFunc2(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("type") == "info" {
			body := `{"version":5,"type":"multiinfo","resultcount":1,"results":[{"Name":"pkg","Version":"1","PackageBase":"pkg"}]}`
			return respI(200, body), nil
		}
		return respI(404, ""), nil
	})}))

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	p := paths.MustInitNoMakepkgChecks()

	// Fake clone creation
	runFn = func(name string, args ...string) error {
		if name == "git" && len(args) >= 3 && args[0] == "clone" {
			dest := args[len(args)-1]
			_ = os.MkdirAll(filepath.Join(dest, ".git"), 0o755)
			_ = os.WriteFile(filepath.Join(dest, "PKGBUILD"), []byte("pkgname=('pkg')\npkgver=1\npkgrel=1\n"), 0o644)
		}
		return nil
	}
	runCFn = func(dir, name string, args ...string) error { return nil }
	runCQFn = func(dir, name string, args ...string) error { return nil } // merged=true
	runShell = func(dir string) error { return nil }
	// build produces artifact
	buildDirectoryFn = func(dir string, _ paths.Paths, _ bool, _ bool, _ bool) error {
		return os.WriteFile(filepath.Join(dir, "pkg-1-1-any.pkg.tar.zst"), []byte("pkg"), 0o644)
	}
	tarCheck = func(_ string) error { return nil }

	// Provide input 'o' to continue from interactive prompt
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()
	f, err := os.CreateTemp("", "stdin-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write([]byte("o\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	os.Stdin = f

	if err := Install([]string{"pkg"}, p, Options{NonInteractive: false, InstallBuilt: false}); err != nil {
		t.Fatalf("Install interactive error: %v", err)
	}
}

func TestInstallInteractiveRequiresURLWarningAck(t *testing.T) {
	restoreInstallSeams(t)

	t.Cleanup(aur.SetHTTPClientForTests(&http.Client{Transport: rtIFunc2(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("type") == "info" {
			body := `{"version":5,"type":"multiinfo","resultcount":1,"results":[{"Name":"pkg","Version":"1","PackageBase":"pkg"}]}`
			return respI(200, body), nil
		}
		return respI(404, ""), nil
	})}))

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	p := paths.MustInitNoMakepkgChecks()

	runFn = func(name string, args ...string) error {
		if name == "git" && len(args) >= 3 && args[0] == "clone" {
			dest := args[len(args)-1]
			_ = os.MkdirAll(filepath.Join(dest, ".git"), 0o755)
			_ = os.WriteFile(filepath.Join(dest, "PKGBUILD"), []byte("pkgname=('pkg')\npkgver=1\npkgrel=1\n"), 0o644)
		}
		return nil
	}
	runCFn = func(dir, name string, args ...string) error { return nil }
	runCQFn = func(dir, name string, args ...string) error { return nil }
	sourceAuditFn = func(string) (sourceaudit.Report, error) {
		return sourceaudit.Report{Incomplete: []string{"source contains shell expansion"}}, nil
	}
	formatSourceAuditFn = func(sourceaudit.Report) string { return "Source URL warnings:\n" }
	buildCalls := 0
	buildDirectoryFn = func(dir string, _ paths.Paths, _ bool, _ bool, _ bool) error {
		buildCalls++
		return os.WriteFile(filepath.Join(dir, "pkg-1-1-any.pkg.tar.zst"), []byte("pkg"), 0o644)
	}
	tarCheck = func(_ string) error { return nil }

	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()
	f, err := os.CreateTemp("", "stdin-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write([]byte("o\nu\no\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	os.Stdin = f

	if err := Install([]string{"pkg"}, p, Options{NonInteractive: false, InstallBuilt: false}); err != nil {
		t.Fatalf("Install interactive error: %v", err)
	}
	if buildCalls != 1 {
		t.Fatalf("expected build after one acknowledgement, got %d", buildCalls)
	}
}

func TestInstallNonInteractiveFailsWithURLWarnings(t *testing.T) {
	restoreInstallSeams(t)

	t.Cleanup(aur.SetHTTPClientForTests(&http.Client{Transport: rtIFunc2(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("type") == "info" {
			body := `{"version":5,"type":"multiinfo","resultcount":1,"results":[{"Name":"pkg","Version":"1","PackageBase":"pkg"}]}`
			return respI(200, body), nil
		}
		return respI(404, ""), nil
	})}))

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	p := paths.MustInitNoMakepkgChecks()

	runFn = func(name string, args ...string) error {
		if name == "git" && len(args) >= 3 && args[0] == "clone" {
			dest := args[len(args)-1]
			_ = os.MkdirAll(filepath.Join(dest, ".git"), 0o755)
			_ = os.WriteFile(filepath.Join(dest, "PKGBUILD"), []byte("pkgname=('pkg')\npkgver=1\npkgrel=1\n"), 0o644)
		}
		return nil
	}
	runCFn = func(dir, name string, args ...string) error { return nil }
	sourceAuditFn = func(string) (sourceaudit.Report, error) {
		return sourceaudit.Report{Incomplete: []string{"source contains shell expansion"}}, nil
	}
	formatSourceAuditFn = func(sourceaudit.Report) string { return "Source URL warnings:\n" }
	buildCalls := 0
	buildDirectoryFn = func(dir string, _ paths.Paths, _ bool, _ bool, _ bool) error {
		buildCalls++
		return os.WriteFile(filepath.Join(dir, "pkg-1-1-any.pkg.tar.zst"), []byte("pkg"), 0o644)
	}
	tarCheck = func(_ string) error { return nil }

	err := Install([]string{"pkg"}, p, Options{NonInteractive: true, InstallBuilt: false})
	if err == nil || !strings.Contains(err.Error(), "source URL audit warnings") {
		t.Fatalf("expected URL warning error, got %v", err)
	}
	if buildCalls != 0 {
		t.Fatalf("expected noninteractive build to stop, got %d calls", buildCalls)
	}
}

func TestInstallInteractiveRequiresShellWarningAck(t *testing.T) {
	restoreInstallSeams(t)

	t.Cleanup(aur.SetHTTPClientForTests(&http.Client{Transport: rtIFunc2(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("type") == "info" {
			body := `{"version":5,"type":"multiinfo","resultcount":1,"results":[{"Name":"pkg","Version":"1","PackageBase":"pkg"}]}`
			return respI(200, body), nil
		}
		return respI(404, ""), nil
	})}))

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	p := paths.MustInitNoMakepkgChecks()

	runFn = func(name string, args ...string) error {
		if name == "git" && len(args) >= 3 && args[0] == "clone" {
			dest := args[len(args)-1]
			_ = os.MkdirAll(filepath.Join(dest, ".git"), 0o755)
			_ = os.WriteFile(filepath.Join(dest, "PKGBUILD"), []byte("pkgname=('pkg')\npkgver=1\npkgrel=1\n"), 0o644)
		}
		return nil
	}
	runCFn = func(dir, name string, args ...string) error { return nil }
	runCQFn = func(dir, name string, args ...string) error { return nil }
	shellAuditFn = func(string) (shellaudit.Report, error) {
		return shellaudit.Report{Findings: []shellaudit.Finding{{File: "PKGBUILD", Line: 1, Column: 1, Rule: "eval", Severity: "high", Reason: "test"}}}, nil
	}
	formatShellAuditFn = func(shellaudit.Report) string { return "Shell logic warnings:\n" }
	buildCalls := 0
	buildDirectoryFn = func(dir string, _ paths.Paths, _ bool, _ bool, _ bool) error {
		buildCalls++
		return os.WriteFile(filepath.Join(dir, "pkg-1-1-any.pkg.tar.zst"), []byte("pkg"), 0o644)
	}
	tarCheck = func(_ string) error { return nil }

	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()
	f, err := os.CreateTemp("", "stdin-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write([]byte("o\nh\no\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	os.Stdin = f

	if err := Install([]string{"pkg"}, p, Options{NonInteractive: false, InstallBuilt: false}); err != nil {
		t.Fatalf("Install interactive error: %v", err)
	}
	if buildCalls != 1 {
		t.Fatalf("expected build after shell acknowledgement, got %d", buildCalls)
	}
}

func TestInstallNonInteractiveFailsWithShellWarnings(t *testing.T) {
	restoreInstallSeams(t)

	t.Cleanup(aur.SetHTTPClientForTests(&http.Client{Transport: rtIFunc2(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("type") == "info" {
			body := `{"version":5,"type":"multiinfo","resultcount":1,"results":[{"Name":"pkg","Version":"1","PackageBase":"pkg"}]}`
			return respI(200, body), nil
		}
		return respI(404, ""), nil
	})}))

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	p := paths.MustInitNoMakepkgChecks()

	runFn = func(name string, args ...string) error {
		if name == "git" && len(args) >= 3 && args[0] == "clone" {
			dest := args[len(args)-1]
			_ = os.MkdirAll(filepath.Join(dest, ".git"), 0o755)
			_ = os.WriteFile(filepath.Join(dest, "PKGBUILD"), []byte("pkgname=('pkg')\npkgver=1\npkgrel=1\n"), 0o644)
		}
		return nil
	}
	runCFn = func(dir, name string, args ...string) error { return nil }
	shellAuditFn = func(string) (shellaudit.Report, error) {
		return shellaudit.Report{Findings: []shellaudit.Finding{{File: "PKGBUILD", Line: 1, Column: 1, Rule: "eval", Severity: "high", Reason: "test"}}}, nil
	}
	formatShellAuditFn = func(shellaudit.Report) string { return "Shell logic warnings:\n" }
	buildCalls := 0
	buildDirectoryFn = func(dir string, _ paths.Paths, _ bool, _ bool, _ bool) error {
		buildCalls++
		return os.WriteFile(filepath.Join(dir, "pkg-1-1-any.pkg.tar.zst"), []byte("pkg"), 0o644)
	}
	tarCheck = func(_ string) error { return nil }

	err := Install([]string{"pkg"}, p, Options{NonInteractive: true, InstallBuilt: false})
	if err == nil || !strings.Contains(err.Error(), "shell logic audit warnings") {
		t.Fatalf("expected shell warning error, got %v", err)
	}
	if buildCalls != 0 {
		t.Fatalf("expected noninteractive build to stop, got %d calls", buildCalls)
	}
}
