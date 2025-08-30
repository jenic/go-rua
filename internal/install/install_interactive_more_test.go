package install

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"go-rua/internal/aur"
	"go-rua/internal/paths"
)

type rtIMFunc func(*http.Request) (*http.Response, error)

func (f rtIMFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func respIM(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewBufferString(body)), Header: make(http.Header)}
}

func TestInstallInteractiveDiffAndShellBranches(t *testing.T) {
	aur.SetHTTPClientForTests(&http.Client{Transport: rtIMFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("type") == "info" {
			return respIM(200, `{"version":5,"type":"multiinfo","resultcount":1,"results":[{"Name":"pkg","Version":"1","PackageBase":"pkg"}]}`), nil
		}
		return respIM(404, ""), nil
	})})
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
	runCQFn = func(dir, name string, args ...string) error { return nil } // merged=true
	runShell = func(dir string) error { return nil }
	buildDirectoryFn = func(dir string, _ paths.Paths, _ bool, _ bool, _ bool) error {
		return os.WriteFile(filepath.Join(dir, "pkg-1-1-any.pkg.tar.zst"), []byte("pkg"), 0o644)
	}
	tarCheck = func(_ string) error { return nil }

	// input: view diff, open shell, then ok
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()
	f, _ := os.CreateTemp("", "stdin-*")
	defer os.Remove(f.Name())
	_, _ = f.Write([]byte("d\n"))
	_, _ = f.Write([]byte("t\n"))
	_, _ = f.Write([]byte("o\n"))
	_, _ = f.Seek(0, 0)
	os.Stdin = f

	if err := Install([]string{"pkg"}, p, Options{NonInteractive: false, InstallBuilt: false}); err != nil {
		t.Fatalf("Install interactive branches error: %v", err)
	}
}
