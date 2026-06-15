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

type rtAFunc func(*http.Request) (*http.Response, error)

func (f rtAFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func respA(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewBufferString(body)), Header: make(http.Header)}
}

func TestInstallAsDepsTrueOverridesDepth(t *testing.T) {
	restoreInstallSeams(t)

	t.Cleanup(aur.SetHTTPClientForTests(&http.Client{Transport: rtAFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("type") == "info" {
			return respA(200, `{"version":5,"type":"multiinfo","resultcount":1,"results":[{"Name":"solo","Version":"1","PackageBase":"solo"}]}`), nil
		}
		return respA(404, ""), nil
	})}))
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	p := paths.MustInitNoMakepkgChecks()

	runFn = func(name string, args ...string) error {
		if name == "git" && len(args) >= 3 && args[0] == "clone" {
			dest := args[len(args)-1]
			_ = os.MkdirAll(filepath.Join(dest, ".git"), 0o755)
			_ = os.WriteFile(filepath.Join(dest, "PKGBUILD"), []byte("pkgname=('solo')\npkgver=1\npkgrel=1\n"), 0o644)
		}
		return nil
	}
	runCFn = func(dir, name string, args ...string) error { return nil }
	runCQFn = func(dir, name string, args ...string) error { return nil }
	buildDirectoryFn = func(dir string, _ paths.Paths, _ bool, _ bool, _ bool) error {
		return os.WriteFile(filepath.Join(dir, "solo-1-1-any.pkg.tar.zst"), []byte("pkg"), 0o644)
	}
	tarCheck = func(_ string) error { return nil }

	calledAsDeps := false
	pacmanInstallLocalWithMode = func(files []string, asDeps bool) error { calledAsDeps = asDeps; return nil }

	// NonInteractive with AsDeps true
	if err := Install([]string{"solo"}, p, Options{NonInteractive: true, InstallBuilt: true, AsDeps: true}); err != nil {
		t.Fatalf("Install error: %v", err)
	}
	if !calledAsDeps {
		t.Fatalf("expected asdeps true when AsDeps option is set")
	}
}
