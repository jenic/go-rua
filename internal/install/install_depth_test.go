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

type rtDFunc func(*http.Request) (*http.Response, error)

func (f rtDFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func respD(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewBufferString(body)), Header: make(http.Header)}
}

func TestInstallDepthAsDepsFlagPerGroup(t *testing.T) {
	restoreInstallSeams(t)

	// AUR info: root depends on dep (both AUR)
	t.Cleanup(aur.SetHTTPClientForTests(&http.Client{Transport: rtDFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("type") == "info" {
			q := r.URL.Query()["arg[]"]
			if len(q) == 1 && q[0] == "root" {
				body := `{"version":5,"type":"multiinfo","resultcount":1,"results":[{"Name":"root","Version":"1","PackageBase":"root","Depends":["dep>=1"]}]}`
				return respD(200, body), nil
			}
			// dep lookup
			body := `{"version":5,"type":"multiinfo","resultcount":1,"results":[{"Name":"dep","Version":"1","PackageBase":"dep"}]}`
			return respD(200, body), nil
		}
		return respD(404, ""), nil
	})}))

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	p := paths.MustInitNoMakepkgChecks()

	// Fake git ops
	runCFn = func(dir, name string, args ...string) error { return nil }

	// Build function creates artifact based on dir base
	buildDirectoryFn = func(dir string, _ paths.Paths, _ bool, _ bool, _ bool) error {
		base := filepath.Base(dir)
		return os.WriteFile(filepath.Join(dir, base+"-1-1-any.pkg.tar.zst"), []byte("pkg"), 0o644)
	}
	// No-op tarcheck
	tarCheck = func(_ string) error { return nil }

	// Capture install calls
	calls := make([]struct{ asdeps bool }, 0, 2)
	pacmanInstallLocalWithMode = func(files []string, asDeps bool) error {
		calls = append(calls, struct{ asdeps bool }{asdeps: asDeps})
		return nil
	}

	// Stub runFn to emulate `git clone` by creating the review dir with .git
	runFn = func(name string, args ...string) error {
		if name == "git" && len(args) >= 3 && args[0] == "clone" {
			dest := args[len(args)-1]
			if err := os.MkdirAll(filepath.Join(dest, ".git"), 0o755); err != nil {
				return err
			}
			// also create a PKGBUILD so copy step finds it
			_ = os.WriteFile(filepath.Join(dest, "PKGBUILD"), []byte("pkgname=('x')\npkgver=1\npkgrel=1\n"), 0o644)
		}
		return nil
	}

	if err := Install([]string{"root"}, p, Options{NonInteractive: true, InstallBuilt: true}); err != nil {
		t.Fatalf("Install error: %v", err)
	}
	if len(calls) != 2 || calls[0].asdeps != true || calls[1].asdeps != false {
		t.Fatalf("unexpected asdeps flags: %+v", calls)
	}
}
