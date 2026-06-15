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
)

type rtIFunc func(*http.Request) (*http.Response, error)

func (f rtIFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func resp(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewBufferString(body)), Header: make(http.Header)}
}

func TestInstallNonInteractiveFlowStagesAndInstalls(t *testing.T) {
	restoreInstallSeams(t)

	// Arrange AUR info for single target "app" with no extra AUR deps
	t.Cleanup(aur.SetHTTPClientForTests(&http.Client{Transport: rtIFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("type") == "info" {
			body := `{"version":5,"type":"multiinfo","resultcount":1,"results":[{"Name":"app","Version":"1","PackageBase":"app"}]}`
			return resp(200, body), nil
		}
		return resp(404, ""), nil
	})}))

	// Create fake repo and build directories with isolated XDG
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	p := paths.MustInitNoMakepkgChecks()
	pkgbase := "app"
	reviewDir := p.ReviewDir(pkgbase)
	// Make fake git dir so Install takes the update path
	if err := os.MkdirAll(filepath.Join(reviewDir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Place a fake PKGBUILD and a built artifact name pattern
	if err := os.WriteFile(filepath.Join(reviewDir, "PKGBUILD"), []byte("pkgname=('app')\npkgver=1\npkgrel=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Stub build directory runner to create an artifact file we can stage
	buildDirectoryFn = func(dir string, p paths.Paths, offline, force bool, seccomp bool) error {
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			return err
		} else if got := fi.Mode().Perm(); got != 0o700 {
			t.Fatalf("build directory permissions = %o, want 700", got)
		}
		// create a fake artifact
		f := filepath.Join(dir, "app-1-1-x86_64.pkg.tar.zst")
		if err := os.WriteFile(f, []byte("pkg"), 0o644); err != nil {
			return err
		}
		// create .sig and an extra unrelated artifact to exercise whitelist
		_ = os.WriteFile(f+".sig", []byte("sig"), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "other-1-1-x86_64.pkg.tar.zst"), []byte("pkg"), 0o644)
		return nil
	}
	// Stub tarcheck to no-op
	tarCheck = func(_ string) error { return nil }
	// Stub pacman installer to capture asdeps flag
	installed := struct {
		files  []string
		asdeps bool
	}{}
	pacmanInstallLocalWithMode = func(files []string, asDeps bool) error {
		installed.files = append(installed.files, files...)
		installed.asdeps = asDeps
		return nil
	}
	// Stub runC to no-op so git commands don’t execute
	runCFn = func(dir, name string, args ...string) error { return nil }

	opt := Options{NonInteractive: true, InstallBuilt: true}
	if err := Install([]string{"app"}, p, opt); err != nil {
		t.Fatalf("Install error: %v", err)
	}
	if len(installed.files) != 1 || !strings.HasSuffix(installed.files[0], ".pkg.tar.zst") || installed.asdeps {
		t.Fatalf("unexpected installed: %+v", installed)
	}
}
