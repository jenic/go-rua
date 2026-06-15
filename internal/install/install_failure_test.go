package install

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-rua/internal/aur"
	"go-rua/internal/paths"
	"go-rua/internal/sourceaudit"
)

type rtFailureFunc func(*http.Request) (*http.Response, error)

func (f rtFailureFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func respFailure(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewBufferString(body)), Header: make(http.Header)}
}

func setupOnePackageInstallFailureTest(t *testing.T, pkg string) paths.Paths {
	t.Helper()

	restoreInstallSeams(t)

	t.Cleanup(aur.SetHTTPClientForTests(&http.Client{Transport: rtFailureFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("type") == "info" {
			body := fmt.Sprintf(`{"version":5,"type":"multiinfo","resultcount":1,"results":[{"Name":%q,"Version":"1","PackageBase":%q}]}`, pkg, pkg)
			return respFailure(200, body), nil
		}
		return respFailure(404, ""), nil
	})}))

	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	p := paths.MustInitNoMakepkgChecks()

	runFn = func(name string, args ...string) error {
		if name == "git" && len(args) >= 3 && args[0] == "clone" {
			dest := args[len(args)-1]
			if err := os.MkdirAll(filepath.Join(dest, ".git"), 0o755); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(dest, "PKGBUILD"), []byte("pkgname=('"+pkg+"')\npkgver=1\npkgrel=1\n"), 0o644)
		}
		return nil
	}
	runCFn = func(dir, name string, args ...string) error { return nil }
	runCQFn = func(dir, name string, args ...string) error { return nil }
	sourceAuditFn = func(string) (sourceaudit.Report, error) { return sourceaudit.Report{}, nil }
	formatSourceAuditFn = func(sourceaudit.Report) string { return "" }
	buildDirectoryFn = func(dir string, _ paths.Paths, _ bool, _ bool, _ bool) error {
		return os.WriteFile(filepath.Join(dir, pkg+"-1-1-any.pkg.tar.zst"), []byte("pkg"), 0o644)
	}
	tarCheck = func(string) error { return nil }
	pacmanInstallLocalWithMode = func([]string, bool) error { return nil }

	return p
}

func TestInstallPropagatesGitCloneFailure(t *testing.T) {
	p := setupOnePackageInstallFailureTest(t, "clonefail")
	runFn = func(string, ...string) error { return errors.New("clone exploded") }

	err := Install([]string{"clonefail"}, p, Options{NonInteractive: true})
	if err == nil || !strings.Contains(err.Error(), "git clone failed") || !strings.Contains(err.Error(), "clone exploded") {
		t.Fatalf("error = %v, want wrapped clone failure", err)
	}
}

func TestInstallPropagatesGitFetchFailure(t *testing.T) {
	p := setupOnePackageInstallFailureTest(t, "fetchfail")
	reviewDir := p.ReviewDir("fetchfail")
	if err := os.MkdirAll(filepath.Join(reviewDir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	runCFn = func(dir, name string, args ...string) error {
		if name == "git" && len(args) >= 1 && args[0] == "fetch" {
			return errors.New("fetch exploded")
		}
		return nil
	}

	err := Install([]string{"fetchfail"}, p, Options{NonInteractive: true})
	if err == nil || !strings.Contains(err.Error(), "fetch exploded") {
		t.Fatalf("error = %v, want fetch failure", err)
	}
}

func TestInstallPropagatesBuildFailure(t *testing.T) {
	p := setupOnePackageInstallFailureTest(t, "buildfail")
	buildDirectoryFn = func(string, paths.Paths, bool, bool, bool) error {
		return errors.New("build exploded")
	}

	err := Install([]string{"buildfail"}, p, Options{NonInteractive: true})
	if err == nil || !strings.Contains(err.Error(), "build exploded") {
		t.Fatalf("error = %v, want build failure", err)
	}
}

func TestInstallPropagatesTarCheckFailure(t *testing.T) {
	p := setupOnePackageInstallFailureTest(t, "tarfail")
	tarCheck = func(string) error { return errors.New("tarcheck exploded") }

	err := Install([]string{"tarfail"}, p, Options{NonInteractive: true})
	if err == nil || !strings.Contains(err.Error(), "tarcheck exploded") {
		t.Fatalf("error = %v, want tarcheck failure", err)
	}
}

func TestInstallPropagatesPacmanInstallFailure(t *testing.T) {
	p := setupOnePackageInstallFailureTest(t, "pacmanfail")
	pacmanInstallLocalWithMode = func([]string, bool) error {
		return errors.New("pacman exploded")
	}

	err := Install([]string{"pacmanfail"}, p, Options{NonInteractive: true, InstallBuilt: true})
	if err == nil || !strings.Contains(err.Error(), "pacman -U failed") || !strings.Contains(err.Error(), "pacman exploded") {
		t.Fatalf("error = %v, want wrapped pacman failure", err)
	}
}
