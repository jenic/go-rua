package main

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"go-rua/internal/aur"
)

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mockResp(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewBufferString(body)), Header: make(http.Header)}
}

func writeExe(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIsDevelPkg(t *testing.T) {
	if !isDevelPkg("foo-git") || isDevelPkg("foo") {
		t.Fatalf("isDevelPkg basic logic failed")
	}
}

func TestFindOutdatedAndListDetailed(t *testing.T) {
	// Fake pacman and vercmp
	bin := t.TempDir()
	writeExe(t, bin, "pacman", `
if [ "$1" = "-Q" ] && [ "$2" = "--foreign" ]; then
  echo "foo 1.0"; echo "devpkg-git 1.0"; echo "ghost 1.0"; exit 0
fi
if [ "$1" = "-Si" ]; then
  # pretend repos have only 'bar' available
  if [ "$2" = "bar" ]; then exit 0; else exit 1; fi
fi
exit 1
`)
	writeExe(t, bin, "vercmp", `
if [ "$1" = "$2" ]; then echo 0; else echo -1; fi
`)
	writeExe(t, bin, "pacman-conf", `
if [ "$1" = "IgnorePkg" ]; then echo "ignored"; exit 0; fi
`)
	os.Setenv("PATH", bin)

	// Mock AUR Info
	aur.SetHTTPClientForTests(&http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("type") == "info" {
			// Return info for foo, devpkg-git only; ghost missing
			body := `{"version":5,"type":"multiinfo","resultcount":2,"results":[{"Name":"foo","Version":"2.0","PackageBase":"foo"},{"Name":"devpkg-git","Version":"1.0","PackageBase":"devpkg-git"}]}`
			return mockResp(200, body), nil
		}
		return mockResp(404, ""), nil
	})})

	// Should mark foo outdated (1.0 -> 2.0), devpkg-git outdated only when devel=true, ghost nonexistent
	outdated, nonexistent, err := findOutdated(true, "")
	if err != nil {
		t.Fatalf("findOutdated error: %v", err)
	}
	if len(outdated) != 2 {
		t.Fatalf("expected two outdated (foo, devpkg-git), got %v", outdated)
	}
	if len(nonexistent) != 1 || nonexistent[0] != "ghost" {
		t.Fatalf("expected ghost nonexistent: %v", nonexistent)
	}

	items, non2, err := listOutdatedDetailed(true, "")
	if err != nil || len(items) != 2 || len(non2) != 1 {
		t.Fatalf("listOutdatedDetailed unexpected: items=%v non2=%v err=%v", items, non2, err)
	}
}

func TestInfoAndUsageHelpers(t *testing.T) {
	// Just ensure helpers don't panic
	buildDepsNote()
	infoUsage()
	upgradeUsage()
	searchUsage()
	installUsage()
	namcapUsage()
	shellcheckUsage()
	tarcheckUsage()
	builddirUsage()
}
