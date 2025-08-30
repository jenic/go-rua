package main

import (
    "bytes"
    "encoding/json"
    "io"
    "net/http"
    "os"
    "strings"
    "testing"

    "go-rua/internal/aur"
    "go-rua/internal/pacman"
    installpkg "go-rua/internal/install"
)

type rtCLIFunc func(*http.Request) (*http.Response, error)

func (f rtCLIFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mrespCLI(status int, body string) *http.Response {
    return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewBufferString(body)), Header: make(http.Header)}
}

func captureOut(f func()) (string, string) {
    oldOut, oldErr := os.Stdout, os.Stderr
    defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
    r1, w1, _ := os.Pipe()
    r2, w2, _ := os.Pipe()
    os.Stdout, os.Stderr = w1, w2
    f()
    w1.Close(); w2.Close()
    b1, _ := io.ReadAll(r1)
    b2, _ := io.ReadAll(r2)
    return string(b1), string(b2)
}

func TestSearchCmd(t *testing.T) {
    // Stub AUR search
    aurSearchANDFn = func(terms []string) ([]aur.Package, error) {
        return []aur.Package{{Name: "foo", Version: "1", Description: "hello"}}, nil
    }
    out, _ := captureOut(func() { searchCmd([]string{"foo"}) })
    if !strings.Contains(out, "foo 1") || !strings.Contains(out, "hello") {
        t.Fatalf("unexpected search out: %q", out)
    }
}

func TestInfoCmdTextAndJSON(t *testing.T) {
    aurInfoFn = func(names []string) ([]aur.Package, error) {
        return []aur.Package{{
            Name: "pkg", Version: "1", Description: "desc", URL: "u", Maintainer: "m",
            Depends: []string{"a"}, MakeDepends: []string{"b"}, CheckDepends: []string{"c"}, OptDepends: []string{"o"},
            Provides: []string{"p"}, Conflicts: []string{"x"}, OutOfDate: 123,
        }}, nil
    }
    out, _ := captureOut(func() { infoCmd([]string{"pkg"}) })
    if !strings.Contains(out, "pkg 1") || !strings.Contains(out, "depends:") || !strings.Contains(out, "conflicts:") {
        t.Fatalf("unexpected info out: %q", out)
    }
    // JSON flag path
    out2, _ := captureOut(func() { infoCmd([]string{"--json", "pkg"}) })
    var js []aur.Package
    if json.Unmarshal([]byte(out2), &js) != nil || len(js) != 1 || js[0].Name != "pkg" {
        t.Fatalf("unexpected JSON out: %q", out2)
    }
}

func TestUpgradeCmdPlanPrints(t *testing.T) {
    // save and restore seams
    oldGetForeign := getForeignPkgsFn
    oldAurInfo := aurInfoFn
    oldVercmp := vercmpFn
    oldIgnored := getIgnoredPkgsFn
    oldPlan := installPlanFn
    oldSudo := pacmanSudoFn
    defer func() {
        getForeignPkgsFn = oldGetForeign
        aurInfoFn = oldAurInfo
        vercmpFn = oldVercmp
        getIgnoredPkgsFn = oldIgnored
        installPlanFn = oldPlan
        pacmanSudoFn = oldSudo
    }()
    // Stub findOutdated deps via seams used inside helpers
    getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
        return []pacman.ForeignPkg{{Name: "foo", Version: "1"}}, nil
    }
    aurInfoFn = func(names []string) ([]aur.Package, error) { return []aur.Package{{Name: "foo", Version: "2"}}, nil }
    vercmpFn = func(a, b string) (int, error) { return -1, nil }
    getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
    installPlanFn = func(names []string) (installpkg.Plan, error) {
        return installpkg.Plan{BuildOrder: names, RepoMissing: []string{"libx"}}, nil
    }
    pacmanSudoFn = func() string { return "sudo" }

    out, _ := captureOut(func() { upgradeCmd([]string{}) })
    if !strings.Contains(out, "Plan:") || !strings.Contains(out, "Build order: foo") {
        t.Fatalf("unexpected upgrade plan out: %q", out)
    }
}
