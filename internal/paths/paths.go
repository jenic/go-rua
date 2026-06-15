package paths

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Paths holds the directories used by go-rua
type Paths struct {
	ConfigDir       string // ~/.config/rua
	CacheBuildDir   string // ~/.cache/rua/build
	DataCheckedTars string // ~/.local/share/rua/checked_tars
}

// allow tests to stub the makepkg presence check
var makepkgCheck = func() error { _, err := os.Stat("/usr/bin/makepkg"); return err }

// MustInit prepares directories and returns paths. It also checks that makepkg exists.
func MustInit() Paths {
	p := MustInitNoMakepkgChecks()
	if err := makepkgCheck(); err != nil {
		fatalf("makepkg not found: %v", err)
	}
	return p
}

// SetMakepkgCheckForTests overrides the makepkg existence check.
func SetMakepkgCheckForTests(fn func() error) { makepkgCheck = fn }

// MustInitNoMakepkgChecks prepares directories and returns paths without makepkg checks.
func MustInitNoMakepkgChecks() Paths {
	home, _ := os.UserHomeDir()
	cfgBase := getenvDefault("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	cacheBase := getenvDefault("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	dataBase := getenvDefault("XDG_DATA_HOME", filepath.Join(home, ".local", "share"))

	cfg := filepath.Join(cfgBase, "rua")
	build := filepath.Join(cacheBase, "rua", "build")
	checked := filepath.Join(dataBase, "rua", "checked_tars")

	mustMkdirAll(cfg)
	mustMkdirAll(build)
	mustMkdirAll(checked)

	return Paths{
		ConfigDir:       cfg,
		CacheBuildDir:   abs(build),
		DataCheckedTars: abs(checked),
	}
}

// ReviewDir returns user review dir for pkgbase
func (p Paths) ReviewDir(pkgbase string) string {
	d := filepath.Join(p.ConfigDir, "pkg", pkgbase)
	mustMkdirAll(filepath.Dir(d))
	mustMkdirAll(d)
	return d
}

// BuildDir returns build dir for pkgbase
func (p Paths) BuildDir(pkgbase string) string {
	d := filepath.Join(p.CacheBuildDir, pkgbase)
	mustMkdirAll(d)
	return d
}

// CheckedTarsDir returns checked_tars dir for pkgbase
func (p Paths) CheckedTarsDir(pkgbase string) string {
	d := filepath.Join(p.DataCheckedTars, pkgbase)
	mustMkdirAll(d)
	return d
}

func getenvDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func mustMkdirAll(p string) {
	if err := os.MkdirAll(p, 0o700); err != nil {
		panic(err)
	}
	if err := os.Chmod(p, 0o700); err != nil {
		panic(err)
	}
}

func abs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}

func fatalf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if strings.Contains(msg, "/usr/bin/makepkg") {
		msg = msg + "\nHint: install base-devel and makepkg."
	}
	panic(errors.New(msg))
}
