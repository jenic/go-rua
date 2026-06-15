package pacman

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeExe(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVercmpAndCheckMissingAndIsRepo(t *testing.T) {
	bin := t.TempDir()
	// fake vercmp
	writeExe(t, bin, "vercmp", `
case "$1,$2" in
  1,2) echo -1 ;;
  2,2) echo 0 ;;
  3,2) echo 1 ;;
  *) echo 0 ;;
esac
`)
	// fake pacman for -T and -Si and -Q --foreign
	writeExe(t, bin, "pacman", `
if [ "$1" = "-T" ]; then
  # echo missing: a and c only
  shift
  for n in "$@"; do
    if [ "$n" = "a" ] || [ "$n" = "c" ]; then echo "$n"; fi
  done
  exit 0
fi
if [ "$1" = "-Si" ]; then
  if [ "$2" = "present" ]; then exit 0; else exit 1; fi
fi
if [ "$1" = "-Q" ] && [ "$2" = "--foreign" ]; then
  echo "foo 1.0"; echo "bar 2.0"; exit 0
fi
exit 1
`)
	// fake pacman-conf
	writeExe(t, bin, "pacman-conf", `
if [ "$1" = "IgnorePkg" ]; then echo "hold1"; echo "hold2"; exit 0; fi
exit 1
`)
	// fake sudo used by Install* funcs
	writeExe(t, bin, "sudofake", `
exit 0
`)

	t.Setenv("PATH", bin)
	t.Setenv("RUA_SUDO_COMMAND", filepath.Join(bin, "sudofake"))

	// Vercmp
	if v, err := Vercmp("1", "2"); err != nil || v != -1 {
		t.Fatalf("Vercmp 1<2 got %d err %v", v, err)
	}
	if v, err := Vercmp("2", "2"); err != nil || v != 0 {
		t.Fatalf("Vercmp 2=2 got %d err %v", v, err)
	}
	if v, err := Vercmp("3", "2"); err != nil || v != 1 {
		t.Fatalf("Vercmp 3>2 got %d err %v", v, err)
	}

	// CheckMissing
	miss, err := CheckMissing([]string{"a", "b", "c"})
	if err != nil {
		t.Fatalf("CheckMissing err: %v", err)
	}
	if len(miss) != 2 || miss[0] != "a" || miss[1] != "c" {
		t.Fatalf("unexpected missing: %v", miss)
	}

	// IsRepoPackage
	ok, err := IsRepoPackage("present")
	if err != nil || !ok {
		t.Fatalf("IsRepoPackage present failed: %v %v", ok, err)
	}
	ok, err = IsRepoPackage("absent")
	if err != nil || ok {
		t.Fatalf("IsRepoPackage absent expected false: %v %v", ok, err)
	}

	// GetForeignPackages
	f, err := GetForeignPackages()
	if err != nil || len(f) != 2 || f[0].Name == "" || f[1].Version == "" {
		t.Fatalf("GetForeignPackages unexpected: %+v, err=%v", f, err)
	}

	// GetIgnoredPackages
	ig, err := GetIgnoredPackages()
	if err != nil || len(ig) != 2 {
		t.Fatalf("GetIgnoredPackages unexpected: %v %v", ig, err)
	}

	// Installers: they should invoke our sudofake and exit 0
	if err := InstallRepoDeps([]string{"x"}); err != nil {
		t.Fatalf("InstallRepoDeps error: %v", err)
	}
	if err := InstallLocal([]string{"/tmp/a.pkg.tar.zst"}); err != nil {
		t.Fatalf("InstallLocal error: %v", err)
	}
	if err := InstallLocalWithMode([]string{"/tmp/a.pkg.tar.zst"}, true); err != nil {
		t.Fatalf("InstallLocalWithMode error: %v", err)
	}

	// SudoCommand default and override
	t.Setenv("RUA_SUDO_COMMAND", "my-sudo")
	if s := SudoCommand(); s != "my-sudo" {
		t.Fatalf("SudoCommand override failed: %s", s)
	}
	t.Setenv("RUA_SUDO_COMMAND", "")
	if s := SudoCommand(); s == "" {
		t.Fatalf("SudoCommand default empty")
	}
}

func TestCommandWrapperFailures(t *testing.T) {
	bin := t.TempDir()
	writeExe(t, bin, "vercmp", `exit 42`)
	writeExe(t, bin, "pacman", `exit 42`)
	writeExe(t, bin, "pacman-conf", `exit 42`)
	writeExe(t, bin, "sudofake", `exit 42`)

	t.Setenv("PATH", bin)
	t.Setenv("RUA_SUDO_COMMAND", filepath.Join(bin, "sudofake"))

	cases := []struct {
		name    string
		run     func() error
		wantErr string
	}{
		{
			name: "vercmp",
			run: func() error {
				_, err := Vercmp("1", "2")
				return err
			},
			wantErr: "vercmp failed",
		},
		{
			name: "check missing",
			run: func() error {
				_, err := CheckMissing([]string{"dep"})
				return err
			},
			wantErr: "pacman -T failed",
		},
		{
			name: "foreign packages",
			run: func() error {
				_, err := GetForeignPackages()
				return err
			},
			wantErr: "pacman -Q --foreign failed",
		},
		{
			name: "ignored packages",
			run: func() error {
				_, err := GetIgnoredPackages()
				return err
			},
			wantErr: "pacman-conf IgnorePkg failed",
		},
		{
			name:    "repo deps install",
			run:     func() error { return InstallRepoDeps([]string{"dep"}) },
			wantErr: "exit status 42",
		},
		{
			name:    "local install",
			run:     func() error { return InstallLocal([]string{"/tmp/pkg.pkg.tar.zst"}) },
			wantErr: "exit status 42",
		},
		{
			name:    "local install asdeps",
			run:     func() error { return InstallLocalWithMode([]string{"/tmp/pkg.pkg.tar.zst"}, true) },
			wantErr: "exit status 42",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestVercmpRejectsUnexpectedOutput(t *testing.T) {
	bin := t.TempDir()
	writeExe(t, bin, "vercmp", `echo wat`)
	t.Setenv("PATH", bin)

	_, err := Vercmp("1", "2")
	if err == nil || !strings.Contains(err.Error(), `unexpected vercmp output: "wat"`) {
		t.Fatalf("error = %v, want unexpected output error", err)
	}
}
