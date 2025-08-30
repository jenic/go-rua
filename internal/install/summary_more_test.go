package install

import (
	"os"
	"path/filepath"
	"testing"

	"go-rua/internal/aur"
)

func TestSummarizeForAURClassifiesDeps(t *testing.T) {
	// Fake pacman: -T returns both missing; -Si returns repo for a, not for b
	bin := t.TempDir()
	write := func(name, body string) {
		p := filepath.Join(bin, name)
		_ = os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755)
	}
	write("pacman", `
if [ "$1" = "-T" ]; then for n in "$@"; do echo "$n"; done; exit 0; fi
if [ "$1" = "-Si" ]; then if [ "$2" = "a" ]; then exit 0; else exit 1; fi; fi
exit 1
`)
	os.Setenv("PATH", bin)

	// Prepare AUR info with deps a and b
	infos := []aur.Package{{Name: "pkg", Depends: []string{"a>=1", "b"}}}
	s, err := SummarizeForAUR([]string{"pkg"}, infos)
	if err != nil {
		t.Fatalf("SummarizeForAUR err: %v", err)
	}
	if len(s.RepoMissing) != 1 || s.RepoMissing[0] != "a" || len(s.Unknown) != 1 || s.Unknown[0] != "b" {
		t.Fatalf("unexpected classification: %+v", s)
	}
}
