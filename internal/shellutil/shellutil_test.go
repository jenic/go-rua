package shellutil

import (
	"os"
	"path/filepath"
	"testing"

	"go-rua/internal/paths"
)

func TestShellcheckMissingFile(t *testing.T) {
	err := Shellcheck(filepath.Join(t.TempDir(), "nope"), paths.Paths{})
	if err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestNamcapMissingFile(t *testing.T) {
	d := t.TempDir()
	// ensure directory exists but no PKGBUILD inside
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Namcap(filepath.Join(d, "PKGBUILD"), paths.Paths{}); err == nil {
		t.Fatalf("expected error for missing PKGBUILD")
	}
}
