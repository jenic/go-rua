package reviewstate

import (
	"go-rua/internal/tarcheck"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func record() Record {
	s := Snapshot{{Path: "PKGBUILD", Mode: 0644, Data: []byte("pkgname=app")}}
	return Record{Schema: 1, Policy: PolicyVersion, Base: "app", Commit: strings.Repeat("a", 40), Recipe: s, EffectiveRecipe: s, Artifacts: []tarcheck.Manifest{{Name: "app", Version: "2-1", SHA256: strings.Repeat("a", 64)}}, InstalledAt: time.Now().UTC().Format(time.RFC3339)}
}
func TestStorePendingAndConfirmedAreSeparate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := record()
	r.InstalledAt = ""
	if err := s.Save(r, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load("app", false); !os.IsNotExist(err) {
		t.Fatal("pending became installed", err)
	}
	if _, err := s.Load("app", true); err != nil {
		t.Fatal(err)
	}
	r.InstalledAt = time.Now().UTC().Format(time.RFC3339)
	if err := s.Save(r, false); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearPending("app"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load("app", false)
	if err != nil || got.Recipe.Digest() != r.Recipe.Digest() {
		t.Fatal(got, err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("concurrent session allowed")
	}
}
func TestStoreRejectsUnsafeState(t *testing.T) {
	for _, kind := range []string{"symlink", "public", "corrupt", "wrong-package"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			s, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			p := filepath.Join(dir, "app.json")
			switch kind {
			case "symlink":
				os.Symlink(filepath.Join(t.TempDir(), "outside"), p)
			case "public":
				os.WriteFile(p, []byte("{}"), 0644)
			case "corrupt":
				os.WriteFile(p, []byte("{"), 0600)
			case "wrong-package":
				r := record()
				r.Base = "other"
				s.Save(r, false)
				os.Rename(filepath.Join(dir, "other.json"), p)
			}
			if _, err := s.Load("app", false); err == nil {
				t.Fatal("unsafe record accepted")
			}
		})
	}
}
func TestSnapshotRejectsEscapesAndLinks(t *testing.T) {
	s := Snapshot{{Path: "../PKGBUILD", Mode: 0644, Data: []byte("x")}}
	if err := s.Validate(); err == nil {
		t.Fatal("path escape allowed")
	}
	dir := t.TempDir()
	os.Symlink("/etc/passwd", filepath.Join(dir, "PKGBUILD"))
	if _, err := Capture(dir, []string{"PKGBUILD"}); err == nil {
		t.Fatal("symlink captured")
	}
}
