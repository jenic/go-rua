package tarcheck

import (
	"archive/tar"
	"bytes"
	"go-rua/internal/review"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func archiveFixture(t *testing.T, headers []*tar.Header, bodies []string) []byte {
	t.Helper()
	meta := "pkgname = app\npkgbase = app\npkgver = 2-1\narch = any\n"
	headers = append([]*tar.Header{{Name: ".PKGINFO", Mode: 0644, Typeflag: tar.TypeReg}}, headers...)
	bodies = append([]string{meta}, bodies...)
	return tarFixture(t, headers, bodies)
}

// tarFixture lets metadata tests supply .PKGINFO itself without a duplicate entry.
func tarFixture(t *testing.T, headers []*tar.Header, bodies []string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for i, h := range headers {
		h.Size = int64(len(bodies[i]))
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(bodies[i])); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func fixturePath(t *testing.T) string {
	t.Helper()
	data := archiveFixture(t, []*tar.Header{{Name: "usr/bin/app", Mode: 04755, Typeflag: tar.TypeReg}, {Name: ".INSTALL", Mode: 0644, Typeflag: tar.TypeReg}}, []string{"binary", "install script"})
	p := filepath.Join(t.TempDir(), "app.pkg.tar")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestInspectStructuredArchive(t *testing.T) {
	m, _, err := Inspect(fixturePath(t))
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "app" || m.Version != "2-1" || m.Install != "install script" || len(m.SHA256) != 64 || len(m.Files) != 3 {
		t.Fatalf("bad manifest: %+v", m)
	}
	if m.Files[2].Mode != 04755 || m.Files[2].SHA256 == "" {
		t.Fatal("privilege bits or content digest lost")
	}
}
func TestArchiveRejectsUnsafeStructures(t *testing.T) {
	for _, tt := range []struct {
		name    string
		headers []*tar.Header
		bodies  []string
	}{
		{"traversal", []*tar.Header{{Name: "../outside", Typeflag: tar.TypeReg}}, []string{""}},
		{"absolute", []*tar.Header{{Name: "/etc/evil", Typeflag: tar.TypeReg}}, []string{""}},
		{"duplicate", []*tar.Header{{Name: "usr/a", Typeflag: tar.TypeReg}, {Name: "usr/a", Typeflag: tar.TypeReg}}, []string{"", ""}},
		{"symlink ancestor", []*tar.Header{{Name: "usr", Typeflag: tar.TypeSymlink, Linkname: "etc"}, {Name: "usr/a", Typeflag: tar.TypeReg}}, []string{"", ""}},
		{"hardlink missing", []*tar.Header{{Name: "usr/a", Typeflag: tar.TypeLink, Linkname: "usr/b"}}, []string{""}},
		{"device", []*tar.Header{{Name: "dev/a", Typeflag: tar.TypeChar}}, []string{""}},
		{"newline", []*tar.Header{{Name: "usr/a\nb", Typeflag: tar.TypeReg}}, []string{""}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := archiveFixture(t, tt.headers, tt.bodies)
			if _, _, err := ReadManifest(bytes.NewReader(data)); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}
func TestArchiveSpacesLinksAndTrailingData(t *testing.T) {
	data := archiveFixture(t, []*tar.Header{{Name: "usr/share/a b", Mode: 0644, Typeflag: tar.TypeReg}, {Name: "usr/share/link", Typeflag: tar.TypeSymlink, Linkname: "a b"}}, []string{"data", ""})
	m, _, err := ReadManifest(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 3 {
		t.Fatal(m)
	}
	if _, _, err := ReadManifest(bytes.NewReader(append(data, []byte("hidden archive")...))); err == nil {
		t.Fatal("trailing data accepted")
	}
	if _, _, err := ReadManifest(bytes.NewReader(data[:700])); err == nil {
		t.Fatal("truncated archive accepted")
	}
}
func TestCompareSeparatesAddedAbsentAndConflict(t *testing.T) {
	m := Manifest{Name: "app", Files: []File{{Path: "usr/bin/new", Mode: 04755, Type: tar.TypeReg}, {Path: "etc/conflict", Mode: 0644, Type: tar.TypeReg}, {Path: "usr/share/missing", Mode: 0644, Type: tar.TypeReg}}}
	old := &Manifest{Files: []File{{Path: "usr/share/missing", Mode: 0644, Type: tar.TypeReg}, {Path: "usr/share/removed", Mode: 0644, Type: tar.TypeReg}}}
	stat := func(p string) (os.FileInfo, error) {
		if strings.HasSuffix(p, "conflict") {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	r := Compare(m, old, nil, map[string][]string{"etc/conflict": {"other"}}, stat)
	seen := map[string]bool{}
	for _, f := range r.Findings {
		seen[f.Rule+":"+f.Location] = true
	}
	if !r.Has(review.Block) || !seen["privileged:usr/bin/new"] || !seen["absent:usr/share/missing"] || seen["added:usr/share/missing"] || !seen["removed:usr/share/removed"] {
		t.Fatalf("bad comparison: %+v", r)
	}
}
