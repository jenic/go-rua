package tarcheck

import (
	"archive/tar"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTarCheckInteractiveReviewAndEOF(t *testing.T) {
	for _, tt := range []struct {
		input   string
		wantErr bool
	}{{"e\nl\nf\ns\ni\no\n", false}, {"", true}, {"q\n", true}} {
		t.Run(tt.input, func(t *testing.T) {
			SetInputForTests(strings.NewReader(tt.input))
			defer SetInputForTests(nil)
			err := TarCheck(fixturePath(t))
			if (err != nil) != tt.wantErr {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestTarCheckRejectsLinkedInstallBeforeApproval(t *testing.T) {
	for _, typeflag := range []byte{tar.TypeLink, tar.TypeSymlink} {
		t.Run(string(typeflag), func(t *testing.T) {
			data := archiveFixture(t, []*tar.Header{
				{Name: "usr/share/script", Mode: 0644, Typeflag: tar.TypeReg},
				{Name: "./.INSTALL", Mode: 0644, Typeflag: typeflag, Linkname: "usr/share/script"},
			}, []string{"post_install() { :; }\n", ""})
			path := filepath.Join(t.TempDir(), "app.pkg.tar")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			input := strings.NewReader("o\n")
			SetInputForTests(input)
			t.Cleanup(func() { SetInputForTests(nil) })
			err := TarCheck(path)
			if err == nil || !strings.Contains(err.Error(), "package metadata \".INSTALL\" must be a regular file") {
				t.Fatalf("linked install script not rejected: %v", err)
			}
			if input.Len() != len("o\n") {
				t.Fatal("malformed metadata reached the approval prompt")
			}
		})
	}
}
