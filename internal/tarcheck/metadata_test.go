package tarcheck

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"go-rua/internal/review"
)

var metadataNames = []string{".PKGINFO", ".BUILDINFO", ".MTREE", ".INSTALL", ".CHANGELOG"}

func TestMetadataRejectsNonregularEntries(t *testing.T) {
	for _, name := range metadataNames {
		for _, prefix := range []string{"", "./"} {
			for _, kind := range []struct {
				name     string
				typeflag byte
			}{{"hardlink", tar.TypeLink}, {"symlink", tar.TypeSymlink}, {"directory", tar.TypeDir}, {"fifo", tar.TypeFifo}, {"device", tar.TypeChar}} {
				for _, targetFirst := range []bool{true, false} {
					order := "target-first"
					if !targetFirst {
						order = "metadata-first"
					}
					t.Run(name+"/"+prefix+kind.name+"/"+order, func(t *testing.T) {
						target := &tar.Header{Name: "usr/share/script", Mode: 0644, Typeflag: tar.TypeReg}
						metadata := &tar.Header{Name: prefix + name, Mode: 0644, Typeflag: kind.typeflag}
						if kind.typeflag == tar.TypeLink || kind.typeflag == tar.TypeSymlink {
							metadata.Linkname = target.Name
						}
						headers := []*tar.Header{metadata, target}
						bodies := []string{"", "post_install() { :; }\n"}
						if targetFirst {
							headers = []*tar.Header{target, metadata}
							bodies = []string{bodies[1], ""}
						}
						var data []byte
						if name == ".PKGINFO" {
							data = tarFixture(t, headers, bodies)
						} else {
							data = archiveFixture(t, headers, bodies)
						}
						_, _, err := ReadManifest(bytes.NewReader(data))
						if err == nil || !strings.Contains(err.Error(), "package metadata \""+name+"\" must be a regular file") {
							t.Fatalf("expected metadata type rejection for %s, got %v", name, err)
						}
					})
				}
			}
		}
	}
}

func TestMetadataAcceptsRegularEntriesAndOrdinaryLinks(t *testing.T) {
	for _, prefix := range []string{"", "./"} {
		for _, typeflag := range []byte{tar.TypeReg, tar.TypeRegA} {
			t.Run(prefix+string(typeflag), func(t *testing.T) {
				var headers []*tar.Header
				bodies := []string{"pkgname = app\npkgver = 2-1\narch = any\n", "build info", "mtree data", "post_install() { :; }\n", "changelog"}
				for _, name := range metadataNames {
					headers = append(headers, &tar.Header{Name: prefix + name, Mode: 0644, Typeflag: typeflag})
				}
				headers = append(headers,
					&tar.Header{Name: "usr/share/data", Mode: 0644, Typeflag: tar.TypeReg},
					&tar.Header{Name: "usr/share/hardlink", Mode: 0644, Typeflag: tar.TypeLink, Linkname: "usr/share/data"},
					&tar.Header{Name: "usr/share/symlink", Mode: 0644, Typeflag: tar.TypeSymlink, Linkname: "data"})
				bodies = append(bodies, "payload", "", "")
				m, r, err := ReadManifest(bytes.NewReader(tarFixture(t, headers, bodies)))
				if err != nil || r.Has(review.Block) || r.Has(review.Review) {
					t.Fatalf("valid archive rejected: %v %+v", err, r)
				}
				if m.Install != bodies[3] || len(m.Files) != len(headers) {
					t.Fatalf("lost metadata or ordinary links: %+v", m)
				}
			})
		}
	}
	_, _, err := ReadManifest(bytes.NewReader(archiveFixture(t, nil, nil)))
	if err != nil {
		t.Fatalf("optional metadata required: %v", err)
	}
}

func TestMetadataDuplicateAliasesRejected(t *testing.T) {
	for _, name := range metadataNames {
		t.Run(name, func(t *testing.T) {
			headers := []*tar.Header{{Name: name, Mode: 0644, Typeflag: tar.TypeReg}, {Name: "./" + name, Mode: 0644, Typeflag: tar.TypeReg}}
			body := "metadata"
			if name == ".PKGINFO" {
				body = "pkgname = app\npkgver = 2-1\narch = any\n"
			}
			data := tarFixture(t, headers, []string{body, body})
			_, _, err := ReadManifest(bytes.NewReader(data))
			if err == nil || !strings.Contains(err.Error(), "duplicate archive path") {
				t.Fatalf("duplicate metadata accepted: %v", err)
			}
		})
	}
}

func TestMetadataAcceptsLegacyRegularEncoding(t *testing.T) {
	// archive/tar.Writer promotes TypeRegA to TypeReg. Set the legacy flag in
	// the serialized .INSTALL header and recompute its tar header checksum.
	body := "post_install() { :; }\n"
	data := tarFixture(t, []*tar.Header{{Name: ".INSTALL", Mode: 0644, Typeflag: tar.TypeReg}}, []string{body})
	data[156] = tar.TypeRegA
	for i := 148; i < 156; i++ {
		data[i] = ' '
	}
	sum := 0
	for _, b := range data[:512] {
		sum += int(b)
	}
	copy(data[148:156], fmt.Appendf(nil, "%06o\x00 ", sum))
	metadata := "pkgname = app\npkgver = 2-1\narch = any\n"
	// Put .PKGINFO before the legacy entry, using one shared archive terminator.
	prefix := tarFixture(t, []*tar.Header{{Name: ".PKGINFO", Mode: 0644, Typeflag: tar.TypeReg}}, []string{metadata})
	data = append(prefix[:len(prefix)-1024], data...)
	m, _, err := ReadManifest(bytes.NewReader(data))
	if err != nil || m.Install != body {
		t.Fatalf("legacy regular metadata rejected: %v %+v", err, m)
	}
}

func TestMetadataSizeLimitPreserved(t *testing.T) {
	for _, name := range []string{".PKGINFO", ".INSTALL"} {
		t.Run(name, func(t *testing.T) {
			var b bytes.Buffer
			w := tar.NewWriter(&b)
			if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0644, Typeflag: tar.TypeReg, Size: maxMetadata + 1}); err != nil {
				t.Fatal(err)
			}
			// Supply only the header: rejection must precede reading the body.
			_, _, err := ReadManifest(bytes.NewReader(b.Bytes()))
			if err == nil || !strings.Contains(err.Error(), "package metadata exceeds limit") {
				t.Fatalf("oversized metadata not rejected before reading: %v", err)
			}
		})
	}
}

func TestCompareBlocksNonregularMetadata(t *testing.T) {
	for _, name := range metadataNames {
		for _, typeflag := range []byte{tar.TypeLink, tar.TypeSymlink, tar.TypeDir, tar.TypeFifo, tar.TypeChar} {
			t.Run(name+"/"+string(typeflag), func(t *testing.T) {
				m := Manifest{Files: []File{{Path: name, Type: typeflag}}}
				r := Compare(m, nil, nil, nil, func(string) (os.FileInfo, error) {
					t.Fatal("package metadata must not be inspected as a host filesystem path")
					return nil, nil
				})
				if len(r.Findings) != 1 || r.Findings[0].Rule != "metadata-type" || r.Findings[0].Action != review.Block || r.Findings[0].Location != name {
					t.Fatalf("invalid metadata not blocked: %+v", r)
				}
			})
		}
	}
}

func TestCompareInstallScriptLifecycle(t *testing.T) {
	for _, tt := range []struct {
		name, before, after string
		baseline            bool
		action              review.Action
		evidence            string
	}{
		{"new", "", "post_install() { :; }", false, review.Review, "post_install() { :; }"},
		{"changed", "old script", "new script", true, review.Review, "new script"},
		{"unchanged", "same script", "same script", true, review.Info, "same script"},
		{"empty", "", "", false, "", ""},
		{"emptied", "old script", "", true, review.Info, "install script removed"},
		{"removed", "old script", "", true, review.Info, "install script removed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var headers []*tar.Header
			var bodies []string
			if tt.name != "removed" {
				headers = []*tar.Header{{Name: ".INSTALL", Mode: 0644, Typeflag: tar.TypeReg}}
				bodies = []string{tt.after}
			}
			m, _, err := ReadManifest(bytes.NewReader(archiveFixture(t, headers, bodies)))
			if err != nil {
				t.Fatal(err)
			}
			var old *Manifest
			if tt.baseline {
				old = &Manifest{Install: tt.before}
			}
			r := Compare(m, old, nil, nil, nil)
			if tt.action == "" {
				if len(r.Findings) != 0 {
					t.Fatalf("empty script produced findings: %+v", r)
				}
				return
			}
			if len(r.Findings) != 1 || r.Findings[0] != (review.Finding{Rule: "install-script", Action: tt.action, Location: ".INSTALL", Evidence: tt.evidence}) {
				t.Fatalf("wrong script finding: %+v", r)
			}
		})
	}
}
