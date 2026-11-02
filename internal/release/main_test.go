package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArchive(t *testing.T) {
	packed, err := archive([]byte("binary"), []byte("readme"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := archive([]byte("binary"), []byte("readme"))
	if err != nil || !bytes.Equal(packed, other) {
		t.Fatal("archive is not deterministic", err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(packed))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	if !gz.ModTime.IsZero() || gz.Name != "" || gz.Comment != "" {
		t.Fatalf("unexpected gzip metadata: %+v", gz.Header)
	}
	tr := tar.NewReader(gz)
	for i, name := range []string{"go-rua", "README.md"} {
		header, err := tr.Next()
		if err != nil {
			t.Fatal(err)
		}
		mode := int64(0644)
		if i == 0 {
			mode = 0755
		}
		if header.Name != name || header.Mode != mode || header.Uid != 0 || header.Gid != 0 || header.ModTime.Unix() != 0 || header.Typeflag != tar.TypeReg {
			t.Fatalf("unexpected header: %+v", header)
		}
		body, err := io.ReadAll(tr)
		if err != nil || string(body) != []string{"binary", "readme"}[i] {
			t.Fatal("unexpected member content", err)
		}
	}
	if _, err := tr.Next(); err != io.EOF {
		t.Fatal("unexpected archive members", err)
	}
}

func TestRelease(t *testing.T) {
	for _, unstable := range []bool{false, true} {
		t.Run(fmt.Sprint(unstable), func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("readme"), 0644); err != nil {
				t.Fatal(err)
			}
			calls := 0
			caches := map[string]bool{}
			compile := func(_ string, output, cache, version string) error {
				calls++
				if caches[cache] || !strings.HasPrefix(cache, filepath.Join(root, ".gocache")+string(os.PathSeparator)) || version != "v1.2.3" {
					t.Fatal("builds must have separate workspace-local caches and the exact version")
				}
				caches[cache] = true
				data := "binary"
				if unstable {
					data += fmt.Sprint(calls)
				}
				return os.WriteFile(output, []byte(data), 0755)
			}
			err := release(root, "v1.2.3", true, compile)
			if (err != nil) != unstable || calls != 2 {
				t.Fatalf("calls=%d error=%v", calls, err)
			}
			if unstable {
				if _, err := os.Stat(filepath.Join(root, "dist", archiveName)); !os.IsNotExist(err) {
					t.Fatal("failed build must not publish output")
				}
				return
			}
			packed, err := os.ReadFile(filepath.Join(root, "dist", archiveName))
			if err != nil {
				t.Fatal(err)
			}
			sums, err := os.ReadFile(filepath.Join(root, "dist", "SHA256SUMS"))
			if err != nil || string(sums) != fmt.Sprintf("%x  %s\n", sha256.Sum256(packed), archiveName) {
				t.Fatal("invalid checksum manifest", err)
			}
		})
	}
}

func TestReleaseRejectsStaleAssets(t *testing.T) {
	root := t.TempDir()
	dist := filepath.Join(root, "dist")
	if err := os.Mkdir(dist, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dist, "provenance.sigstore.json"), []byte("old provenance"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := release(root, "v1.0.0", false, nil); err == nil {
		t.Fatal("must reject stale provenance before building")
	}
}

func TestVersions(t *testing.T) {
	for _, version := range []string{"dev", "v0.0.0", "v1.2.3", "v1.2.3-rc.1", "v2.0.0-0"} {
		if !validVersion(version) {
			t.Errorf("rejected %q", version)
		}
	}
	for _, version := range []string{"", "v01.0.0", "v1.0.0-01", "v1.0.0+meta", "v1.0.0\n", "v1.0.0 -X main.Version=bad"} {
		if validVersion(version) {
			t.Errorf("accepted %q", version)
		}
	}
}
