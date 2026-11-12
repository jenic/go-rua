// Command release builds deterministic Linux amd64 release archives.
// It is maintainer tooling and is never called by the go-rua executable.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/buildinfo"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"time"
)

const archiveName = "go-rua_linux_amd64.tar.gz"

func main() {
	version := flag.String("version", "dev", "release version")
	verify := flag.Bool("verify", false, "build twice with independent caches and compare all outputs")
	flag.Parse()
	root, err := os.Getwd()
	if err == nil {
		err = release(root, *version, *verify, build)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(1)
	}
}

func validVersion(version string) bool {
	number := `(0|[1-9][0-9]*)`
	identifier := `(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)`
	return version == "dev" || regexp.MustCompile(`^v`+number+`\.`+number+`\.`+number+`(-`+identifier+`(\.`+identifier+`)*)?$`).MatchString(version)
}

func build(root, output, cache, version string) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return fmt.Errorf("release builds require a Linux amd64 host and native C compiler")
	}
	goTool := os.Getenv("GO")
	if goTool == "" {
		goTool = "go"
	}
	cmd := exec.Command(goTool, "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-buildmode=pie",
		"-ldflags", "-s -w -buildid= -X main.Version="+version, "-o", output, "./cmd/go-rua")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=1", "GOOS=linux", "GOARCH=amd64", "GOCACHE="+cache)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	return verifyCompiler(output, runtime.Version())
}

func verifyCompiler(binary, expected string) error {
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		return fmt.Errorf("read release compiler: %w", err)
	}
	if info.GoVersion != expected {
		return fmt.Errorf("release compiler %q does not match verified builder %q", info.GoVersion, expected)
	}
	return nil
}

func archive(binary, readme []byte) ([]byte, error) {
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	tw := tar.NewWriter(gz)
	for _, member := range []struct {
		name string
		mode int64
		data []byte
	}{{"go-rua", 0755, binary}, {"README.md", 0644, readme}} {
		if err := tw.WriteHeader(&tar.Header{
			Name: member.name, Mode: member.mode, Size: int64(len(member.data)),
			ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR,
		}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(member.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

type buildFunc func(root, output, cache, version string) error

func release(root, version string, verify bool, compile buildFunc) error {
	if !validVersion(version) {
		return fmt.Errorf("expected dev or a v-prefixed SemVer version without build metadata")
	}
	dist := filepath.Join(root, "dist")
	if info, err := os.Lstat(dist); err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
		return fmt.Errorf("dist must be a real directory")
	}
	if err := os.MkdirAll(dist, 0755); err != nil {
		return err
	}
	entries, err := os.ReadDir(dist)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != archiveName && entry.Name() != "SHA256SUMS" {
			return fmt.Errorf("unexpected existing release asset: %s", entry.Name())
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("invalid existing release asset: %s", entry.Name())
		}
	}
	cacheRoot := filepath.Join(root, ".gocache")
	if err := os.MkdirAll(cacheRoot, 0755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(cacheRoot, "release-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		return err
	}
	count := 1
	if verify {
		count = 2
	}
	var previousBinary, previousArchive, previousManifest []byte
	for i := 0; i < count; i++ {
		dir := filepath.Join(stage, fmt.Sprintf("build-%d", i))
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
		binaryPath := filepath.Join(dir, "go-rua")
		if err := compile(root, binaryPath, filepath.Join(dir, "cache"), version); err != nil {
			return fmt.Errorf("build %d: %w", i+1, err)
		}
		binary, err := os.ReadFile(binaryPath)
		if err != nil {
			return err
		}
		packed, err := archive(binary, readme)
		if err != nil {
			return err
		}
		manifest := fmt.Appendf(nil, "%x  %s\n", sha256.Sum256(packed), archiveName)
		if i > 0 && (!bytes.Equal(binary, previousBinary) || !bytes.Equal(packed, previousArchive) || !bytes.Equal(manifest, previousManifest)) {
			return fmt.Errorf("release binaries or archives are not reproducible")
		}
		previousBinary, previousArchive, previousManifest = binary, packed, manifest
	}
	// Stage outputs before replacing existing unsigned artifacts; failed builds leave them intact.
	for _, asset := range []struct {
		name string
		data []byte
	}{{archiveName, previousArchive}, {"SHA256SUMS", previousManifest}} {
		staged := filepath.Join(stage, asset.name)
		if err := os.WriteFile(staged, asset.data, 0644); err != nil {
			return err
		}
		if err := os.Rename(staged, filepath.Join(dist, asset.name)); err != nil {
			return err
		}
	}
	fmt.Println(archiveName)
	return nil
}
