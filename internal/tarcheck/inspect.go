package tarcheck

import (
	"archive/tar"
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"go-rua/internal/review"
	"go-rua/internal/sandbox"
	"golang.org/x/sys/unix"
)

const maxArchiveBytes int64 = 32 << 30
const maxEntries = 250000
const maxMetadata = 4 << 20

type File struct {
	Path   string `json:"path"`
	Type   byte   `json:"type"`
	Mode   int64  `json:"mode"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
	Size   int64  `json:"size"`
	Link   string `json:"link,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}
type Manifest struct {
	Name    string `json:"name"`
	Base    string `json:"base"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	SHA256  string `json:"sha256"`
	Files   []File `json:"files"`
	Install string `json:"install,omitempty"`
}

func IsArtifact(name string) bool {
	for _, ext := range []string{".pkg.tar", ".pkg.tar.gz", ".pkg.tar.gzip", ".pkg.tar.xz", ".pkg.tar.zst", ".pkg.tar.zstd"} {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}
func Digest(name string) (string, error) {
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() || st.Size() > maxArchiveBytes {
		return "", fmt.Errorf("invalid artifact type or size")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxArchiveBytes+1))
	if err != nil {
		return "", err
	}
	if n > maxArchiveBytes {
		return "", fmt.Errorf("artifact exceeds size limit")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func Inspect(name string) (Manifest, review.Report, error) {
	var m Manifest
	var report review.Report
	abs, err := filepath.Abs(name)
	if err != nil {
		return m, report, err
	}
	before, err := Digest(abs)
	if err != nil {
		return m, report, err
	}
	read := func(r io.Reader) error { var e error; m, report, e = ReadManifest(r); return e }
	var argv []string
	switch {
	case strings.HasSuffix(abs, ".gz"), strings.HasSuffix(abs, ".gzip"):
		argv = []string{"gzip", "-dc", "--", abs}
	case strings.HasSuffix(abs, ".xz"):
		argv = []string{"xz", "--memlimit-decompress=256MiB", "-dc", "--", abs}
	case strings.HasSuffix(abs, ".zst"), strings.HasSuffix(abs, ".zstd"):
		argv = []string{"zstd", "--memory=256MB", "-dc", "--", abs}
	case strings.HasSuffix(abs, ".tar"):
		f, e := os.Open(abs)
		if e != nil {
			return m, report, e
		}
		err = read(f)
		f.Close()
	default:
		return m, report, fmt.Errorf("unsupported package archive %q", abs)
	}
	if argv != nil {
		cfg := sandbox.Config{RO: []string{"/etc", filepath.Dir(abs)}, ROX: []string{"/usr", "/bin", "/lib", "/lib64"}}
		err = sandbox.ReadStream(cfg, argv, read)
	}
	if err != nil {
		return m, report, fmt.Errorf("inspect archive: %w", err)
	}
	after, err := Digest(abs)
	if err != nil {
		return m, report, err
	}
	if before != after {
		return m, report, fmt.Errorf("artifact changed during inspection")
	}
	m.SHA256 = before
	return m, report, nil
}

// ReadManifest inspects tar bytes without extracting anything to disk.
func ReadManifest(input io.Reader) (Manifest, review.Report, error) {
	var m Manifest
	var report review.Report
	tail := &archiveTail{r: input}
	limited := &io.LimitedReader{R: tail, N: maxArchiveBytes + 1}
	r := tar.NewReader(limited)
	seen := map[string]File{}
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return m, report, err
		}
		if len(seen) >= maxEntries {
			return m, report, fmt.Errorf("too many archive entries")
		}
		name := strings.TrimPrefix(h.Name, "./")
		name = strings.TrimSuffix(name, "/")
		if (name == "" || name == ".") && h.Typeflag == tar.TypeDir {
			continue
		}
		if !safePath(name) {
			return m, report, fmt.Errorf("unsafe archive path %q", h.Name)
		}
		if _, ok := seen[name]; ok {
			return m, report, fmt.Errorf("duplicate archive path %q", name)
		}
		if err := validateMetadataType(name, h.Typeflag); err != nil {
			return m, report, err
		}
		f := File{Path: name, Type: h.Typeflag, Mode: h.Mode, UID: h.Uid, GID: h.Gid, Size: h.Size, Link: h.Linkname}
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			f.Type = tar.TypeReg
			hash := sha256.New()
			if name == ".PKGINFO" || name == ".INSTALL" {
				if h.Size > maxMetadata {
					return m, report, fmt.Errorf("package metadata exceeds limit")
				}
				data, e := io.ReadAll(io.TeeReader(r, hash))
				if e != nil {
					return m, report, e
				}
				if name == ".INSTALL" {
					m.Install = string(data)
				} else if e := packageInfo(data, &m); e != nil {
					return m, report, e
				}
			} else if _, e := io.Copy(hash, r); e != nil {
				return m, report, e
			}
			f.SHA256 = hex.EncodeToString(hash.Sum(nil))
		case tar.TypeDir:
		case tar.TypeSymlink:
			if f.Link == "" || strings.ContainsAny(f.Link, "\x00\r\n") {
				return m, report, fmt.Errorf("invalid symlink %q", name)
			}
			resolved := path.Clean(path.Join(path.Dir(name), f.Link))
			if strings.HasPrefix(f.Link, "/") {
				report.Add("absolute-symlink", review.Review, name, "absolute symlink target: "+f.Link)
			} else if !safePath(resolved) {
				return m, report, fmt.Errorf("symlink escapes package root: %q", name)
			}
		case tar.TypeLink:
			f.Link = strings.TrimPrefix(f.Link, "./")
			if !safePath(f.Link) {
				return m, report, fmt.Errorf("unsafe hardlink %q", name)
			}
		default:
			return m, report, fmt.Errorf("unsupported archive entry type at %q", name)
		}
		for key := range h.PAXRecords {
			if strings.Contains(key, "xattr") || strings.Contains(key, "acl") {
				report.Add("extended-permissions", review.Review, name, "extended permission metadata: "+key)
			}
		}
		seen[name] = f
		m.Files = append(m.Files, f)
	}
	// Consume padding to check decompressor errors and reject hidden trailing data.
	buf := make([]byte, 32*1024)
	for {
		n, err := limited.Read(buf)
		for _, b := range buf[:n] {
			if b != 0 {
				return m, report, fmt.Errorf("nonzero data after tar end")
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return m, report, err
		}
	}
	if limited.N == 0 {
		return m, report, fmt.Errorf("expanded archive exceeds limit")
	}
	if tail.n < 1024 || tail.n%512 != 0 {
		return m, report, fmt.Errorf("truncated tar end markers")
	}
	for _, b := range tail.last {
		if b != 0 {
			return m, report, fmt.Errorf("missing tar end markers")
		}
	}
	if m.Name == "" || m.Version == "" || m.Arch == "" {
		return m, report, fmt.Errorf("missing package identity in .PKGINFO")
	}
	for _, f := range m.Files {
		for p := path.Dir(f.Path); p != "."; p = path.Dir(p) {
			if parent, ok := seen[p]; ok && parent.Type != tar.TypeDir {
				return m, report, fmt.Errorf("non-directory archive ancestor %q", p)
			}
		}
		if f.Type == tar.TypeLink {
			target, ok := seen[f.Link]
			if !ok || target.Type != tar.TypeReg {
				return m, report, fmt.Errorf("hardlink target is not a regular archive member: %q", f.Path)
			}
			if f.Mode != target.Mode || f.UID != target.UID || f.GID != target.GID {
				report.Add("hardlink-permissions", review.Review, f.Path, "hardlink metadata differs from target "+f.Link)
			}
		}
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	return m, report, nil
}

// archive/tar permits EOF without end markers. Package inspection requires them.
type archiveTail struct {
	r    io.Reader
	n    int64
	last [1024]byte
}

func (t *archiveTail) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	t.n += int64(n)
	if n >= len(t.last) {
		copy(t.last[:], p[n-len(t.last):n])
	} else if n > 0 {
		copy(t.last[:], t.last[n:])
		copy(t.last[len(t.last)-n:], p[:n])
	}
	return n, err
}
func safePath(s string) bool {
	return s != "" && s != "." && path.Clean(s) == s && !strings.HasPrefix(s, "/") && s != ".." && !strings.HasPrefix(s, "../") && !strings.ContainsAny(s, "\x00\r\n")
}
func packageInfo(data []byte, m *Manifest) error {
	seen := map[string]bool{}
	s := bufio.NewScanner(strings.NewReader(string(data)))
	for s.Scan() {
		k, v, ok := strings.Cut(s.Text(), " = ")
		if !ok {
			continue
		}
		var target *string
		switch k {
		case "pkgname":
			target = &m.Name
		case "pkgbase":
			target = &m.Base
		case "pkgver":
			target = &m.Version
		case "arch":
			target = &m.Arch
		default:
			continue
		}
		if seen[k] || v == "" || strings.ContainsAny(v, "\x00\t\r\n /\\") {
			return fmt.Errorf("invalid package metadata %s", k)
		}
		seen[k] = true
		*target = v
	}
	return s.Err()
}

// Compare distinguishes package changes, disk absence, and ownership conflicts.
func Compare(m Manifest, old *Manifest, installedFiles map[string]bool, owners map[string][]string, stat func(string) (os.FileInfo, error)) review.Report {
	var r review.Report
	previous := map[string]File{}
	if old != nil {
		for _, f := range old.Files {
			previous[f.Path] = f
		}
	}
	current := map[string]bool{}
	for _, f := range m.Files {
		if packageMetadata(f.Path) {
			if err := validateMetadataType(f.Path, f.Type); err != nil {
				r.Add("metadata-type", review.Block, f.Path, err.Error())
			}
			continue
		}
		if f.Type == tar.TypeDir {
			if f.Mode&0002 != 0 {
				r.Add("world-writable", review.Review, f.Path, "world-writable directory")
			}
			if f.Mode&06000 != 0 {
				r.Add("privileged-directory", review.Review, f.Path, fmt.Sprintf("directory SUID/SGID mode %04o", f.Mode))
			}
			if previous, ok := previous[f.Path]; ok && previous.Type != tar.TypeDir {
				r.Add("file-metadata", review.Review, f.Path, "file changed to directory")
			}
			continue
		}
		current[f.Path] = true
		before, known := previous[f.Path]
		added := !installedFiles[f.Path]
		if old != nil {
			added = !known
		}
		if added {
			r.Add("added", review.Info, f.Path, "added to package")
		}
		if _, err := stat("/" + f.Path); os.IsNotExist(err) {
			r.Add("absent", review.Info, f.Path, "absent from disk")
		} else if err != nil {
			r.Add("stat-failed", review.Block, f.Path, "cannot inspect disk path: "+err.Error())
		} else {
			owned := owners[f.Path]
			if len(owned) == 0 {
				r.Add("unowned", review.Review, f.Path, "existing path is unowned")
			}
			for _, owner := range owned {
				if owner != m.Name {
					r.Add("ownership", review.Block, f.Path, "existing path belongs to "+owner)
				}
			}
		}
		if f.Mode&06000 != 0 {
			action := review.Review
			if known && before.Mode&06000 == f.Mode&06000 {
				action = review.Info
			}
			r.Add("privileged", action, f.Path, fmt.Sprintf("SUID/SGID mode %04o", f.Mode))
		}
		if f.Mode&0002 != 0 {
			r.Add("world-writable", review.Review, f.Path, "world-writable entry")
		}
		if f.UID != 0 || f.GID != 0 {
			r.Add("ownership-metadata", review.Review, f.Path, fmt.Sprintf("archive owner %d:%d", f.UID, f.GID))
		}
		if known && (before.Type != f.Type || before.Link != f.Link || before.Mode != f.Mode) {
			r.Add("file-metadata", review.Review, f.Path, fmt.Sprintf("type/mode/link changed: %c %04o %q -> %c %04o %q", before.Type, before.Mode, before.Link, f.Type, f.Mode, f.Link))
		}
		if added && f.Mode&0111 != 0 {
			r.Add("executable", review.Review, f.Path, "new executable")
		}
		if (added || !known || before.SHA256 != f.SHA256) && sensitivePath(f.Path) {
			r.Add("system-behavior", review.Review, f.Path, "new or changed service, hook, or system configuration")
		}
	}
	if old != nil {
		for _, f := range old.Files {
			if !packageMetadata(f.Path) && f.Type != tar.TypeDir && !current[f.Path] {
				r.Add("removed", review.Info, f.Path, "removed from package")
			}
		}
	} else {
		for p := range installedFiles {
			if !current[p] && !strings.HasSuffix(p, "/") {
				r.Add("removed", review.Info, p, "removed from installed file list")
			}
		}
	}
	if m.Install != "" {
		action := review.Review
		if old != nil && old.Install == m.Install {
			action = review.Info
		}
		r.Add("install-script", action, ".INSTALL", m.Install)
	} else if old != nil && old.Install != "" {
		r.Add("install-script", review.Info, ".INSTALL", "install script removed")
	}
	sort.SliceStable(r.Findings, func(i, j int) bool { return r.Findings[i].Location < r.Findings[j].Location })
	return r
}

// Metadata is omitted from ordinary filesystem findings, so links and other
// special entries must be rejected rather than bypassing metadata inspection.
func validateMetadataType(name string, entryType byte) error {
	if packageMetadata(name) && entryType != tar.TypeReg && entryType != tar.TypeRegA {
		return fmt.Errorf("package metadata %q must be a regular file (type %q)", name, entryType)
	}
	return nil
}

func packageMetadata(p string) bool {
	switch p {
	case ".PKGINFO", ".BUILDINFO", ".MTREE", ".INSTALL", ".CHANGELOG":
		return true
	}
	return false
}
func sensitivePath(p string) bool {
	for _, prefix := range []string{"etc/", "usr/lib/systemd/", "usr/lib/sysusers.d/", "usr/lib/tmpfiles.d/", "usr/share/libalpm/hooks/", "usr/lib/udev/", "usr/share/polkit-1/"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}
