// Package reviewstate records evidence only after a confirmed installation.
package reviewstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"go-rua/internal/review"
	"go-rua/internal/tarcheck"
	"golang.org/x/sys/unix"
)

const MaxSnapshot = 8 << 20
const maxRecord = 64 << 20
const PolicyVersion = 1

var nameRE = regexp.MustCompile(`^[a-zA-Z0-9_+@][a-zA-Z0-9_+.@-]*$`)

func ValidName(s string) bool { return len(s) <= 255 && nameRE.MatchString(s) }

type File struct {
	Path string `json:"path"`
	Mode uint32 `json:"mode"`
	Data []byte `json:"data"`
}
type Snapshot []File

func (s Snapshot) Digest() string {
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (s Snapshot) Get(name string) []byte {
	for _, f := range s {
		if f.Path == name {
			return f.Data
		}
	}
	return nil
}
func (s Snapshot) Validate() error {
	total := 0
	last := ""
	if len(s) == 0 || len(s) > 4096 {
		return fmt.Errorf("invalid recipe file count")
	}
	for _, f := range s {
		if !filepath.IsLocal(f.Path) || filepath.Clean(f.Path) != f.Path || f.Path <= last || strings.Split(f.Path, "/")[0] == ".git" || f.Mode & ^uint32(0777) != 0 {
			return fmt.Errorf("invalid recipe path or mode %q", f.Path)
		}
		total += len(f.Data)
		last = f.Path
	}
	if total > MaxSnapshot || s.Get("PKGBUILD") == nil {
		return fmt.Errorf("recipe is too large or lacks PKGBUILD")
	}
	return nil
}
func (s Snapshot) Write(dir string) error {
	if err := s.Validate(); err != nil {
		return err
	}
	for _, f := range s {
		path := filepath.Join(dir, f.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW, f.Mode)
		if err != nil {
			return err
		}
		out := os.NewFile(uintptr(fd), path)
		_, err = out.Write(f.Data)
		closeErr := out.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

// Capture reads only named recipe inputs, excluding build products and caches.
func Capture(dir string, names []string) (Snapshot, error) {
	var s Snapshot
	total := 0
	for _, name := range names {
		if !filepath.IsLocal(name) {
			return nil, fmt.Errorf("invalid recipe path %q", name)
		}
		path := filepath.Join(dir, name)
		if err := noSymlinks(path); err != nil {
			return nil, err
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, err
		}
		if !st.Mode().IsRegular() || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			f.Close()
			return nil, fmt.Errorf("recipe input %q is not regular", name)
		}
		b, err := io.ReadAll(io.LimitReader(f, MaxSnapshot+1))
		f.Close()
		if err != nil {
			return nil, err
		}
		total += len(b)
		if total > MaxSnapshot {
			return nil, fmt.Errorf("recipe snapshot exceeds limit")
		}
		s = append(s, File{name, uint32(st.Mode().Perm()), b})
	}
	sort.Slice(s, func(i, j int) bool { return s[i].Path < s[j].Path })
	return s, s.Validate()
}
func (s Snapshot) Names() []string {
	var names []string
	for _, f := range s {
		names = append(names, f.Path)
	}
	return names
}

type Record struct {
	Schema          int                 `json:"schema"`
	Policy          int                 `json:"policy"`
	Base            string              `json:"base"`
	Commit          string              `json:"commit"`
	Recipe          Snapshot            `json:"recipe"`
	EffectiveRecipe Snapshot            `json:"effective_recipe"`
	Artifacts       []tarcheck.Manifest `json:"artifacts"`
	Accepted        []review.Finding    `json:"accepted"`
	InstalledAt     string              `json:"installed_at,omitempty"`
}

func (r Record) Validate() error {
	if r.Schema != 1 || r.Policy != PolicyVersion || !ValidName(r.Base) || len(r.Artifacts) == 0 {
		return fmt.Errorf("invalid review record")
	}
	if _, err := hex.DecodeString(r.Commit); err != nil || (len(r.Commit) != 40 && len(r.Commit) != 64) {
		return fmt.Errorf("invalid reviewed commit")
	}
	if err := r.Recipe.Validate(); err != nil {
		return err
	}
	if err := r.EffectiveRecipe.Validate(); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, a := range r.Artifacts {
		if !ValidName(a.Name) || a.Version == "" || seen[a.Name] || len(a.SHA256) != 64 {
			return fmt.Errorf("invalid artifact record")
		}
		seen[a.Name] = true
		if _, err := hex.DecodeString(a.SHA256); err != nil {
			return fmt.Errorf("invalid artifact digest")
		}
	}
	for _, f := range r.Accepted {
		if f.Rule == "" || (f.Action != review.Info && f.Action != review.Review && f.Action != review.Block) {
			return fmt.Errorf("invalid finding record")
		}
	}
	return nil
}

type Store struct {
	dir  string
	lock *os.File
}

func Open(dir string) (*Store, error) {
	if err := noSymlinks(filepath.Dir(dir)); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := private(dir, true); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "session.lock")
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if err := private(path, false); err != nil {
		f.Close()
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another guided upgrade holds the review lock: %w", err)
	}
	return &Store{dir, f}, nil
}
func (s *Store) Close() error { return s.lock.Close() }
func (s *Store) path(base string, pending bool) string {
	suffix := ".json"
	if pending {
		suffix = ".pending.json"
	}
	return filepath.Join(s.dir, base+suffix)
}
func (s *Store) Load(base string, pending bool) (*Record, error) {
	if !ValidName(base) {
		return nil, fmt.Errorf("invalid package base")
	}
	p := s.path(base, pending)
	if err := private(p, false); err != nil {
		return nil, err
	}
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || st.Mode&0077 != 0 {
		return nil, fmt.Errorf("unsafe opened review record")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxRecord+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxRecord {
		return nil, fmt.Errorf("review record exceeds limit")
	}
	var r Record
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return nil, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("trailing review record data")
	}
	if r.Base != base {
		return nil, fmt.Errorf("review record package mismatch")
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	if !pending {
		if _, err := time.Parse(time.RFC3339, r.InstalledAt); err != nil {
			return nil, err
		}
	}
	return &r, nil
}
func (s *Store) Save(r Record, pending bool) error {
	if err := r.Validate(); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(b) > maxRecord {
		return fmt.Errorf("review record exceeds limit")
	}
	dst := s.path(r.Base, pending)
	if err := private(dst, false); err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(s.dir, ".record-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), dst); err != nil {
		return err
	}
	d, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func (s *Store) ClearPending(base string) error {
	if !ValidName(base) {
		return fmt.Errorf("invalid package base")
	}
	err := os.Remove(s.path(base, true))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
func noSymlinks(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for p := path; ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in review path %s", p)
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}
func private(path string, dir bool) error {
	if err := noSymlinks(path); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return err
	}
	want := uint32(unix.S_IFREG)
	if dir {
		want = unix.S_IFDIR
	}
	if st.Mode&unix.S_IFMT != want || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 || (!dir && (st.Nlink != 1 || st.Size > maxRecord)) {
		return fmt.Errorf("unsafe review state permissions or type: %s", path)
	}
	return nil
}
