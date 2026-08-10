package upstream

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	maxEvidenceFiles      = 256
	maxEvidenceExportSize = 32 << 20
)

type EvidenceOperation struct {
	Files   int   `json:"files"`
	Bytes   int64 `json:"bytes"`
	Removed int   `json:"removed,omitempty"`
}

type evidenceRecord struct {
	History []Evidence `json:"history"`
}

var evidenceRenameNoReplace = renameNoReplace

var (
	evidenceBeforeLock     = func(string) {}
	evidenceAfterLock      = func(string) {}
	evidenceLockOwnerCheck = validateFDOwner
)

func DefaultEvidenceDir() string {
	home, _ := os.UserHomeDir()
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "rua", "upstream_evidence")
}

// ExportEvidence copies only validated owned evidence records into a new
// directory and publishes it with one rename. The destination must not exist.
func ExportEvidence(sourceDir, destination string) (EvidenceOperation, error) {
	var result EvidenceOperation
	if sourceDir == "" {
		sourceDir = DefaultEvidenceDir()
	}
	if destination == "" {
		return result, fmt.Errorf("evidence export destination is empty")
	}
	if err := rejectSymlinkComponents(filepath.Dir(destination)); err != nil {
		return result, err
	}
	if _, err := os.Lstat(destination); err == nil {
		return result, fmt.Errorf("evidence export destination already exists")
	} else if !os.IsNotExist(err) {
		return result, err
	}
	entries, err := readEvidenceEntries(sourceDir)
	if os.IsNotExist(err) {
		entries = nil
	} else if err != nil {
		return result, err
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return result, err
	}
	if err := validateOpenedDirectory(parent, false, "evidence export parent directory"); err != nil {
		return result, err
	}
	temporary, err := os.MkdirTemp(parent, ".upstream-evidence-export-*")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(temporary)
	if err := os.Chmod(temporary, 0o700); err != nil {
		return result, err
	}
	if err := validateOpenedDirectory(temporary, true, "temporary evidence export directory"); err != nil {
		return result, err
	}
	for _, entry := range entries {
		data, err := readEvidenceRecord(filepath.Join(sourceDir, entry.Name()))
		if err != nil {
			return result, err
		}
		result.Files++
		result.Bytes += int64(len(data))
		if result.Files > maxEvidenceFiles || result.Bytes > maxEvidenceExportSize {
			return result, fmt.Errorf("evidence export exceeds bounded file or byte limit")
		}
		file, err := openCreateNoFollow(filepath.Join(temporary, entry.Name()), 0o600)
		if err != nil {
			return result, err
		}
		if _, err := file.Write(data); err != nil {
			file.Close()
			return result, err
		}
		if err := file.Close(); err != nil {
			return result, err
		}
	}
	manifest, err := json.MarshalIndent(struct {
		Version    int      `json:"version"`
		ExportedAt string   `json:"exported_at"`
		Files      []string `json:"files"`
	}{Version: 1, ExportedAt: time.Now().UTC().Format(time.RFC3339), Files: evidenceEntryNames(entries)}, "", "  ")
	if err != nil {
		return result, err
	}
	manifestFile, err := openCreateNoFollow(filepath.Join(temporary, "manifest.json"), 0o600)
	if err != nil {
		return result, err
	}
	if _, err := manifestFile.Write(manifest); err != nil {
		manifestFile.Close()
		return result, err
	}
	if err := manifestFile.Close(); err != nil {
		return result, err
	}
	if err := evidenceRenameNoReplace(temporary, destination); err != nil {
		return result, err
	}
	return result, nil
}

// GCEvidence removes only abandoned temporary files created by the evidence
// writer. Valid history records are retained and never shortened by GC.
func GCEvidence(dir string) (EvidenceOperation, error) {
	var result EvidenceOperation
	if dir == "" {
		dir = DefaultEvidenceDir()
	}
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		return result, nil
	} else if err != nil {
		return result, err
	}
	if err := validateOpenedDirectory(dir, true, "evidence directory"); err != nil {
		return result, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return result, err
	}
	for _, entry := range entries {
		if validEvidenceName(entry.Name()) {
			data, err := readEvidenceRecord(filepath.Join(dir, entry.Name()))
			if err != nil {
				return result, err
			}
			result.Files++
			result.Bytes += int64(len(data))
			continue
		}
		if !strings.HasPrefix(entry.Name(), ".evidence-") || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		entryInfo, err := entry.Info()
		if err != nil || !entryInfo.Mode().IsRegular() || time.Since(entryInfo.ModTime()) < 24*time.Hour {
			continue
		}
		if err := validateOwnedPrivateRegular(path, "evidence temporary file"); err != nil {
			return result, err
		}
		if err := os.Remove(path); err != nil {
			return result, err
		}
		result.Removed++
	}
	return result, nil
}

func readEvidenceEntries(dir string) ([]os.DirEntry, error) {
	if err := validateOpenedDirectory(dir, true, "evidence directory"); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	result := make([]os.DirEntry, 0, len(entries))
	for _, entry := range entries {
		if !validEvidenceName(entry.Name()) {
			continue
		}
		result = append(result, entry)
	}
	if len(result) > maxEvidenceFiles {
		return nil, fmt.Errorf("evidence directory exceeds %d records", maxEvidenceFiles)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name() < result[j].Name() })
	return result, nil
}

func readEvidenceRecord(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	if err := validateFDOwner(fd, "evidence record"); err != nil {
		unix.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("open evidence record returned no file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("evidence record %s is not a regular file", filepath.Base(path))
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("evidence record permissions must not grant group or other access")
	}
	data, err := readLimited(file, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("read evidence record: %w", err)
	}
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("evidence record exceeds 1048576 bytes")
	}
	var record evidenceRecord
	if err := decodeStrict(data, &record); err != nil {
		return nil, fmt.Errorf("evidence record %s is invalid: %w", filepath.Base(path), err)
	}
	if len(record.History) == 0 || len(record.History) > 32 {
		return nil, fmt.Errorf("evidence record %s is invalid", filepath.Base(path))
	}
	packageBase := record.History[0].PackageBase
	if filepath.Base(path) != hashString(packageBase)+".json" {
		return nil, fmt.Errorf("evidence record filename does not match package base %q", packageBase)
	}
	for _, evidence := range record.History {
		if evidence.PackageBase != packageBase {
			return nil, fmt.Errorf("evidence record mixes package bases %q and %q", packageBase, evidence.PackageBase)
		}
		if err := validateEvidence(evidence); err != nil {
			return nil, fmt.Errorf("evidence record %s is incomplete", filepath.Base(path))
		}
	}
	canonical, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, err
	}
	return canonical, nil
}

func renameNoReplace(oldPath, newPath string) error {
	return unix.Renameat2(unix.AT_FDCWD, oldPath, unix.AT_FDCWD, newPath, unix.RENAME_NOREPLACE)
}

func evidenceLockPath(dir, packageBase string) string {
	return filepath.Join(dir, "."+hashString(packageBase)+".lock")
}

func acquireEvidenceLock(dir, packageBase string) (*os.File, error) {
	path := evidenceLockPath(dir, packageBase)
	return acquirePrivateLock(path, "evidence lock", func() { evidenceBeforeLock(packageBase) }, func() { evidenceAfterLock(packageBase) }, evidenceLockOwnerCheck)
}

func acquirePrivateLock(path, label string, beforeLock, afterLock func(), ownerCheck func(int, string) error) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("open %s returned no file", label)
	}
	fail := func(err error) (*os.File, error) {
		file.Close()
		return nil, err
	}
	if err := ownerCheck(fd, label+" file"); err != nil {
		return fail(err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return fail(fmt.Errorf("%s is not a regular file", label))
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fail(fmt.Errorf("%s permissions must not grant group or other access", label))
	}
	if info.Size() != 0 {
		return fail(fmt.Errorf("%s file must be empty", label))
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || opened.Nlink != 1 {
		return fail(fmt.Errorf("%s must have exactly one link", label))
	}
	beforeLock()
	for {
		err = unix.Flock(fd, unix.LOCK_EX)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		return fail(fmt.Errorf("lock %s: %w", label, err))
	}
	var linked unix.Stat_t
	if err := unix.Lstat(path, &linked); err != nil || linked.Dev != opened.Dev || linked.Ino != opened.Ino || linked.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Flock(fd, unix.LOCK_UN)
		return fail(fmt.Errorf("%s path changed during acquisition", label))
	}
	afterLock()
	return file, nil
}

func releaseEvidenceLock(file *os.File) {
	if file == nil {
		return
	}
	_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
	_ = file.Close()
}

func validateOwnedPrivateRegular(path, label string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	if err := validateFDOwner(fd, label); err != nil {
		unix.Close(fd)
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return fmt.Errorf("open %s returned no file", label)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", label)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s permissions must not grant group or other access", label)
	}
	return nil
}

func validateEvidence(evidence Evidence) error {
	repositoryParts := strings.Split(evidence.Repository, "/")
	if !validPackageBase(evidence.PackageBase) || evidence.AURVersion == "" || evidence.Upstream == "" || len(repositoryParts) != 2 || !validGitHubComponent(repositoryParts[0]) || !validGitHubComponent(repositoryParts[1]) || evidence.ReleaseID < 0 || !validGitRefName(evidence.Tag) || !validGitHubComponent(evidence.HostArchitecture) || !validSHA256(evidence.BaselineRecipeSHA256) || !validSHA256(evidence.GeneratedRecipeSHA256) || len(evidence.Artifacts)+len(evidence.GitReferences) == 0 {
		return fmt.Errorf("missing evidence identity")
	}
	if !validSHA256(evidence.ProviderHostHash) || !validSHA256(evidence.APIOriginHash) {
		return fmt.Errorf("invalid endpoint identity")
	}
	if _, err := time.Parse(time.RFC3339, evidence.AppliedAt); err != nil {
		return fmt.Errorf("invalid evidence timestamp")
	}
	for _, value := range append(append([]string(nil), evidence.ArtifactHashes...), evidence.Sources...) {
		if !validSHA256(value) {
			return fmt.Errorf("invalid evidence hash")
		}
	}
	for _, signer := range evidence.Signers {
		if !validFingerprintValue(signer) {
			return fmt.Errorf("invalid evidence signer")
		}
	}
	for _, artifact := range evidence.Artifacts {
		if artifact.ID <= 0 || !validGitHubComponent(artifact.Name) || !validGitHubComponent(artifact.Architecture) || !validSHA256(artifact.NameHash) || !validSHA256(artifact.SHA256) || artifact.Size < 0 || !validSHA256(artifact.URLHash) || len(artifact.Methods) == 0 {
			return fmt.Errorf("invalid artifact evidence")
		}
		for _, method := range artifact.Methods {
			if method != "github-api-digest" && method != "sha256-sidecar" && method != "artifact-signature" && method != "checksum-signature" {
				return fmt.Errorf("invalid artifact evidence method")
			}
		}
		for _, signer := range artifact.Signers {
			if !validFingerprintValue(signer) {
				return fmt.Errorf("invalid artifact signer")
			}
		}
		if artifact.APIDigest != "" && !assetDigestPattern.MatchString(artifact.APIDigest) {
			return fmt.Errorf("invalid artifact API digest")
		}
		for _, sidecar := range artifact.Sidecars {
			if sidecar.ID <= 0 || sidecar.Kind != ".sha256" && sidecar.Kind != ".asc" && sidecar.Kind != ".sha256.asc" || sidecar.Size < 0 || !validSHA256(sidecar.URLHash) || !validSHA256(sidecar.LocalSHA256) || !validSidecarStatus(sidecar.Status) {
				return fmt.Errorf("invalid sidecar evidence")
			}
			if sidecar.APIDigest != "" && !assetDigestPattern.MatchString(sidecar.APIDigest) {
				return fmt.Errorf("invalid sidecar API digest")
			}
		}
	}
	for _, reference := range evidence.GitReferences {
		if !validGitHubComponent(reference.Architecture) || !validEvidenceSourceKey(reference.SourceKey) || reference.SourceIndex < 0 || !validSHA256(reference.TagHash) || !validGitObjectID(reference.RefSHA) || !validGitObjectID(reference.CommitSHA) || reference.ObjectType != "tag" && reference.ObjectType != "commit" {
			return fmt.Errorf("invalid Git reference evidence")
		}
		if reference.SignatureRequired && !reference.SignatureVerified {
			return fmt.Errorf("required Git signature evidence is absent")
		}
		if (reference.SignatureVerified && !validFingerprintValue(reference.Signer)) || (!reference.SignatureVerified && reference.Signer != "") {
			return fmt.Errorf("invalid Git reference signer")
		}
	}
	return nil
}

func validEvidenceSourceKey(value string) bool {
	if value == "source" {
		return true
	}
	return strings.HasPrefix(value, "source_") && validGitHubComponent(strings.TrimPrefix(value, "source_"))
}

func validSidecarStatus(value string) bool {
	for _, allowed := range []string{"downloaded and API digest checked", "exact checksum parsed and matched", "recipe-anchored signature valid", "recipe-anchored checksum signature valid"} {
		if value == allowed {
			return true
		}
	}
	return false
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func validEvidenceName(name string) bool {
	if !strings.HasSuffix(name, ".json") || len(name) != 64+len(".json") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimSuffix(name, ".json"))
	return err == nil
}

func evidenceEntryNames(entries []os.DirEntry) []string {
	result := make([]string, len(entries))
	for index, entry := range entries {
		result[index] = entry.Name()
	}
	return result
}
