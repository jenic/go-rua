package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEnterpriseReleaseMetadataAndSameRepositoryAreHostBound(t *testing.T) {
	body := "[" + strings.ReplaceAll(releaseJSON("v1.2.3", false, false, []string{"app-1.2.3.zip"}), "github.com", "git.example.com") + "]"
	if _, err := decodeAndValidateReleasesAt([]byte(body), GitHubRepository{Owner: "brave", Name: "brave-browser"}, "git.example.com"); err != nil {
		t.Fatalf("configured enterprise metadata rejected: %v", err)
	}
	if _, err := decodeAndValidateReleasesAt([]byte(body), GitHubRepository{Owner: "brave", Name: "brave-browser"}, "github.com"); err == nil {
		t.Fatal("same owner/repository crossed host identity")
	}
	client := GitHubClient{CacheDir: t.TempDir()}
	githubKey := client.cachePath("https://api.github.com/repos/acme/app/releases?per_page=20")
	enterpriseKey := client.cachePath("https://api.git.example.com/repos/acme/app/releases?per_page=20")
	if githubKey == enterpriseKey {
		t.Fatal("same owner/repository collided across API origins")
	}
}

func TestEnterpriseTokenIsBoundToExactAPIOrigin(t *testing.T) {
	body := "[" + strings.ReplaceAll(releaseJSON("v1.2.3", false, false, []string{"app-1.2.3.zip"}), "github.com", "git.example.com") + "]"
	for _, test := range []struct {
		name        string
		tokenOrigin string
		wantToken   bool
	}{
		{name: "exact origin", tokenOrigin: "https://api.git.example.com", wantToken: true},
		{name: "different origin", tokenOrigin: "https://other.example.com", wantToken: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &GitHubClient{WebHost: "git.example.com", BaseURL: "https://api.git.example.com", Token: "secret", TokenOrigin: test.tokenOrigin, HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if got := request.Header.Get("Authorization") != ""; got != test.wantToken {
					t.Fatalf("Authorization presence = %v, want %v", got, test.wantToken)
				}
				return testHTTPResponse(http.StatusOK, body), nil
			})}}
			if _, err := client.Releases(context.Background(), GitHubRepository{Owner: "brave", Name: "brave-browser"}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEnterpriseReleaseByTagUsesConfiguredAPIAndWebHosts(t *testing.T) {
	body := strings.ReplaceAll(releaseJSON("v1.2.3", false, false, []string{"app-1.2.3.zip"}), "github.com", "git.example.com")
	client := &GitHubClient{
		WebHost: "git.example.com", BaseURL: "https://api.git.example.com",
		Token: "secret", TokenOrigin: "https://api.git.example.com",
		HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Host != "api.git.example.com" || request.URL.Path != "/repos/brave/brave-browser/releases/tags/v1.2.3" {
				t.Fatalf("unexpected enterprise release request: %s", request.URL)
			}
			if request.Header.Get("Authorization") != "Bearer secret" {
				t.Fatal("enterprise exact-release request omitted configured token")
			}
			return testHTTPResponse(http.StatusOK, body), nil
		})},
	}
	release, err := client.ReleaseByTag(context.Background(), GitHubRepository{Owner: "brave", Name: "brave-browser"}, "v1.2.3")
	if err != nil || release.TagName != "v1.2.3" || len(release.Assets) != 1 {
		t.Fatalf("enterprise exact release=%#v err=%v", release, err)
	}
}

func TestConfiguredAssetRedirectHostsAreExact(t *testing.T) {
	parse := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	allowed := []string{"assets.git.example.com", "cdn.example.com:8443"}
	for _, raw := range []string{
		"https://git.example.com/acme/app/releases/download/v1/app",
		"https://assets.git.example.com/object",
		"https://cdn.example.com:8443/object",
	} {
		if !validCandidateDownloadURL(parse(raw), "git.example.com", allowed) {
			t.Errorf("configured URL rejected: %s", raw)
		}
	}
	for _, raw := range []string{
		"https://assets.git.example.com.evil.test/object",
		"https://cdn.example.com/object",
		"https://user@assets.git.example.com/object",
		"http://assets.git.example.com/object",
	} {
		if validCandidateDownloadURL(parse(raw), "git.example.com", allowed) {
			t.Errorf("spoofed or weakened redirect URL accepted: %s", raw)
		}
	}
	if validCandidateDownloadURLMode(parse("https://objects.githubusercontent.com/object"), "github.com", nil, true) {
		t.Fatal("configured github.com policy inherited the implicit public redirect wildcard")
	}
}

func TestEvidenceExportAndGCStayBoundedAndRetainHistory(t *testing.T) {
	source := filepath.Join(t.TempDir(), "evidence")
	prepareEvidenceDir(t, source)
	evidence := completeEvidenceFixture()
	if err := persistEvidence(source, evidence); err != nil {
		t.Fatal(err)
	}
	useOwnerOf(t, source)
	abandoned := filepath.Join(source, ".evidence-abandoned")
	if err := os.WriteFile(abandoned, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(abandoned, old, old); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "export")
	exported, err := ExportEvidence(source, destination)
	if err != nil || exported.Files != 1 {
		t.Fatalf("export=%#v err=%v", exported, err)
	}
	if _, err := os.Stat(filepath.Join(destination, "manifest.json")); err != nil {
		t.Fatalf("atomic export manifest missing: %v", err)
	}
	if _, err := ExportEvidence(source, destination); err == nil {
		t.Fatal("export replaced existing destination")
	}
	gc, err := GCEvidence(source)
	if err != nil || gc.Removed != 1 || gc.Files != 1 {
		t.Fatalf("gc=%#v err=%v", gc, err)
	}
	entries, err := readEvidenceEntries(source)
	if err != nil || len(entries) != 1 {
		t.Fatalf("valid evidence history was not retained: %v %#v", err, entries)
	}
}

func completeEvidenceFixture() Evidence {
	return Evidence{
		PackageBase: "app-bin", AURVersion: "1.0-1", Upstream: "1.1-1", Repository: "acme/app",
		ProviderHostHash: strings.Repeat("1", 64), APIOriginHash: strings.Repeat("2", 64), ReleaseID: 1, Tag: "v1.1", HostArchitecture: "x86_64", BaselineRecipeSHA256: strings.Repeat("a", 64), GeneratedRecipeSHA256: strings.Repeat("b", 64), AppliedAt: "2026-01-01T00:00:00Z",
		ArtifactHashes: []string{strings.Repeat("d", 64)}, Sources: []string{strings.Repeat("e", 64)},
		Artifacts: []ArtifactEvidence{{ID: 1, Name: "app", Architecture: "x86_64", NameHash: strings.Repeat("c", 64), SHA256: strings.Repeat("d", 64), Methods: []string{"github-api-digest"}, Size: 3, URLHash: strings.Repeat("e", 64), APIDigest: "sha256:" + strings.Repeat("d", 64)}},
	}
}

func prepareEvidenceDir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	useOwnerOf(t, path)
}

func TestEvidenceExportRejectsTrailingMalformedAndPublicRecords(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, path string)
		want   string
	}{
		{name: "trailing object", mutate: func(t *testing.T, path string) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(data, []byte(` {}`)...), 0o600); err != nil {
				t.Fatal(err)
			}
		}, want: "trailing JSON"},
		{name: "trailing junk", mutate: func(t *testing.T, path string) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(data, []byte(` junk`)...), 0o600); err != nil {
				t.Fatal(err)
			}
		}, want: "trailing JSON"},
		{name: "unknown schema field", mutate: func(t *testing.T, path string) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			data = bytes.Replace(data, []byte(`"history"`), []byte(`"secret":"token", "history"`), 1)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}, want: "invalid"},
		{name: "public record", mutate: func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		}, want: "record permissions"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "evidence")
			prepareEvidenceDir(t, source)
			if err := persistEvidence(source, completeEvidenceFixture()); err != nil {
				t.Fatal(err)
			}
			useOwnerOf(t, source)
			test.mutate(t, filepath.Join(source, hashString("app-bin")+".json"))
			destination := filepath.Join(t.TempDir(), "export")
			if _, err := ExportEvidence(source, destination); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid evidence export: err=%v", err)
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				t.Fatalf("failed export published a destination: %v", err)
			}
		})
	}
}

func TestEvidencePersistenceRejectsTrailingExistingRecord(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	prepareEvidenceDir(t, dir)
	evidence := completeEvidenceFixture()
	if err := persistEvidence(dir, evidence); err != nil {
		t.Fatal(err)
	}
	useOwnerOf(t, dir)
	path := filepath.Join(dir, hashString(evidence.PackageBase)+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, []byte(` trailing`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := persistEvidence(dir, evidence); err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("existing evidence trailing data was imported: %v", err)
	}
}

func TestEvidencePersistenceRejectsWrongOwnerEmptyDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	prepareEvidenceDir(t, dir)
	owner := useOwnerOf(t, dir)
	effectiveUID = func() uint32 { return owner + 1 }
	if err := persistEvidence(dir, completeEvidenceFixture()); err == nil || !strings.Contains(err.Error(), "effective user") {
		t.Fatalf("wrong-owner empty evidence directory accepted: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("wrong-owner persistence created evidence: %v %#v", err, entries)
	}
}

func TestEvidenceRecordsBindFilenameAndHistoryPackageIdentity(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, dir, path string) string
		want   string
	}{
		{name: "misplaced filename", mutate: func(t *testing.T, dir, path string) string {
			misplaced := filepath.Join(dir, strings.Repeat("f", 64)+".json")
			if err := os.Rename(path, misplaced); err != nil {
				t.Fatal(err)
			}
			return misplaced
		}, want: "filename does not match"},
		{name: "mixed package history", mutate: func(t *testing.T, _, path string) string {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var record evidenceRecord
			if err := decodeStrict(data, &record); err != nil {
				t.Fatal(err)
			}
			other := completeEvidenceFixture()
			other.PackageBase = "other-bin"
			record.History = append(record.History, other)
			data, err = json.MarshalIndent(record, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}, want: "mixes package bases"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "evidence")
			prepareEvidenceDir(t, dir)
			evidence := completeEvidenceFixture()
			if err := persistEvidence(dir, evidence); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, hashString(evidence.PackageBase)+".json")
			test.mutate(t, dir, path)
			if _, err := ExportEvidence(dir, filepath.Join(t.TempDir(), "export")); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("export accepted %s: %v", test.name, err)
			}
			if _, err := GCEvidence(dir); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("GC accepted %s: %v", test.name, err)
			}
			if err := persistEvidence(dir, evidence); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("persistence accepted %s: %v", test.name, err)
			}
		})
	}
}

func TestEvidenceExportPublicationDoesNotReplaceConcurrentDestination(t *testing.T) {
	source := filepath.Join(t.TempDir(), "evidence")
	prepareEvidenceDir(t, source)
	if err := persistEvidence(source, completeEvidenceFixture()); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "export")
	oldRename := evidenceRenameNoReplace
	evidenceRenameNoReplace = func(oldPath, newPath string) error {
		if err := os.Mkdir(newPath, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(newPath, "concurrent"), []byte("keep"), 0o600); err != nil {
			return err
		}
		return renameNoReplace(oldPath, newPath)
	}
	t.Cleanup(func() { evidenceRenameNoReplace = oldRename })
	if _, err := ExportEvidence(source, destination); err == nil || !os.IsExist(err) {
		t.Fatalf("concurrent destination was replaced or did not fail closed: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(destination, "concurrent"))
	if err != nil || string(data) != "keep" {
		t.Fatalf("concurrent destination was modified: %v %q", err, data)
	}
}

func TestPersistEvidenceSerializesConcurrentWriters(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	prepareEvidenceDir(t, dir)
	firstLocked := make(chan struct{})
	attempted := make(chan struct{}, 2)
	var lockCount atomic.Int32
	oldBefore, oldAfter := evidenceBeforeLock, evidenceAfterLock
	evidenceBeforeLock = func(string) { attempted <- struct{}{} }
	evidenceAfterLock = func(string) {
		if lockCount.Add(1) == 1 {
			close(firstLocked)
			<-attempted
			<-attempted
		}
	}
	t.Cleanup(func() { evidenceBeforeLock, evidenceAfterLock = oldBefore, oldAfter })

	first := completeEvidenceFixture()
	second := completeEvidenceFixture()
	second.ReleaseID = 2
	second.AppliedAt = "2026-01-01T00:00:01Z"
	errors := make(chan error, 2)
	var writers sync.WaitGroup
	writers.Add(1)
	go func() {
		defer writers.Done()
		errors <- persistEvidence(dir, first)
	}()
	<-firstLocked
	writers.Add(1)
	go func() {
		defer writers.Done()
		errors <- persistEvidence(dir, second)
	}()
	writers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	data, err := readEvidenceRecord(filepath.Join(dir, hashString(first.PackageBase)+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var record evidenceRecord
	if err := decodeStrict(data, &record); err != nil {
		t.Fatal(err)
	}
	if len(record.History) != 2 || record.History[0].ReleaseID != 1 || record.History[1].ReleaseID != 2 {
		t.Fatalf("concurrent evidence append lost a writer: %#v", record.History)
	}
}

func TestEvidenceLockRejectsUnsafeFiles(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(t *testing.T, path string)
		owner   func(int, string) error
		want    string
	}{
		{name: "symlink", prepare: func(t *testing.T, path string) {
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}, want: "open evidence lock"},
		{name: "public mode", prepare: func(t *testing.T, path string) {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		}, want: "lock permissions"},
		{name: "nonempty", prepare: func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("unexpected"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, want: "must be empty"},
		{name: "hardlink", prepare: func(t *testing.T, path string) {
			target := filepath.Join(filepath.Dir(path), "hardlink-target")
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(target, path); err != nil {
				t.Fatal(err)
			}
		}, want: "exactly one link"},
		{name: "wrong owner", prepare: func(t *testing.T, path string) {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, owner: func(int, string) error { return fmt.Errorf("evidence lock file must be owned by the effective user") }, want: "effective user"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "evidence")
			prepareEvidenceDir(t, dir)
			lockPath := evidenceLockPath(dir, "app-bin")
			test.prepare(t, lockPath)
			oldOwner := evidenceLockOwnerCheck
			if test.owner != nil {
				evidenceLockOwnerCheck = test.owner
			}
			t.Cleanup(func() { evidenceLockOwnerCheck = oldOwner })
			if err := persistEvidence(dir, completeEvidenceFixture()); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unsafe evidence lock accepted: %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, hashString("app-bin")+".json")); !os.IsNotExist(err) {
				t.Fatalf("unsafe lock allowed evidence publication: %v", err)
			}
		})
	}
}

func TestEvidenceOperationsRejectOwnershipPrivacyAndSymlinkParents(t *testing.T) {
	source := filepath.Join(t.TempDir(), "evidence")
	prepareEvidenceDir(t, source)
	if err := persistEvidence(source, completeEvidenceFixture()); err != nil {
		t.Fatal(err)
	}
	owner := useOwnerOf(t, source)
	effectiveUID = func() uint32 { return owner + 1 }
	for _, operation := range []struct {
		name string
		run  func() error
	}{
		{name: "export", run: func() error { _, err := ExportEvidence(source, filepath.Join(t.TempDir(), "export")); return err }},
		{name: "gc", run: func() error { _, err := GCEvidence(source); return err }},
	} {
		if err := operation.run(); err == nil || !strings.Contains(err.Error(), "effective user") {
			t.Errorf("%s accepted wrong-owner source: %v", operation.name, err)
		}
	}
	effectiveUID = func() uint32 { return owner }
	if err := os.Chmod(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportEvidence(source, filepath.Join(t.TempDir(), "export")); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("export accepted public evidence directory: %v", err)
	}
	if _, err := GCEvidence(source); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("GC accepted public evidence directory: %v", err)
	}
	if err := os.Chmod(source, 0o700); err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	useOwnerOf(t, parent)
	link := filepath.Join(parent, "linked-evidence")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportEvidence(link, filepath.Join(t.TempDir(), "export")); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("export accepted symlink source parent: %v", err)
	}
	if _, err := GCEvidence(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("GC accepted symlink source parent: %v", err)
	}
	exportTarget := t.TempDir()
	linkParent := filepath.Join(t.TempDir(), "linked-parent")
	if err := os.Symlink(exportTarget, linkParent); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportEvidence(source, filepath.Join(linkParent, "export")); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("export accepted symlink destination parent: %v", err)
	}
}
