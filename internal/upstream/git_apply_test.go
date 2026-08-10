package upstream

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const gitTestFingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"

const gitApplyRecipe = `pkgname=app-git
pkgver=1.2.3
pkgrel=2
arch=('any')
source=("checkout::git+https://github.com/acme/app.git#tag=v${pkgver}")
sha256sums=('SKIP')
`

const gitApplySRCINFO = `pkgbase = app-git
	pkgver = 1.2.3
	pkgrel = 2
	arch = any
	source = checkout::git+https://github.com/acme/app.git#tag=v1.2.3
	sha256sums = SKIP
`

func gitCandidateFixture() Candidate {
	return Candidate{
		Provider: "github", Host: "github.com", APIOrigin: defaultGitHubAPI, Repository: "acme/app",
		Tag: "v1.2.4", Version: "1.2.4", FullVersion: "1.2.4-1", NewerThanAUR: true, NewerThanLocal: true,
		GitReferences: []GitReference{{Architecture: "any", SourceKey: "source", SourceIndex: 0, SourceName: "checkout", Tag: "v1.2.4", RefSHA: gitCommit124, CommitSHA: gitCommit124, ObjectType: "commit"}},
	}
}

func TestPlanOverrideMapsGitTagToImmutableCommit(t *testing.T) {
	candidate := gitCandidateFixture()
	plan, err := PlanOverride([]byte(gitApplyRecipe), ApplyRequest{PackageBase: "app-git", AURVersion: "1.2.3-2", Candidate: candidate}, "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	want := "checkout::git+https://github.com/acme/app.git#commit=" + gitCommit124
	if len(plan.Mappings) != 1 || plan.Mappings[0].Kind != "git" || plan.Mappings[0].Next != want || plan.Mappings[0].ChecksumKey != "sha256sums" {
		t.Fatalf("plan=%#v", plan)
	}

	recipe := strings.Replace(gitApplyRecipe, "sha256sums=('SKIP')", "sha256sums=('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')", 1)
	if _, err := PlanOverride([]byte(recipe), ApplyRequest{PackageBase: "app-git", AURVersion: "1.2.3-2", Candidate: candidate}, "x86_64"); err == nil || !strings.Contains(err.Error(), "requires a SKIP") {
		t.Fatalf("Git source with content checksum accepted: %v", err)
	}

	signedRecipe := strings.Replace(gitApplyRecipe, ".git#tag=", ".git?signed#tag=", 1)
	if _, err := PlanOverride([]byte(signedRecipe), ApplyRequest{PackageBase: "app-git", AURVersion: "1.2.3-2", Candidate: candidate}, "x86_64"); err == nil || !strings.Contains(err.Error(), "signature requirement") {
		t.Fatalf("candidate bypassed reviewed signed-source requirement: %v", err)
	}
}

func TestApplyBuildCopyPinsGitWithoutDownloadingContent(t *testing.T) {
	candidate := gitCandidateFixture()
	root := t.TempDir()
	reviewDir, buildDir := filepath.Join(root, "review"), filepath.Join(root, "build")
	for _, dir := range []string{reviewDir, buildDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(gitApplyRecipe), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(buildDir, ".SRCINFO"), []byte(gitApplySRCINFO), 0o600); err != nil {
		t.Fatal(err)
	}
	networkCalled := false
	httpClient := &http.Client{Transport: applyRT(func(*http.Request) (*http.Response, error) {
		networkCalled = true
		return nil, fmt.Errorf("Git content must be fetched later by makepkg prefetch")
	})}
	evidence, err := ApplyBuildCopy(context.Background(), reviewDir, buildDir, ApplyRequest{PackageBase: "app-git", AURVersion: "1.2.3-2", Candidate: candidate}, ApplyOptions{
		HTTP: httpClient, HostArch: "x86_64",
		Revalidate: func(context.Context, ApplyRequest) (Candidate, error) { return candidate, nil },
		Audit:      func(string) error { return nil },
		Confirm:    func(string, Evidence) (bool, error) { return true, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if networkCalled || len(evidence.Artifacts) != 0 || len(evidence.GitReferences) != 1 || evidence.GitReferences[0].CommitSHA != gitCommit124 {
		t.Fatalf("unexpected Git evidence or download: called=%v evidence=%#v", networkCalled, evidence)
	}
	review, err := os.ReadFile(filepath.Join(reviewDir, "PKGBUILD"))
	if err != nil {
		t.Fatal(err)
	}
	build, err := os.ReadFile(filepath.Join(buildDir, "PKGBUILD"))
	if err != nil {
		t.Fatal(err)
	}
	srcinfo, err := os.ReadFile(filepath.Join(buildDir, ".SRCINFO"))
	if err != nil {
		t.Fatal(err)
	}
	immutable := "git+https://github.com/acme/app.git#commit=" + gitCommit124
	if string(review) != gitApplyRecipe || !strings.Contains(string(build), immutable) || !strings.Contains(string(srcinfo), immutable) || !strings.Contains(string(build), "sha256sums=('SKIP')") {
		t.Fatalf("Git override was not isolated and exact\nreview:\n%s\nbuild:\n%s\nsrcinfo:\n%s", review, build, srcinfo)
	}
}

type gitSignatureVerifier struct {
	t *testing.T
}

func (v gitSignatureVerifier) Verify(_ context.Context, payload, signature []byte, keys []string) (SignatureResult, error) {
	v.t.Helper()
	if string(payload) != "tag payload" || string(signature) != "tag signature" || len(keys) != 1 || keys[0] != gitTestFingerprint {
		v.t.Fatalf("unexpected signature input: payload=%q signature=%q keys=%#v", payload, signature, keys)
	}
	return SignatureResult{Fingerprint: gitTestFingerprint, Valid: true}, nil
}

func TestApplyBuildCopyVerifiesSignedGitTagAgainstRecipeKey(t *testing.T) {
	recipe := strings.Replace(gitApplyRecipe, ".git#tag=", ".git?signed#tag=", 1) + "validpgpkeys=('" + gitTestFingerprint + "')\n"
	srcinfo := strings.Replace(gitApplySRCINFO, ".git#tag=", ".git?signed#tag=", 1) + "\tvalidpgpkeys = " + gitTestFingerprint + "\n"
	candidate := gitCandidateFixture()
	reference := &candidate.GitReferences[0]
	reference.ObjectType = "tag"
	reference.RefSHA = gitTagObject
	reference.SignatureRequired = true
	reference.SignaturePresent = true
	reference.Signature = []byte("tag signature")
	reference.Payload = []byte("tag payload")

	root := t.TempDir()
	reviewDir, buildDir := filepath.Join(root, "review"), filepath.Join(root, "build")
	for _, dir := range []string{reviewDir, buildDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(recipe), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(buildDir, ".SRCINFO"), []byte(srcinfo), 0o600); err != nil {
		t.Fatal(err)
	}
	evidence, err := ApplyBuildCopy(context.Background(), reviewDir, buildDir, ApplyRequest{PackageBase: "app-git", AURVersion: "1.2.3-2", Candidate: candidate}, ApplyOptions{
		HostArch: "x86_64", Verifier: gitSignatureVerifier{t: t},
		Revalidate: func(context.Context, ApplyRequest) (Candidate, error) { return candidate, nil },
		Audit:      func(string) error { return nil },
		Confirm:    func(string, Evidence) (bool, error) { return true, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.GitReferences) != 1 || !evidence.GitReferences[0].SignatureVerified || evidence.GitReferences[0].Signer != gitTestFingerprint {
		t.Fatalf("signed Git evidence=%#v", evidence.GitReferences)
	}
}
