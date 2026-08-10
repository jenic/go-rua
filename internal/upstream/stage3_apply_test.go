package upstream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const allArchRecipe = `pkgname=multi-bin
pkgver=1.0.0
pkgrel=3
arch=('x86_64' 'aarch64')
source=("common-${pkgver}::https://github.com/acme/multi/releases/download/v${pkgver}/common-${pkgver}")
source_x86_64=("amd64-${pkgver}::https://github.com/acme/multi/releases/download/v${pkgver}/amd64-${pkgver}")
source_aarch64=("arm64-${pkgver}::https://github.com/acme/multi/releases/download/v${pkgver}/arm64-${pkgver}")
sha256sums=('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
sha256sums_x86_64=('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')
sha256sums_aarch64=('cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc')
`

const allArchSRCINFO = `pkgbase = multi-bin
	pkgver = 1.0.0
	pkgrel = 3
	arch = x86_64
	arch = aarch64
	source = common-1.0.0::https://github.com/acme/multi/releases/download/v1.0.0/common-1.0.0
	sha256sums = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
	source_x86_64 = amd64-1.0.0::https://github.com/acme/multi/releases/download/v1.0.0/amd64-1.0.0
	sha256sums_x86_64 = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
	source_aarch64 = arm64-1.0.0::https://github.com/acme/multi/releases/download/v1.0.0/arm64-1.0.0
	sha256sums_aarch64 = cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
`

func allArchCandidate(contents map[string][]byte) Candidate {
	architectures := map[string]string{"common-1.1.0": "any", "amd64-1.1.0": "x86_64", "arm64-1.1.0": "aarch64"}
	assets := make([]Asset, 0, len(architectures))
	var id int64 = 10
	for _, name := range []string{"common-1.1.0", "amd64-1.1.0", "arm64-1.1.0"} {
		sum := sha256.Sum256(contents[name])
		assets = append(assets, Asset{ID: id, Architecture: architectures[name], Name: name, URL: "https://github.com/acme/multi/releases/download/v1.1.0/" + name, Digest: "sha256:" + hex.EncodeToString(sum[:]), State: "uploaded", Size: int64(len(contents[name]))})
		id++
	}
	return Candidate{Provider: "github", Host: "github.com", APIOrigin: defaultGitHubAPI, Repository: "acme/multi", ReleaseID: 9, Tag: "v1.1.0", Version: "1.1.0", FullVersion: "1.1.0-1", NewerThanAUR: true, NewerThanLocal: true, Assets: assets}
}

func TestPlanOverrideAllArchitecturesMapsGenericAndSplitArrays(t *testing.T) {
	candidate := allArchCandidate(map[string][]byte{"common-1.1.0": []byte("common"), "amd64-1.1.0": []byte("amd64"), "arm64-1.1.0": []byte("arm64")})
	plan, err := PlanOverrideForArchitectures([]byte(allArchRecipe), ApplyRequest{PackageBase: "multi-bin", AURVersion: "1.0.0-3", Candidate: candidate}, "x86_64", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Mappings) != 3 || plan.Mappings[0].SourceKey != "source" || plan.Mappings[1].SourceKey != "source_aarch64" || plan.Mappings[2].SourceKey != "source_x86_64" {
		t.Fatalf("all-architecture mappings are not exact and deterministic: %#v", plan.Mappings)
	}
	if _, err := PlanOverride([]byte(allArchRecipe), ApplyRequest{PackageBase: "multi-bin", AURVersion: "1.0.0-3", Candidate: candidate}, "x86_64"); err == nil || !strings.Contains(err.Error(), "non-host") {
		t.Fatalf("host-only mode accepted changing non-host metadata: %v", err)
	}
}

func TestApplyBuildCopyAllArchitecturesIsCompleteAndAtomicAgainstReview(t *testing.T) {
	contents := map[string][]byte{"common-1.1.0": []byte("common"), "amd64-1.1.0": []byte("amd64"), "arm64-1.1.0": []byte("arm64")}
	candidate := allArchCandidate(contents)
	root := t.TempDir()
	reviewDir, buildDir := filepath.Join(root, "review"), filepath.Join(root, "build")
	for _, dir := range []string{reviewDir, buildDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(allArchRecipe), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(buildDir, ".SRCINFO"), []byte(allArchSRCINFO), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: applyRT(func(request *http.Request) (*http.Response, error) {
		body := contents[filepath.Base(request.URL.Path)]
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: request, Header: make(http.Header)}, nil
	})}
	evidence, err := ApplyBuildCopy(context.Background(), reviewDir, buildDir, ApplyRequest{PackageBase: "multi-bin", AURVersion: "1.0.0-3", Candidate: candidate}, ApplyOptions{
		HTTP: client, HostArch: "x86_64", ValidateAllArches: true,
		Revalidate: func(context.Context, ApplyRequest) (Candidate, error) { return candidate, nil },
		Audit:      func(string) error { return nil }, Confirm: func(string, Evidence) (bool, error) { return true, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.Artifacts) != 3 || evidence.Artifacts[0].Architecture == "" {
		t.Fatalf("per-architecture evidence missing: %#v", evidence.Artifacts)
	}
	review, _ := os.ReadFile(filepath.Join(reviewDir, "PKGBUILD"))
	build, _ := os.ReadFile(filepath.Join(buildDir, "PKGBUILD"))
	info, _ := os.ReadFile(filepath.Join(buildDir, ".SRCINFO"))
	if string(review) != allArchRecipe || !strings.Contains(string(build), "pkgver='1.1.0'") || !strings.Contains(string(info), "source_aarch64 = arm64-1.1.0") {
		t.Fatalf("all-architecture rewrite was incomplete\nreview:\n%s\nbuild:\n%s\nsrcinfo:\n%s", review, build, info)
	}
}

func TestAllArchitectureMissingAssetAndEvidenceConflictAbortWithoutRecipeMutation(t *testing.T) {
	contents := map[string][]byte{"common-1.1.0": []byte("common"), "amd64-1.1.0": []byte("amd64"), "arm64-1.1.0": []byte("arm64")}
	candidate := allArchCandidate(contents)
	candidate.Assets = candidate.Assets[:2]
	if _, err := PlanOverrideForArchitectures([]byte(allArchRecipe), ApplyRequest{PackageBase: "multi-bin", AURVersion: "1.0.0-3", Candidate: candidate}, "x86_64", true); err == nil {
		t.Fatal("missing architecture asset accepted")
	}

	candidate = allArchCandidate(contents)
	candidate.Assets[2].Digest = "sha256:" + strings.Repeat("0", 64)
	root := t.TempDir()
	reviewDir, buildDir := filepath.Join(root, "review"), filepath.Join(root, "build")
	for _, dir := range []string{reviewDir, buildDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(allArchRecipe), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(buildDir, ".SRCINFO"), []byte(allArchSRCINFO), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: applyRT(func(request *http.Request) (*http.Response, error) {
		body := contents[filepath.Base(request.URL.Path)]
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: request, Header: make(http.Header)}, nil
	})}
	_, err := ApplyBuildCopy(context.Background(), reviewDir, buildDir, ApplyRequest{PackageBase: "multi-bin", AURVersion: "1.0.0-3", Candidate: candidate}, ApplyOptions{HTTP: client, HostArch: "x86_64", ValidateAllArches: true, Revalidate: func(context.Context, ApplyRequest) (Candidate, error) { return candidate, nil }})
	buildRecipe, _ := os.ReadFile(filepath.Join(buildDir, "PKGBUILD"))
	reviewRecipe, _ := os.ReadFile(filepath.Join(reviewDir, "PKGBUILD"))
	if err == nil || string(buildRecipe) != allArchRecipe || string(reviewRecipe) != allArchRecipe {
		t.Fatalf("evidence conflict partially rewrote a recipe: err=%v", err)
	}
}
