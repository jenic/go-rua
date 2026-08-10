package upstream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const applyFixture = `pkgname=app-bin
pkgver=1.2.3
pkgrel=2
source_x86_64=("app-${pkgver}.tar.zst::https://github.com/acme/app/releases/download/v${pkgver}/app-${pkgver}.tar.zst" 'launcher')
sha256sums_x86_64=('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')
`

func candidateFixture(content []byte) Candidate {
	sum := sha256.Sum256(content)
	return Candidate{Provider: "github", Repository: "acme/app", ReleaseID: 42, Tag: "v1.2.4", Version: "1.2.4", FullVersion: "1.2.4-1", NewerThanAUR: true, NewerThanLocal: true, Assets: []Asset{{
		ID: 7, Architecture: "x86_64", Name: "app-1.2.4.tar.zst", URL: "https://github.com/acme/app/releases/download/v1.2.4/app-1.2.4.tar.zst", Digest: "sha256:" + hex.EncodeToString(sum[:]), State: "uploaded", Size: int64(len(content)),
	}}}
}

func TestPlanOverrideMapsExactHostIndices(t *testing.T) {
	request := ApplyRequest{PackageBase: "app-bin", AURVersion: "1.2.3-2", Candidate: candidateFixture([]byte("artifact"))}
	plan, err := PlanOverride([]byte(applyFixture), request, "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	if plan.ToVersion != "1.2.4" || len(plan.Mappings) != 1 || plan.Mappings[0].Index != 0 || plan.Mappings[0].ChecksumKey != "sha256sums_x86_64" {
		t.Fatalf("unexpected plan: %#v", plan)
	}
}

func TestPlanOverrideRejectsBaselineAndMappingAmbiguity(t *testing.T) {
	request := ApplyRequest{PackageBase: "app-bin", AURVersion: "1.2.3-9", Candidate: candidateFixture([]byte("artifact"))}
	if _, err := PlanOverride([]byte(applyFixture), request, "x86_64"); err == nil || !strings.Contains(err.Error(), "baseline") {
		t.Fatalf("expected baseline error, got %v", err)
	}
	request.AURVersion = "1.2.3-2"
	request.Candidate.Assets = append(request.Candidate.Assets, request.Candidate.Assets[0])
	if _, err := PlanOverride([]byte(applyFixture), request, "x86_64"); err == nil || !strings.Contains(err.Error(), "maps to 2") {
		t.Fatalf("expected mapping ambiguity, got %v", err)
	}
}

func TestPlanOverrideRejectsVersionDependentNonHostMetadata(t *testing.T) {
	recipe := applyFixture + "source_aarch64=(\"https://github.com/acme/app/releases/download/v${pkgver}/app-${pkgver}-arm.tar\")\nsha256sums_aarch64=('SKIP')\n"
	request := ApplyRequest{PackageBase: "app-bin", AURVersion: "1.2.3-2", Candidate: candidateFixture([]byte("artifact"))}
	if _, err := PlanOverride([]byte(recipe), request, "x86_64"); err == nil || !strings.Contains(err.Error(), "non-host") {
		t.Fatalf("expected non-host metadata rejection, got %v", err)
	}
}

func TestPlanOverrideRejectsUnmappedVersionDependentHostSource(t *testing.T) {
	recipe := strings.Replace(applyFixture,
		`'launcher')`,
		`"https://downloads.example.invalid/launcher-${pkgver}")`, 1)
	request := ApplyRequest{PackageBase: "app-bin", AURVersion: "1.2.3-2", Candidate: candidateFixture([]byte("artifact"))}
	if _, err := PlanOverride([]byte(recipe), request, "x86_64"); err == nil || !strings.Contains(err.Error(), "no selected asset mapping") {
		t.Fatalf("expected unmapped source rejection, got %v", err)
	}
}

func TestPlanOverrideRejectsStaleUnsupportedChecksumFamily(t *testing.T) {
	request := ApplyRequest{PackageBase: "app-bin", AURVersion: "1.2.3-2", Candidate: candidateFixture([]byte("artifact"))}
	recipe := applyFixture + "b2sums_x86_64=('cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' 'SKIP')\n"
	if _, err := PlanOverride([]byte(recipe), request, "x86_64"); err == nil || !strings.Contains(err.Error(), "unsupported checksum family") {
		t.Fatalf("expected unsupported checksum rejection, got %v", err)
	}

	recipe = applyFixture + "b2sums_x86_64=('SKIP' 'SKIP')\n"
	if _, err := PlanOverride([]byte(recipe), request, "x86_64"); err != nil {
		t.Fatalf("SKIP checksum family should remain safe: %v", err)
	}
}

func TestApplyBuildCopyRejectsHostAndNonHostPkgrelDriftBeforeDownload(t *testing.T) {
	hostRecipe := `pkgname=app-bin
pkgver=1.2.3
pkgrel=2
source_x86_64=("app-${pkgver}-${pkgrel}.tar.zst::https://github.com/acme/app/releases/download/v${pkgver}-${pkgrel}/app-${pkgver}-${pkgrel}.tar.zst")
sha256sums_x86_64=('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
`
	hostSRCINFO := "pkgbase = app-bin\npkgver = 1.2.3\npkgrel = 2\nsource_x86_64 = app-1.2.3-2.tar.zst::https://github.com/acme/app/releases/download/v1.2.3-2/app-1.2.3-2.tar.zst\nsha256sums_x86_64 = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
	nonHostRecipe := applyFixture + `source_aarch64=("https://github.com/acme/app/releases/download/v${pkgver}-${pkgrel}/app-${pkgver}-${pkgrel}-arm.tar.zst")
sha256sums_aarch64=('SKIP')
`
	nonHostSRCINFO := "pkgbase = app-bin\npkgver = 1.2.3\npkgrel = 2\nsource_x86_64 = app-1.2.3.tar.zst::https://github.com/acme/app/releases/download/v1.2.3/app-1.2.3.tar.zst\nsource_x86_64 = launcher\nsha256sums_x86_64 = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nsha256sums_x86_64 = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\nsource_aarch64 = https://github.com/acme/app/releases/download/v1.2.3-2/app-1.2.3-2-arm.tar.zst\nsha256sums_aarch64 = SKIP\n"
	for _, test := range []struct {
		name    string
		recipe  string
		srcinfo string
		want    string
	}{
		{name: "host mapping retains old pkgrel", recipe: hostRecipe, srcinfo: hostSRCINFO, want: "prospective pkgver/pkgrel"},
		{name: "non-host source changes with pkgrel reset", recipe: nonHostRecipe, srcinfo: nonHostSRCINFO, want: "non-host"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := candidateFixture([]byte("artifact"))
			applyRejectsBeforeNetwork(t, test.recipe, test.srcinfo, candidate, test.want)
		})
	}
}

func TestApplyBuildCopyRejectsUnsafeMappedAliasBeforeDownload(t *testing.T) {
	alias := "bad\rname"
	recipe := strings.Replace(applyFixture, "app-${pkgver}.tar.zst::https", alias+"::https", 1)
	srcinfo := strings.Replace(
		"pkgbase = app-bin\npkgver = 1.2.3\npkgrel = 2\nsource_x86_64 = app-1.2.3.tar.zst::https://github.com/acme/app/releases/download/v1.2.3/app-1.2.3.tar.zst\nsource_x86_64 = launcher\nsha256sums_x86_64 = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nsha256sums_x86_64 = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
		"app-1.2.3.tar.zst::https", alias+"::https", 1,
	)
	applyRejectsBeforeNetwork(t, recipe, srcinfo, candidateFixture([]byte("artifact")), "unsafe")

	for _, unsafe := range []string{"bad\nname", "bad\rname", "bad\x00name"} {
		if _, err := sourceDestination(unsafe + "::https://github.com/acme/app/releases/download/v1/app.tar"); err == nil {
			t.Fatalf("accepted unsafe mapped alias %q", unsafe)
		}
	}
}

func applyRejectsBeforeNetwork(t *testing.T, recipe, srcinfo string, candidate Candidate, want string) {
	t.Helper()
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
	networkCalled := false
	client := &http.Client{Transport: applyRT(func(*http.Request) (*http.Response, error) {
		networkCalled = true
		return nil, fmt.Errorf("unexpected download")
	})}
	_, err := ApplyBuildCopy(context.Background(), reviewDir, buildDir, ApplyRequest{PackageBase: "app-bin", AURVersion: "1.2.3-2", Candidate: candidate}, ApplyOptions{
		HTTP: client, HostArch: "x86_64", Revalidate: func(context.Context, ApplyRequest) (Candidate, error) { return candidate, nil },
	})
	if err == nil || networkCalled || !strings.Contains(err.Error(), want) {
		t.Fatalf("expected pre-download %q rejection, called=%v err=%v", want, networkCalled, err)
	}
}

type applyRT func(*http.Request) (*http.Response, error)

func (f applyRT) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestApplyBuildCopyMutatesOnlyCopyAfterVerificationAndApproval(t *testing.T) {
	content := []byte("verified artifact")
	candidate := candidateFixture(content)
	root := t.TempDir()
	reviewDir, buildDir := filepath.Join(root, "review"), filepath.Join(root, "build")
	for _, dir := range []string{reviewDir, buildDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(applyFixture), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), []byte("pkgbase = app-bin\npkgver = 1.2.3\npkgrel = 2\nsource_x86_64 = app-1.2.3.tar.zst::https://github.com/acme/app/releases/download/v1.2.3/app-1.2.3.tar.zst\nsource_x86_64 = launcher\nsha256sums_x86_64 = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nsha256sums_x86_64 = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	client := &http.Client{Transport: applyRT(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(content)), ContentLength: int64(len(content)), Request: request, Header: make(http.Header)}, nil
	})}
	confirmed, audited := false, false
	evidenceDir := filepath.Join(root, "evidence")
	prepareEvidenceDir(t, evidenceDir)
	evidence, err := ApplyBuildCopy(context.Background(), reviewDir, buildDir, ApplyRequest{PackageBase: "app-bin", AURVersion: "1.2.3-2", Candidate: candidate}, ApplyOptions{
		HTTP: client, HostArch: "x86_64", EvidenceDir: evidenceDir,
		Revalidate: func(context.Context, ApplyRequest) (Candidate, error) { return candidate, nil },
		Audit:      func(string) error { audited = true; return nil },
		Confirm: func(diff string, evidence Evidence) (bool, error) {
			confirmed = strings.Contains(diff, "pkgver='1.2.4'") && len(evidence.ArtifactHashes) == 1
			return confirmed, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !audited || !confirmed || evidence.ReleaseID != 42 {
		t.Fatalf("audit/confirmation/evidence missing: %#v", evidence)
	}
	review, _ := os.ReadFile(filepath.Join(reviewDir, "PKGBUILD"))
	build, _ := os.ReadFile(filepath.Join(buildDir, "PKGBUILD"))
	if string(review) != applyFixture || !strings.Contains(string(build), "pkgver='1.2.4'") || !strings.Contains(string(build), evidence.ArtifactHashes[0]) {
		t.Fatalf("unexpected persistent/build recipes\nreview:\n%s\nbuild:\n%s", review, build)
	}
	if got, _ := os.ReadFile(filepath.Join(buildDir, candidate.Assets[0].Name)); string(got) != string(content) {
		t.Fatalf("downloaded artifact: %q", got)
	}
}

func TestExactChecksumAndGPGStatusValidation(t *testing.T) {
	hash := strings.Repeat("a", 64)
	if got, err := parseExactSHA256([]byte(hash+"  app.tar\n"), "app.tar"); err != nil || got != hash {
		t.Fatalf("checksum: %q %v", got, err)
	}
	if got, err := parseExactSHA256([]byte(hash+"\n"), "app.tar"); err != nil || got != hash {
		t.Fatalf("digest-only checksum: %q %v", got, err)
	}
	if _, err := parseExactSHA256([]byte(hash+"  other\n"), "app.tar"); err == nil {
		t.Fatal("accepted checksum for another file")
	}
	if _, err := parseExactSHA256([]byte(hash+"  dir/app.tar\n"), "app.tar"); err == nil {
		t.Fatal("accepted checksum path instead of exact filename")
	}
	fingerprint := "0123456789ABCDEF0123456789ABCDEF01234567"
	validLine := "[GNUPG:] VALIDSIG " + fingerprint + " 2026-01-01 0 0 4 0 1 10 00 " + fingerprint + "\n"
	valid := parseGPGStatus([]byte(validLine), []string{fingerprint})
	if !valid.Valid || valid.Fingerprint != fingerprint {
		t.Fatalf("valid status rejected: %#v", valid)
	}
	revoked := parseGPGStatus([]byte(validLine+"[GNUPG:] REVKEYSIG key user\n"), []string{fingerprint})
	if revoked.Valid || !revoked.Revoked {
		t.Fatalf("revoked status accepted: %#v", revoked)
	}
	expired := parseGPGStatus([]byte(validLine+"[GNUPG:] SIGEXPIRED 0\n"), []string{fingerprint})
	if expired.Valid || !expired.Expired {
		t.Fatalf("expired status accepted: %#v", expired)
	}
	unknown := parseGPGStatus([]byte(validLine), []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	if unknown.Valid {
		t.Fatal("accepted unknown signing key")
	}
}

func TestDownloadURLPolicyRejectsCredentialsAndPorts(t *testing.T) {
	for _, raw := range []string{"https://user@release-assets.githubusercontent.com/x", "https://release-assets.githubusercontent.com:444/x", "http://release-assets.githubusercontent.com/x", "https://evil.example/x"} {
		u, _ := url.Parse(raw)
		if validDownloadURL(u) {
			t.Fatalf("accepted unsafe download URL %s", raw)
		}
	}
	u, _ := url.Parse("https://release-assets.githubusercontent.com/x")
	if !validDownloadURL(u) {
		t.Fatal("rejected canonical HTTPS asset URL")
	}
}

func TestDownloadArtifactFollowsBoundedRedirectWithoutCredentials(t *testing.T) {
	content := []byte("artifact")
	requests := 0
	client := &http.Client{Transport: applyRT(func(request *http.Request) (*http.Response, error) {
		requests++
		switch requests {
		case 1:
			request.Header.Set("Authorization", "Bearer secret")
			request.Header.Set("Cookie", "session=secret")
			request.Header.Set("Proxy-Authorization", "Basic secret")
			return &http.Response{StatusCode: http.StatusFound, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{"Location": []string{"https://release-assets.githubusercontent.com/acme/app/artifact"}}, Request: request}, nil
		case 2:
			if request.URL.User != nil || request.URL.Port() != "" || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" || request.Header.Get("Proxy-Authorization") != "" {
				t.Fatalf("credentials or authority leaked to redirect: %s %#v", request.URL, request.Header)
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(content)), ContentLength: int64(len(content)), Header: make(http.Header), Request: request}, nil
		default:
			t.Fatalf("unexpected redirect request %d", requests)
			return nil, nil
		}
	})}
	destination := filepath.Join(t.TempDir(), "artifact")
	if _, _, err := downloadArtifact(context.Background(), client, "https://github.com/acme/app/releases/download/v1/artifact", destination, int64(len(content)), 1024); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("request count = %d", requests)
	}
}

func TestDownloadArtifactRejectsUnsafeRedirectAuthorityAndHopCount(t *testing.T) {
	for _, location := range []string{
		"https://user@release-assets.githubusercontent.com/acme/app/artifact",
		"https://release-assets.githubusercontent.com:443/acme/app/artifact",
		"https://release-assets.githubusercontent.com:444/acme/app/artifact",
	} {
		client := &http.Client{Transport: applyRT(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusFound, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{"Location": []string{location}}, Request: request}, nil
		})}
		if _, _, err := downloadArtifact(context.Background(), client, "https://github.com/acme/app/releases/download/v1/artifact", "", 0, 1024); err == nil || !strings.Contains(err.Error(), "redirect refused") {
			t.Fatalf("accepted redirect %s: %v", location, err)
		}
	}

	hops := 0
	client := &http.Client{Transport: applyRT(func(request *http.Request) (*http.Response, error) {
		hops++
		location := fmt.Sprintf("https://release-assets.githubusercontent.com/acme/app/hop-%d", hops)
		return &http.Response{StatusCode: http.StatusFound, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{"Location": []string{location}}, Request: request}, nil
	})}
	if _, _, err := downloadArtifact(context.Background(), client, "https://github.com/acme/app/releases/download/v1/artifact", "", 0, 1024); err == nil || !strings.Contains(err.Error(), "redirect refused") {
		t.Fatalf("accepted excessive redirects after %d requests: %v", hops, err)
	}
}

func TestFetchAndVerifyRejectsConflictingEvidence(t *testing.T) {
	content := []byte("artifact")
	sum := sha256.Sum256(content)
	wrong := strings.Repeat("b", 64) + "  app.tar\n"
	asset := Asset{Architecture: "x86_64", Name: "app.tar", URL: "https://github.com/acme/app/releases/download/v1.1/app.tar", Digest: "sha256:" + hex.EncodeToString(sum[:]), State: "uploaded", Size: int64(len(content)), Sidecars: Sidecars{SHA256: true}, SidecarAssets: []SidecarAsset{{Kind: ".sha256", Name: "app.tar.sha256", URL: "https://github.com/acme/app/releases/download/v1.1/app.tar.sha256", State: "uploaded", Size: int64(len(wrong))}}}
	client := &http.Client{Transport: applyRT(func(request *http.Request) (*http.Response, error) {
		body := content
		if strings.HasSuffix(request.URL.Path, ".sha256") {
			body = []byte(wrong)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: request, Header: make(http.Header)}, nil
	})}
	if _, _, _, _, err := fetchAndVerify(context.Background(), t.TempDir(), "app.tar", asset, nil, ApplyOptions{HTTP: client}); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("expected conflicting evidence error, got %v", err)
	}
}

func TestApplyBuildCopyRejectsSymlinkRecipe(t *testing.T) {
	root := t.TempDir()
	reviewDir, buildDir := filepath.Join(root, "review"), filepath.Join(root, "build")
	if err := os.Mkdir(reviewDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(buildDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reviewDir, "PKGBUILD"), []byte(applyFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(reviewDir, "PKGBUILD"), filepath.Join(buildDir, "PKGBUILD")); err != nil {
		t.Fatal(err)
	}
	candidate := candidateFixture([]byte("artifact"))
	_, err := ApplyBuildCopy(context.Background(), reviewDir, buildDir, ApplyRequest{PackageBase: "app-bin", AURVersion: "1.2.3-2", Candidate: candidate}, ApplyOptions{Revalidate: func(context.Context, ApplyRequest) (Candidate, error) { return candidate, nil }})
	if err == nil {
		t.Fatal("accepted symlink build-copy recipe")
	}
}

func TestApplyBuildCopyRejectsCandidateDriftBeforeFilesystemOrNetwork(t *testing.T) {
	candidate := candidateFixture([]byte("artifact"))
	drifted := candidate
	drifted.ReleaseID++
	_, err := ApplyBuildCopy(context.Background(), "missing-review", "missing-build", ApplyRequest{PackageBase: "app-bin", AURVersion: "1.2.3-2", Candidate: candidate}, ApplyOptions{Revalidate: func(context.Context, ApplyRequest) (Candidate, error) { return drifted, nil }})
	if err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("expected pre-application drift rejection, got %v", err)
	}
}

func TestApplyBuildCopyRejectsReservedDuplicateAndPreexistingDestinationsBeforeDownload(t *testing.T) {
	content := []byte("artifact")
	candidate := candidateFixture(content)
	baseSRCINFO := "pkgbase = app-bin\npkgver = 1.2.3\npkgrel = 2\nsource_x86_64 = app-1.2.3.tar.zst::https://github.com/acme/app/releases/download/v1.2.3/app-1.2.3.tar.zst\nsource_x86_64 = launcher\nsha256sums_x86_64 = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nsha256sums_x86_64 = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
	tests := []struct {
		name        string
		recipe      string
		srcinfo     string
		preexisting bool
	}{
		{
			name:    "reserved",
			recipe:  strings.Replace(applyFixture, "app-${pkgver}.tar.zst::https", "PKGBUILD::https", 1),
			srcinfo: strings.Replace(baseSRCINFO, "app-1.2.3.tar.zst::https", "PKGBUILD::https", 1),
		},
		{
			name:    "duplicate declared source",
			recipe:  strings.Replace(applyFixture, "'launcher'", "'app-1.2.4.tar.zst'", 1),
			srcinfo: strings.Replace(baseSRCINFO, "source_x86_64 = launcher", "source_x86_64 = app-1.2.4.tar.zst", 1),
		},
		{name: "preexisting file", recipe: applyFixture, srcinfo: baseSRCINFO, preexisting: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			reviewDir, buildDir := filepath.Join(root, "review"), filepath.Join(root, "build")
			for _, dir := range []string{reviewDir, buildDir} {
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(test.recipe), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), []byte(test.srcinfo), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if test.preexisting {
				if err := os.WriteFile(filepath.Join(buildDir, candidate.Assets[0].Name), []byte("do not replace"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			networkCalled := false
			client := &http.Client{Transport: applyRT(func(*http.Request) (*http.Response, error) {
				networkCalled = true
				return nil, fmt.Errorf("unexpected download")
			})}
			_, err := ApplyBuildCopy(context.Background(), reviewDir, buildDir, ApplyRequest{PackageBase: "app-bin", AURVersion: "1.2.3-2", Candidate: candidate}, ApplyOptions{
				HTTP: client, HostArch: "x86_64", Revalidate: func(context.Context, ApplyRequest) (Candidate, error) { return candidate, nil },
			})
			if err == nil || networkCalled || !strings.Contains(err.Error(), "destination") {
				t.Fatalf("expected pre-download collision rejection, called=%v err=%v", networkCalled, err)
			}
		})
	}
}

func TestApplyBuildCopyRejectsStaleSRCINFOBeforeDownloadOrMutation(t *testing.T) {
	candidate := candidateFixture([]byte("artifact"))
	root := t.TempDir()
	reviewDir, buildDir := filepath.Join(root, "review"), filepath.Join(root, "build")
	for _, dir := range []string{reviewDir, buildDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(applyFixture), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stale := "pkgbase = app-bin\npkgver = 1.2.2\npkgrel = 2\nsource_x86_64 = stale\nsha256sums_x86_64 = SKIP\n"
	if err := os.WriteFile(filepath.Join(buildDir, ".SRCINFO"), []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	networkCalled := false
	client := &http.Client{Transport: applyRT(func(*http.Request) (*http.Response, error) {
		networkCalled = true
		return nil, fmt.Errorf("unexpected download")
	})}
	_, err := ApplyBuildCopy(context.Background(), reviewDir, buildDir, ApplyRequest{PackageBase: "app-bin", AURVersion: "1.2.3-2", Candidate: candidate}, ApplyOptions{
		HTTP: client, HostArch: "x86_64", Revalidate: func(context.Context, ApplyRequest) (Candidate, error) { return candidate, nil },
	})
	if err == nil || networkCalled || !strings.Contains(err.Error(), "pkgver") {
		t.Fatalf("expected pre-download .SRCINFO rejection, called=%v err=%v", networkCalled, err)
	}
	got, readErr := os.ReadFile(filepath.Join(buildDir, "PKGBUILD"))
	if readErr != nil || string(got) != applyFixture {
		t.Fatalf("build recipe mutated after stale metadata rejection: %v\n%s", readErr, got)
	}
}

func TestPersistEvidenceRejectsSymlinkParentAndBoundsHistory(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	if err := persistEvidence(filepath.Join(link, "evidence"), Evidence{PackageBase: "app"}); err == nil {
		t.Fatal("accepted symlink evidence parent")
	}
	dir := filepath.Join(root, "evidence")
	prepareEvidenceDir(t, dir)
	first := completeEvidenceFixture()
	if err := persistEvidence(dir, first); err != nil {
		t.Fatal(err)
	}
	useOwnerOf(t, dir)
	for i := 1; i < 35; i++ {
		evidence := completeEvidenceFixture()
		evidence.ReleaseID = int64(i + 1)
		if err := persistEvidence(dir, evidence); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, hashString("app-bin")+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		History []Evidence `json:"history"`
	}
	if json.Unmarshal(data, &record) != nil || len(record.History) != 32 || record.History[0].ReleaseID != 4 {
		t.Fatalf("unexpected bounded history: %d %#v", len(record.History), record.History)
	}
}

func TestGPGVerifierUsesIsolatedAnchoredKeyring(t *testing.T) {
	primary := "0123456789ABCDEF0123456789ABCDEF01234567"
	subkey := "89ABCDEF0123456789ABCDEF0123456789ABCDEF"
	payload := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(payload, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	verifier := GPGVerifier{Run: func(_ context.Context, input []byte, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "--export"):
			return []byte("anchored-key"), nil
		case strings.Contains(joined, "--import"):
			if string(input) != "anchored-key" {
				t.Fatalf("unexpected imported key material")
			}
			return nil, nil
		default:
			return []byte("[GNUPG:] VALIDSIG " + subkey + " 2026-01-01 0 0 4 0 22 10 00 " + primary + "\n"), nil
		}
	}}
	result, err := verifier.VerifyFile(context.Background(), payload, []byte("signature"), []string{primary})
	if err != nil || !result.Valid || result.Fingerprint != primary || len(calls) != 3 {
		t.Fatalf("isolated verification failed: %#v %v calls=%v", result, err, calls)
	}
	for _, call := range calls[1:] {
		if !strings.Contains(strings.Join(call, " "), "--homedir") {
			t.Fatalf("non-export call lacks isolated homedir: %v", call)
		}
	}
	weak := parseGPGStatus([]byte("[GNUPG:] VALIDSIG "+primary+" 2026-01-01 0 0 4 0 17 2 00 "+primary+"\n"), []string{primary})
	if weak.Valid {
		t.Fatal("accepted weak key/hash algorithms")
	}
}
