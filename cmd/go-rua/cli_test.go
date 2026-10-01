package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-rua/internal/aur"
	installpkg "go-rua/internal/install"
	"go-rua/internal/pacman"
	"go-rua/internal/paths"
	"go-rua/internal/upstream"
)

type rtCLIFunc func(*http.Request) (*http.Response, error)

func (f rtCLIFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mrespCLI(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewBufferString(body)), Header: make(http.Header)}
}

func captureOut(f func()) (string, string) {
	oldOut, oldErr := os.Stdout, os.Stderr
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
	r1, w1, _ := os.Pipe()
	r2, w2, _ := os.Pipe()
	os.Stdout, os.Stderr = w1, w2
	f()
	w1.Close()
	w2.Close()
	b1, _ := io.ReadAll(r1)
	b2, _ := io.ReadAll(r2)
	return string(b1), string(b2)
}

func restoreCLISeams(t *testing.T) {
	t.Helper()
	oldAurInfo, oldAurSearchAND := aurInfoFn, aurSearchANDFn
	oldPlan, oldInstall := installPlanFn, installInstallFn
	oldSummary, oldFormatSummary := summarizeAURFn, formatSummaryFn
	oldSudo, oldRepoDeps := pacmanSudoFn, pacmanInstallRepoDepsFn
	oldForeign, oldVercmp, oldIgnored := getForeignPkgsFn, vercmpFn, getIgnoredPkgsFn
	oldTarcheck, oldShellcheck, oldNamcap := tarcheckFn, shellcheckFn, namcapFn
	oldPaths, oldPathsNoMakepkg := pathsInitFn, pathsInitNoMakepkgFn
	oldBuildDir := buildDirectoryCLIFn
	oldSourceAudit, oldFormatSourceAudit := sourceAuditDirFn, formatSourceAuditFn
	oldShellAudit, oldFormatShellAudit := shellAuditDirFn, formatShellAuditFn
	oldUpstreamCheck := upstreamCheckFn
	oldUpstreamPlan, oldUpstreamPlanAll, oldUpstreamApply, oldUpstreamPolicyFatal := upstreamPlanFn, upstreamPlanAllFn, upstreamApplyFn, upstreamPolicyFatalFn
	oldExit := osExitFn
	t.Cleanup(func() {
		aurInfoFn = oldAurInfo
		aurSearchANDFn = oldAurSearchAND
		installPlanFn = oldPlan
		installInstallFn = oldInstall
		summarizeAURFn = oldSummary
		formatSummaryFn = oldFormatSummary
		pacmanSudoFn = oldSudo
		pacmanInstallRepoDepsFn = oldRepoDeps
		getForeignPkgsFn = oldForeign
		vercmpFn = oldVercmp
		getIgnoredPkgsFn = oldIgnored
		tarcheckFn = oldTarcheck
		shellcheckFn = oldShellcheck
		namcapFn = oldNamcap
		pathsInitFn = oldPaths
		pathsInitNoMakepkgFn = oldPathsNoMakepkg
		buildDirectoryCLIFn = oldBuildDir
		sourceAuditDirFn = oldSourceAudit
		formatSourceAuditFn = oldFormatSourceAudit
		shellAuditDirFn = oldShellAudit
		formatShellAuditFn = oldFormatShellAudit
		upstreamCheckFn = oldUpstreamCheck
		upstreamPlanFn = oldUpstreamPlan
		upstreamPlanAllFn = oldUpstreamPlanAll
		upstreamApplyFn = oldUpstreamApply
		upstreamPolicyFatalFn = oldUpstreamPolicyFatal
		osExitFn = oldExit
	})
}

func TestSearchCmd(t *testing.T) {
	restoreCLISeams(t)

	// Stub AUR search
	aurSearchANDFn = func(terms []string) ([]aur.Package, error) {
		return []aur.Package{{Name: "foo", Version: "1", Description: "hello"}}, nil
	}
	out, _ := captureOut(func() { searchCmd([]string{"foo"}) })
	if !strings.Contains(out, "foo 1") || !strings.Contains(out, "hello") {
		t.Fatalf("unexpected search out: %q", out)
	}
}

func TestInfoCmdTextAndJSON(t *testing.T) {
	restoreCLISeams(t)

	aurInfoFn = func(names []string) ([]aur.Package, error) {
		return []aur.Package{{
			Name: "pkg", Version: "1", Description: "desc", URL: "u", Maintainer: "m",
			Depends: []string{"a"}, MakeDepends: []string{"b"}, CheckDepends: []string{"c"}, OptDepends: []string{"o"},
			Provides: []string{"p"}, Conflicts: []string{"x"}, OutOfDate: 123,
		}}, nil
	}
	out, _ := captureOut(func() { infoCmd([]string{"pkg"}) })
	if !strings.Contains(out, "pkg 1") || !strings.Contains(out, "depends:") || !strings.Contains(out, "conflicts:") {
		t.Fatalf("unexpected info out: %q", out)
	}
	// JSON flag path
	out2, _ := captureOut(func() { infoCmd([]string{"--json", "pkg"}) })
	var js []aur.Package
	if json.Unmarshal([]byte(out2), &js) != nil || len(js) != 1 || js[0].Name != "pkg" {
		t.Fatalf("unexpected JSON out: %q", out2)
	}
}

func TestUpgradeCmdPlanPrints(t *testing.T) {
	restoreCLISeams(t)

	// Stub findOutdated deps via seams used inside helpers
	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "foo", Version: "1"}}, nil
	}
	aurInfoFn = func(names []string) ([]aur.Package, error) { return []aur.Package{{Name: "foo", Version: "2"}}, nil }
	vercmpFn = func(a, b string) (int, error) { return -1, nil }
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
	installPlanFn = func(names []string) (installpkg.Plan, error) {
		return installpkg.Plan{BuildOrder: names, RepoMissing: []string{"libx"}}, nil
	}
	pacmanSudoFn = func() string { return "sudo" }

	out, _ := captureOut(func() { upgradeCmd([]string{"--plan"}) })
	if !strings.Contains(out, "Plan:") || !strings.Contains(out, "Build order: foo") {
		t.Fatalf("unexpected upgrade plan out: %q", out)
	}
}

func TestUpgradeCmdPlanDoesNotInstall(t *testing.T) {
	restoreCLISeams(t)

	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "foo", Version: "1"}}, nil
	}
	aurInfoFn = func(names []string) ([]aur.Package, error) { return []aur.Package{{Name: "foo", Version: "2"}}, nil }
	vercmpFn = func(a, b string) (int, error) { return -1, nil }
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
	installPlanFn = func(names []string) (installpkg.Plan, error) {
		return installpkg.Plan{BuildOrder: names}, nil
	}
	pacmanSudoFn = func() string { return "sudo" }
	installCalled := false
	installInstallFn = func([]string, paths.Paths, installpkg.Options) error {
		installCalled = true
		return nil
	}

	out, _ := captureOut(func() { upgradeCmd([]string{"--plan"}) })
	if !strings.Contains(out, "Plan:") || !strings.Contains(out, "Build order: foo") {
		t.Fatalf("unexpected upgrade plan out: %q", out)
	}
	if installCalled {
		t.Fatal("upgrade --plan must not install")
	}
}

func TestUpgradeCmdPlanReportsUpstreamLagAndSidecars(t *testing.T) {
	restoreCLISeams(t)
	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "brave-bin", Version: "1.0-1"}}, nil
	}
	aurInfoFn = func([]string) ([]aur.Package, error) {
		return []aur.Package{{Name: "brave-bin", PackageBase: "brave-bin", Version: "1.1-1"}}, nil
	}
	vercmpFn = func(a, b string) (int, error) {
		if a == b {
			return 0, nil
		}
		return -1, nil
	}
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
	installPlanFn = func(names []string) (installpkg.Plan, error) { return installpkg.Plan{BuildOrder: names}, nil }
	upstreamCheckFn = func(_ context.Context, requests []upstream.Request) []upstream.Report {
		if len(requests) != 1 || requests[0].PackageBase != "brave-bin" {
			t.Fatalf("unexpected upstream requests: %#v", requests)
		}
		return []upstream.Report{{
			Package: "brave-bin", LocalVersion: "1.0-1", AURVersion: "1.1-1", Source: "github:brave/brave-browser", LocalCompare: -1,
			Candidate: &upstream.Candidate{
				Tag: "v1.2", FullVersion: "1.2-1", Confidence: "high", NewerThanAUR: true, NewerThanLocal: true,
				Reasons:       []string{"all declared GitHub release assets are present"},
				Assets:        []upstream.Asset{{Architecture: "x86_64", Name: "brave-1.2.zip", Sidecars: upstream.Sidecars{SHA256: true, Signature: true, SHA256Signed: true}}},
				GitReferences: []upstream.GitReference{{Architecture: "any", SourceKey: "source", SourceIndex: 1, RefSHA: "0123456789abcdef0123456789abcdef01234567", CommitSHA: "1123456789abcdef0123456789abcdef01234567", SignatureRequired: true}},
			},
		}}
	}
	out, _ := captureOut(func() { upgradeCmd([]string{"--plan"}) })
	for _, want := range []string{"Upstream status:", "github:brave/brave-browser", "Installed: 1.0-1", "AUR: 1.1-1", "GitHub: 1.2-1", "upstream is newer than installed", "AUR lag: yes", "confidence high", "brave-1.2.zip", "detected sidecars: .sha256, .asc, .sha256.asc", "Git [any] source[1]", "signature required by PKGBUILD"} {
		if !strings.Contains(out, want) {
			t.Fatalf("plan output missing %q: %s", want, out)
		}
	}
}

func TestUpgradeCmdPlainPlanReportsUpstreamOnlyLagThenExitsNoWork(t *testing.T) {
	restoreCLISeams(t)
	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "app-bin", Version: "1.0-1"}}, nil
	}
	aurInfoFn = func([]string) ([]aur.Package, error) {
		return []aur.Package{{Name: "app-bin", PackageBase: "app-bin", Version: "1.0-1"}}, nil
	}
	vercmpFn = func(a, b string) (int, error) {
		if a == b {
			return 0, nil
		}
		return -1, nil
	}
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
	candidate := upstream.Candidate{Provider: "github", Repository: "acme/app", Tag: "v1.1", Version: "1.1", FullVersion: "1.1-1", Confidence: "high", NewerThanAUR: true, NewerThanLocal: true}
	upstreamCheckFn = func(context.Context, []upstream.Request) []upstream.Report {
		return []upstream.Report{{Package: "app-bin", LocalVersion: "1.0-1", AURVersion: "1.0-1", Source: "github:acme/app", LocalCompare: -1, Candidate: &candidate}}
	}
	installPlanFn = func([]string) (installpkg.Plan, error) {
		t.Fatal("plain upstream status entered install planning")
		return installpkg.Plan{}, nil
	}
	installInstallFn = func([]string, paths.Paths, installpkg.Options) error {
		t.Fatal("plain upstream status entered install workflow")
		return nil
	}
	upstreamApplyFn = func(context.Context, string, string, upstream.ApplyRequest, upstream.ApplyOptions) (upstream.Evidence, error) {
		t.Fatal("plain upstream status entered override application")
		return upstream.Evidence{}, nil
	}
	exitCode := 0
	osExitFn = func(code int) { exitCode = code }
	out, _ := captureOut(func() { upgradeCmd([]string{"--plan"}) })
	for _, want := range []string{"Upstream status:", "app-bin:", "AUR: 1.0-1", "GitHub: 1.1-1", "AUR lag: yes"} {
		if !strings.Contains(out, want) {
			t.Fatalf("plain plan output missing %q: %s", want, out)
		}
	}
	if exitCode != 7 {
		t.Fatalf("plain plan exit code = %d, want 7", exitCode)
	}
}

func TestUpgradeCmdPlanUpstreamShowsEligibilityWithoutApplying(t *testing.T) {
	restoreCLISeams(t)
	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "app-bin", Version: "1.0-1"}}, nil
	}
	aurInfoFn = func([]string) ([]aur.Package, error) {
		return []aur.Package{{Name: "app-bin", PackageBase: "app-bin", Version: "1.0-1"}}, nil
	}
	vercmpFn = func(a, b string) (int, error) {
		if a == b {
			return 0, nil
		}
		return -1, nil
	}
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
	installPlanFn = func(names []string) (installpkg.Plan, error) { return installpkg.Plan{BuildOrder: names}, nil }
	candidate := upstream.Candidate{Provider: "github", Repository: "acme/app", Tag: "v1.1", Version: "1.1", FullVersion: "1.1-1", NewerThanLocal: true, NewerThanAUR: true}
	upstreamCheckFn = func(context.Context, []upstream.Request) []upstream.Report {
		return []upstream.Report{{Package: "app-bin", LocalVersion: "1.0-1", AURVersion: "1.0-1", Source: "github:acme/app", Candidate: &candidate}}
	}
	upstreamPlanFn = func(_ context.Context, request upstream.Request, got upstream.Candidate) (upstream.Plan, error) {
		if request.PackageBase != "app-bin" || got.Tag != "v1.1" {
			t.Fatalf("unexpected eligibility request: %#v %#v", request, got)
		}
		return upstream.Plan{PackageBase: "app-bin", FromVersion: "1.0", ToVersion: "1.1", Release: "1", Mappings: []upstream.Mapping{{SourceKey: "source_x86_64", ChecksumKey: "sha256sums_x86_64", Index: 0, Asset: upstream.Asset{Name: "app-1.1.tar"}}}}, nil
	}
	upstreamApplyFn = func(context.Context, string, string, upstream.ApplyRequest, upstream.ApplyOptions) (upstream.Evidence, error) {
		t.Fatal("--plan --upstream entered artifact application")
		return upstream.Evidence{}, nil
	}
	installInstallFn = func([]string, paths.Paths, installpkg.Options) error {
		t.Fatal("--plan --upstream entered install workflow")
		return nil
	}
	out, _ := captureOut(func() { upgradeCmd([]string{"--plan", "--upstream"}) })
	for _, want := range []string{"Eligible upstream overrides:", "pkgver 1.0 -> 1.1", "source_x86_64[0] -> app-1.1.tar", "downloaded SHA-256"} {
		if !strings.Contains(out, want) {
			t.Fatalf("upstream plan missing %q: %s", want, out)
		}
	}
}

func TestUpgradeCmdValidateAllArchitecturesUsesCompletePlanner(t *testing.T) {
	restoreCLISeams(t)
	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "app-bin", Version: "1.0-1"}}, nil
	}
	aurInfoFn = func([]string) ([]aur.Package, error) {
		return []aur.Package{{Name: "app-bin", PackageBase: "app-bin", Version: "1.0-1"}}, nil
	}
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
	vercmpFn = func(a, b string) (int, error) {
		if a == b {
			return 0, nil
		}
		return -1, nil
	}
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
	installPlanFn = func(names []string) (installpkg.Plan, error) { return installpkg.Plan{BuildOrder: names}, nil }
	candidate := upstream.Candidate{Provider: "github", Repository: "acme/app", Tag: "v1.1", Version: "1.1", FullVersion: "1.1-1", NewerThanLocal: true, NewerThanAUR: true}
	upstreamCheckFn = func(context.Context, []upstream.Request) []upstream.Report {
		return []upstream.Report{{Package: "app-bin", LocalVersion: "1.0-1", AURVersion: "1.0-1", Candidate: &candidate}}
	}
	upstreamPlanFn = func(context.Context, upstream.Request, upstream.Candidate) (upstream.Plan, error) {
		t.Fatal("host-only planner used with --validate-all-arches")
		return upstream.Plan{}, nil
	}
	allCalled := false
	upstreamPlanAllFn = func(context.Context, upstream.Request, upstream.Candidate) (upstream.Plan, error) {
		allCalled = true
		return upstream.Plan{PackageBase: "app-bin", FromVersion: "1.0", ToVersion: "1.1", Mappings: []upstream.Mapping{{Architecture: "aarch64", SourceKey: "source_aarch64", ChecksumKey: "sha256sums_aarch64", Asset: upstream.Asset{Name: "app-arm64"}}}}, nil
	}
	out, _ := captureOut(func() { upgradeCmd([]string{"--plan", "--upstream", "--validate-all-arches"}) })
	if !allCalled || !strings.Contains(out, "source_aarch64") {
		t.Fatalf("complete architecture plan missing: called=%v out=%s", allCalled, out)
	}
}

func TestUpgradeCmdMalformedPolicyCannotFallBackToDiscoveryOrApply(t *testing.T) {
	restoreCLISeams(t)
	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "app-bin", Version: "1.0-1"}}, nil
	}
	aurInfoFn = func([]string) ([]aur.Package, error) {
		return []aur.Package{{Name: "app-bin", PackageBase: "app-bin", Version: "1.0-1"}}, nil
	}
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
	vercmpFn = func(a, b string) (int, error) {
		if a == b {
			return 0, nil
		}
		return -1, nil
	}
	upstreamCheckFn = func(context.Context, []upstream.Request) []upstream.Report {
		return []upstream.Report{{Package: "app-bin", PolicyReason: "packages[0]: package identity is missing, malformed, or invalid", UnknownReason: "GitHub upstream policy is invalid"}}
	}
	failed := false
	upstreamPolicyFatalFn = func(err error) {
		failed = strings.Contains(err.Error(), "package identity")
	}
	upstreamPlanFn = func(context.Context, upstream.Request, upstream.Candidate) (upstream.Plan, error) {
		t.Fatal("malformed policy fell back to unconfigured planning")
		return upstream.Plan{}, nil
	}
	installPlanFn = func([]string) (installpkg.Plan, error) {
		t.Fatal("malformed policy reached install planning")
		return installpkg.Plan{}, nil
	}
	installInstallFn = func([]string, paths.Paths, installpkg.Options) error {
		t.Fatal("malformed policy reached application")
		return nil
	}
	captureOut(func() { upgradeCmd([]string{"--upstream"}) })
	if !failed {
		t.Fatal("explicit upstream application did not fail on malformed policy")
	}
}

func TestUpstreamCmdJSONStatus(t *testing.T) {
	restoreCLISeams(t)
	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "app-bin", Version: "1.0-1"}}, nil
	}
	aurInfoFn = func([]string) ([]aur.Package, error) {
		return []aur.Package{{Name: "app-bin", PackageBase: "app-bin", Version: "1.0-1"}}, nil
	}
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
	pathsInitNoMakepkgFn = func() paths.Paths { return paths.Paths{DataCheckedTars: filepath.Join(t.TempDir(), "checked_tars")} }
	upstreamCheckFn = func(context.Context, []upstream.Request) []upstream.Report {
		return []upstream.Report{{Package: "app-bin", LocalVersion: "1.0-1", AURVersion: "1.0-1", PolicyReason: "configured stable policy"}}
	}
	out, _ := captureOut(func() { upstreamCmd([]string{"--json", "app-bin"}) })
	var reports []map[string]any
	if err := json.Unmarshal([]byte(out), &reports); err != nil || len(reports) != 1 || reports[0]["package"] != "app-bin" || reports[0]["policy_reason"] != "configured stable policy" {
		t.Fatalf("machine-readable upstream status invalid: %v %s", err, out)
	}
}

func TestUpgradeCmdUpstreamAddsCandidateAndBuildCopyHook(t *testing.T) {
	restoreCLISeams(t)
	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "app-bin", Version: "1.0-1"}}, nil
	}
	aurInfoFn = func([]string) ([]aur.Package, error) {
		return []aur.Package{{Name: "app-bin", PackageBase: "app-bin", Version: "1.0-1"}}, nil
	}
	vercmpFn = func(a, b string) (int, error) {
		if a == b {
			return 0, nil
		}
		return -1, nil
	}
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
	installPlanFn = func(names []string) (installpkg.Plan, error) { return installpkg.Plan{BuildOrder: names}, nil }
	candidate := upstream.Candidate{Provider: "github", Repository: "acme/app", Tag: "v1.1", Version: "1.1", FullVersion: "1.1-1", NewerThanLocal: true, NewerThanAUR: true}
	upstreamCheckFn = func(context.Context, []upstream.Request) []upstream.Report {
		return []upstream.Report{{Package: "app-bin", LocalVersion: "1.0-1", AURVersion: "1.0-1", Candidate: &candidate}}
	}
	upstreamPlanFn = func(context.Context, upstream.Request, upstream.Candidate) (upstream.Plan, error) {
		return upstream.Plan{PackageBase: "app-bin", FromVersion: "1.0", ToVersion: "1.1"}, nil
	}
	pathsInitFn = func() paths.Paths {
		return paths.Paths{ConfigDir: t.TempDir(), CacheBuildDir: t.TempDir(), DataCheckedTars: t.TempDir()}
	}
	called := false
	installInstallFn = func(names []string, _ paths.Paths, options installpkg.Options) error {
		called = len(names) == 1 && names[0] == "app-bin" && options.InstallBuilt && options.PrepareBuildCopy != nil
		return nil
	}
	_, stderr := captureOut(func() { upgradeCmd([]string{"--upstream"}) })
	if !called || !strings.Contains(stderr, "explicit trust decision") && !strings.Contains(stderr, "downloads and builds") {
		t.Fatalf("upstream workflow not selected: called=%v stderr=%q", called, stderr)
	}
}

func TestUpstreamPrepareHookRechecksLocalStateAndRevalidatesCandidate(t *testing.T) {
	restoreCLISeams(t)
	candidate := upstream.Candidate{Provider: "github", Repository: "acme/app", Tag: "v1.1", Version: "1.1", FullVersion: "1.1-1"}
	request := upstream.ApplyRequest{Name: "app-bin", PackageBase: "app-bin", LocalVersion: "1.0-1", AURVersion: "1.0-1", Candidate: candidate}
	foreignReads, providerChecks := 0, 0
	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		foreignReads++
		return []pacman.ForeignPkg{{Name: "app-bin", Version: "1.0-1"}}, nil
	}
	vercmpFn = func(a, b string) (int, error) {
		if a != "1.0-1" || b != "1.1-1" {
			t.Fatalf("fresh comparison = %q, %q", a, b)
		}
		return -1, nil
	}
	upstreamCheckFn = func(_ context.Context, requests []upstream.Request) []upstream.Report {
		providerChecks++
		if len(requests) != 1 || requests[0].LocalVersion != request.LocalVersion || requests[0].AURVersion != request.AURVersion {
			t.Fatalf("revalidation request = %#v", requests)
		}
		return []upstream.Report{{Package: request.Name, Candidate: &candidate}}
	}
	upstreamApplyFn = func(ctx context.Context, _, _ string, planned upstream.ApplyRequest, options upstream.ApplyOptions) (upstream.Evidence, error) {
		if planned.Name != request.Name || planned.PackageBase != request.PackageBase || planned.Candidate.Tag != request.Candidate.Tag || options.Revalidate == nil {
			t.Fatalf("apply request/options = %#v %#v", planned, options)
		}
		fresh, err := options.Revalidate(ctx, planned)
		if err != nil || fresh.ReleaseID != candidate.ReleaseID || fresh.Tag != candidate.Tag {
			t.Fatalf("candidate revalidation = %#v, %v", fresh, err)
		}
		return upstream.Evidence{}, nil
	}
	p := paths.Paths{DataCheckedTars: filepath.Join(t.TempDir(), "checked")}
	if err := upstreamPrepareHook(request, p)("app-bin", "review", "build"); err != nil {
		t.Fatal(err)
	}
	if foreignReads != 1 || providerChecks != 1 {
		t.Fatalf("freshness checks = local %d provider %d", foreignReads, providerChecks)
	}
}

func TestUpstreamPrepareHookRejectsChangedInstalledVersionBeforeApply(t *testing.T) {
	restoreCLISeams(t)
	request := upstream.ApplyRequest{Name: "app-bin", PackageBase: "app-bin", LocalVersion: "1.0-1", Candidate: upstream.Candidate{FullVersion: "1.2-1"}}
	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "app-bin", Version: "1.1-1"}}, nil
	}
	upstreamApplyFn = func(context.Context, string, string, upstream.ApplyRequest, upstream.ApplyOptions) (upstream.Evidence, error) {
		t.Fatal("applied candidate after installed version changed")
		return upstream.Evidence{}, nil
	}
	err := upstreamPrepareHook(request, paths.Paths{})("app-bin", "review", "build")
	if err == nil || !strings.Contains(err.Error(), "changed after planning") {
		t.Fatalf("expected local-state freshness error, got %v", err)
	}
}

func TestPrintUpstreamReportsDistinguishesLocalVersionState(t *testing.T) {
	tests := []struct {
		name      string
		compare   int
		newer     bool
		want      string
		sidecars  upstream.Sidecars
		wantExtra string
	}{
		{name: "behind", compare: -1, newer: true, want: "upstream is newer than installed"},
		{name: "equal", compare: 0, want: "installed matches upstream"},
		{name: "ahead", compare: 1, want: "installed is newer than detected upstream"},
		{name: "incomplete signed checksum", compare: 0, want: "installed matches upstream", sidecars: upstream.Sidecars{SHA256Signed: true}, wantExtra: ".sha256.asc (incomplete chain: .sha256 missing)"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := upstream.Report{
				Package: "app", LocalVersion: "2.0-1", AURVersion: "1.9-1", Source: "github:acme/app", LocalCompare: test.compare,
				Candidate: &upstream.Candidate{
					Tag: "v2.0", FullVersion: "2.0-1", Confidence: "report-only", NewerThanLocal: test.newer,
					Assets: []upstream.Asset{{Architecture: "x86_64", Name: "app.zip", Sidecars: test.sidecars}},
				},
			}
			out, _ := captureOut(func() { printUpstreamReports([]upstream.Report{report}) })
			if !strings.Contains(out, test.want) || test.wantExtra != "" && !strings.Contains(out, test.wantExtra) {
				t.Fatalf("unexpected output: %s", out)
			}
		})
	}
}

func TestUpgradeCmdNoUpstreamCheckMakesNoProviderCall(t *testing.T) {
	restoreCLISeams(t)
	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "foo", Version: "1"}}, nil
	}
	aurInfoFn = func([]string) ([]aur.Package, error) {
		return []aur.Package{{Name: "foo", PackageBase: "foo", Version: "2"}}, nil
	}
	vercmpFn = func(string, string) (int, error) { return -1, nil }
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
	installPlanFn = func(names []string) (installpkg.Plan, error) { return installpkg.Plan{BuildOrder: names}, nil }
	upstreamCheckFn = func(context.Context, []upstream.Request) []upstream.Report {
		t.Fatal("upstream provider called with --no-upstream-check")
		return nil
	}
	out, _ := captureOut(func() { upgradeCmd([]string{"--plan", "--no-upstream-check"}) })
	if strings.Contains(out, "Upstream status:") {
		t.Fatalf("unexpected upstream output: %s", out)
	}
}

func TestUpgradeCmdUpstreamFailureIsUnknownAndKeepsAURPlan(t *testing.T) {
	restoreCLISeams(t)
	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "foo", Version: "1"}}, nil
	}
	aurInfoFn = func([]string) ([]aur.Package, error) {
		return []aur.Package{{Name: "foo", PackageBase: "foo", Version: "2"}}, nil
	}
	vercmpFn = func(string, string) (int, error) { return -1, nil }
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
	installPlanFn = func(names []string) (installpkg.Plan, error) { return installpkg.Plan{BuildOrder: names}, nil }
	upstreamCheckFn = func(context.Context, []upstream.Request) []upstream.Report {
		return []upstream.Report{{Package: "foo", UnknownReason: "GitHub releases API HTTP 403"}}
	}
	out, _ := captureOut(func() { upgradeCmd([]string{"--plan"}) })
	if !strings.Contains(out, "Status: unknown (GitHub releases API HTTP 403)") || !strings.Contains(out, "Build order: foo") {
		t.Fatalf("provider failure changed AUR plan: %s", out)
	}
}

func TestUpgradeCmdDefaultsToInteractiveInstall(t *testing.T) {
	restoreCLISeams(t)

	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "foo", Version: "1"}}, nil
	}
	aurInfoFn = func(names []string) ([]aur.Package, error) { return []aur.Package{{Name: "foo", Version: "2"}}, nil }
	vercmpFn = func(a, b string) (int, error) { return -1, nil }
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
	installPlanFn = func(names []string) (installpkg.Plan, error) {
		return installpkg.Plan{BuildOrder: names}, nil
	}
	pathsInitFn = func() paths.Paths {
		d := t.TempDir()
		return paths.Paths{ConfigDir: d, CacheBuildDir: d, DataCheckedTars: d}
	}
	var got installpkg.Options
	installInstallFn = func(_ []string, _ paths.Paths, opt installpkg.Options) error {
		got = opt
		return nil
	}

	captureOut(func() { upgradeCmd(nil) })
	if got.NonInteractive {
		t.Fatal("upgrade must keep review interactive")
	}
	if !got.InstallBuilt {
		t.Fatal("upgrade should install built artifacts by default")
	}
}

func TestUpgradeCmdDefaultReportsPackagesMissingFromAUR(t *testing.T) {
	restoreCLISeams(t)

	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "foo", Version: "1"}, {Name: "ghost", Version: "1"}}, nil
	}
	aurInfoFn = func([]string) ([]aur.Package, error) {
		return []aur.Package{{Name: "foo", Version: "2"}}, nil
	}
	vercmpFn = func(string, string) (int, error) { return -1, nil }
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
	installPlanFn = func([]string) (installpkg.Plan, error) {
		return installpkg.Plan{BuildOrder: []string{"foo"}}, nil
	}
	pathsInitFn = func() paths.Paths { return paths.Paths{} }
	installed := false
	installInstallFn = func([]string, paths.Paths, installpkg.Options) error {
		installed = true
		return nil
	}

	out, _ := captureOut(func() { upgradeCmd(nil) })
	if !strings.Contains(out, "installed packages not found in AUR: ghost") {
		t.Fatalf("upgrade output missing nonexistent package note: %q", out)
	}
	if !installed {
		t.Fatal("upgrade did not continue with the available outdated package")
	}
}

func TestUpgradeCmdDefaultStopsWhenOnlyPackagesMissingFromAUR(t *testing.T) {
	restoreCLISeams(t)

	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "ghost", Version: "1"}}, nil
	}
	aurInfoFn = func([]string) ([]aur.Package, error) { return nil, nil }
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
	workCalls := 0
	installPlanFn = func([]string) (installpkg.Plan, error) {
		workCalls++
		return installpkg.Plan{}, nil
	}
	pathsInitFn = func() paths.Paths {
		workCalls++
		return paths.Paths{}
	}
	installInstallFn = func([]string, paths.Paths, installpkg.Options) error {
		workCalls++
		return nil
	}

	out, _ := captureOut(func() { upgradeCmd(nil) })
	if !strings.Contains(out, "installed packages not found in AUR: ghost") {
		t.Fatalf("upgrade output missing nonexistent package note: %q", out)
	}
	if workCalls != 0 {
		t.Fatalf("upgrade started %d plan, path, or install operations without outdated packages", workCalls)
	}
}

func TestInstallCmdInstallsByDefaultUnlessStageOnly(t *testing.T) {
	restoreCLISeams(t)

	pathsInitFn = func() paths.Paths {
		d := t.TempDir()
		return paths.Paths{ConfigDir: d, CacheBuildDir: d, DataCheckedTars: d}
	}
	aurInfoFn = func([]string) ([]aur.Package, error) { return nil, nil }
	summarizeAURFn = func([]string, []aur.Package) (installpkg.DepSummary, error) {
		return installpkg.DepSummary{}, nil
	}
	formatSummaryFn = func(installpkg.DepSummary) string { return "" }

	var got []installpkg.Options
	installInstallFn = func(_ []string, _ paths.Paths, opt installpkg.Options) error {
		got = append(got, opt)
		return nil
	}

	captureOut(func() { installCmd([]string{"pkg"}) })
	captureOut(func() { installCmd([]string{"--stage-only", "pkg"}) })

	if len(got) != 2 {
		t.Fatalf("install calls = %d, want 2", len(got))
	}
	if !got[0].InstallBuilt {
		t.Fatal("install should install built artifacts by default")
	}
	if got[1].InstallBuilt {
		t.Fatal("install --stage-only should not install built artifacts")
	}
}

func TestUpgradeUsesOneGuidedSessionForAllTargets(t *testing.T) {
	restoreCLISeams(t)
	getForeignPkgsFn = func() ([]pacman.ForeignPkg, error) {
		return []pacman.ForeignPkg{{Name: "a", Version: "1-1"}, {Name: "b", Version: "1-1"}}, nil
	}
	aurInfoFn = func([]string) ([]aur.Package, error) {
		return []aur.Package{{Name: "a", PackageBase: "a", Version: "2-1"}, {Name: "b", PackageBase: "b", Version: "2-1"}}, nil
	}
	vercmpFn = func(a, b string) (int, error) {
		if a == b {
			return 0, nil
		}
		return -1, nil
	}
	getIgnoredPkgsFn = func() ([]string, error) { return nil, nil }
	installPlanFn = func(names []string) (installpkg.Plan, error) {
		return installpkg.Plan{Targets: names, BuildOrder: []string{"shared", "a", "b"}}, nil
	}
	pathsInitFn = func() paths.Paths { return paths.Paths{} }
	calls := 0
	installInstallFn = func(names []string, _ paths.Paths, opt installpkg.Options) error {
		calls++
		if len(names) != 2 || !opt.Guided || opt.Plan == nil || len(opt.Plan.BuildOrder) != 3 || !opt.InstallBuilt {
			t.Fatalf("wrong guided invocation: %v %+v", names, opt)
		}
		return nil
	}
	captureOut(func() { upgradeCmd(nil) })
	if calls != 1 {
		t.Fatalf("got %d installer calls", calls)
	}
}
