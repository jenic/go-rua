package upstream

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const validPolicyJSON = `{
  "version": 1,
  "hosts": [{
    "host": "git.example.com",
    "api_base": "https://api.git.example.com",
    "asset_redirect_hosts": ["assets.git.example.com"],
    "token_env": "RUA_GIT_EXAMPLE_TOKEN"
  }],
  "packages": [{
    "package": "app-bin",
    "host": "git.example.com",
    "repository": "acme/app",
    "channel": "stable",
    "tag_template": "v{version}",
    "asset_templates": {"x86_64": "app-{version}-amd64.tar.zst"},
    "trusted_fingerprints": ["0123456789ABCDEF0123456789ABCDEF01234567"]
  }]
}`

func writePolicyForTest(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "github_upstream.json")
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	useOwnerOf(t, path)
	return path
}

func useOwnerOf(t *testing.T, path string) uint32 {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		t.Fatal(err)
	}
	old := effectiveUID
	effectiveUID = func() uint32 { return stat.Uid }
	t.Cleanup(func() { effectiveUID = old })
	return stat.Uid
}

func TestLoadPolicyStrictVersionedConfiguration(t *testing.T) {
	policy, err := LoadPolicy(writePolicyForTest(t, validPolicyJSON))
	if err != nil {
		t.Fatal(err)
	}
	host := policy.Hosts["git.example.com"]
	configured := policy.Packages["app-bin"]
	if host.APIBase != "https://api.git.example.com" || host.TokenEnv != "RUA_GIT_EXAMPLE_TOKEN" || configured.Repository != "acme/app" || configured.AssetTemplates["x86_64"] == "" {
		t.Fatalf("unexpected policy: %#v", policy)
	}
}

func TestLoadPolicyAllowsGitOnlyPackageWithoutAssetTemplates(t *testing.T) {
	data := strings.Replace(validPolicyJSON, `"asset_templates": {"x86_64": "app-{version}-amd64.tar.zst"},`, `"asset_templates": {},`, 1)
	policy, err := LoadPolicy(writePolicyForTest(t, data))
	if err != nil || policy.Diagnostics["app-bin"] != "" {
		t.Fatalf("Git-only package policy rejected: policy=%#v err=%v", policy, err)
	}
	if configured := policy.Packages["app-bin"]; configured.Package == "" || len(configured.AssetTemplates) != 0 {
		t.Fatalf("Git-only policy was not retained: %#v", configured)
	}
}

func TestLoadPolicyScopesBadAndDuplicatePackages(t *testing.T) {
	data := strings.Replace(validPolicyJSON, `"trusted_fingerprints": ["0123456789ABCDEF0123456789ABCDEF01234567"]`, `"trusted_fingerprints": [], "unknown": true`, 1)
	policy, err := LoadPolicy(writePolicyForTest(t, data))
	if err != nil || policy.Diagnostics["app-bin"] == "" || len(policy.Packages) != 0 {
		t.Fatalf("bad package was not isolated: policy=%#v err=%v", policy, err)
	}

	duplicate := strings.Replace(validPolicyJSON, "  }]\n}", "  }, {\n    \"package\": \"app-bin\", \"host\": \"git.example.com\", \"repository\": \"acme/app\", \"channel\": \"stable\", \"tag_template\": \"v{version}\", \"asset_templates\": {\"x86_64\": \"app-{version}.tar\"}\n  }]\n}", 1)
	policy, err = LoadPolicy(writePolicyForTest(t, duplicate))
	if err != nil || !strings.Contains(policy.Diagnostics["app-bin"], "duplicate") || len(policy.Packages) != 0 {
		t.Fatalf("duplicate package mapping was not rejected deterministically: policy=%#v err=%v", policy, err)
	}
}

func TestLoadPolicyFailsClosedForUnattributablePackageIdentity(t *testing.T) {
	for _, test := range []struct {
		name        string
		replacement string
	}{
		{name: "missing misspelled field", replacement: `"pakage": "app-bin"`},
		{name: "malformed type", replacement: `"package": 7`},
		{name: "invalid value", replacement: `"package": "../app-bin"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := strings.Replace(validPolicyJSON, `"package": "app-bin"`, test.replacement, 1)
			policy, err := LoadPolicy(writePolicyForTest(t, data))
			if err == nil || !strings.Contains(err.Error(), "package identity") || len(policy.Packages) != 0 {
				t.Fatalf("unattributable policy did not fail closed: policy=%#v err=%v", policy, err)
			}
		})
	}
}

func TestUnattributablePolicyErrorPreventsUnconfiguredProviderFallback(t *testing.T) {
	data := strings.Replace(validPolicyJSON, `"package": "app-bin"`, `"pakage": "app-bin"`, 1)
	_, policyErr := LoadPolicy(writePolicyForTest(t, data))
	if policyErr == nil {
		t.Fatal("malformed policy unexpectedly loaded")
	}
	providerCalled := false
	checker := Checker{
		PolicyError: policyErr.Error(), Compare: numericCompare,
		Provider: providerFunc(func(context.Context, Recipe, string, VersionComparator) (Candidate, bool, error) {
			providerCalled = true
			return Candidate{Provider: "github"}, true, nil
		}),
		RecipeFetcher: func(context.Context, string) (Recipe, error) {
			t.Fatal("global policy error reached unconfigured recipe discovery")
			return Recipe{}, nil
		},
	}
	reports := checker.Check(context.Background(), []Request{{Name: "app-bin", PackageBase: "app-bin", LocalVersion: "1.0-1", AURVersion: "1.0-1"}})
	if providerCalled || len(reports) != 1 || reports[0].Candidate != nil || reports[0].PolicyReason == "" {
		t.Fatalf("malformed policy fell back to discovery: called=%v reports=%#v", providerCalled, reports)
	}
}

func TestStrictPolicyJSONRejectsTrailingData(t *testing.T) {
	for _, suffix := range []string{` {}`, ` trailing`} {
		if _, err := LoadPolicy(writePolicyForTest(t, validPolicyJSON+suffix)); err == nil || !strings.Contains(err.Error(), "JSON") {
			t.Fatalf("policy trailing data %q accepted: %v", suffix, err)
		}
	}
}

func TestLoadPolicyRejectsUnsafeFileAndOrigins(t *testing.T) {
	path := writePolicyForTest(t, validPolicyJSON)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(path); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("public policy accepted: %v", err)
	}

	target := writePolicyForTest(t, validPolicyJSON)
	link := filepath.Join(t.TempDir(), "policy.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(link); err == nil {
		t.Fatal("symlink policy accepted")
	}

	spoofed := strings.Replace(validPolicyJSON, `"host": "git.example.com"`, `"host": "git.example.com@evil.test"`, 1)
	if _, err := LoadPolicy(writePolicyForTest(t, spoofed)); err == nil || !strings.Contains(err.Error(), "host") {
		t.Fatalf("unmapped spoofed host accepted: %v", err)
	}
	userinfo := strings.Replace(validPolicyJSON, `https://api.git.example.com`, `https://user@api.git.example.com`, 1)
	if _, err := LoadPolicy(writePolicyForTest(t, userinfo)); err == nil || !strings.Contains(err.Error(), "api_base") {
		t.Fatalf("API userinfo accepted: %v", err)
	}
}

func TestLoadPolicyRejectsWrongOwnerPublicDirectoryAndSymlinkParent(t *testing.T) {
	path := writePolicyForTest(t, validPolicyJSON)
	owner := useOwnerOf(t, path)
	effectiveUID = func() uint32 { return owner + 1 }
	if _, err := LoadPolicy(path); err == nil || !strings.Contains(err.Error(), "effective user") {
		t.Fatalf("wrong-owner policy accepted: %v", err)
	}
	effectiveUID = func() uint32 { return owner }
	if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(path); err == nil || !strings.Contains(err.Error(), "directory permissions") {
		t.Fatalf("public policy directory accepted: %v", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	useOwnerOf(t, parent)
	link := filepath.Join(parent, "linked")
	if err := os.Symlink(filepath.Dir(path), link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(filepath.Join(link, filepath.Base(path))); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink-parent policy accepted: %v", err)
	}
}

func TestHostPolicyRequiresExplicitNondefaultPort(t *testing.T) {
	withPort := strings.ReplaceAll(validPolicyJSON, "git.example.com", "git.example.com:8443")
	withPort = strings.Replace(withPort, `"api_base": "https://api.git.example.com:8443"`, `"api_base": "https://api.git.example.com:8443"`, 1)
	if _, err := LoadPolicy(writePolicyForTest(t, withPort)); err == nil || !strings.Contains(err.Error(), "nondefault ports") {
		t.Fatalf("implicit port accepted: %v", err)
	}
	withPort = strings.Replace(withPort, `"token_env":`, `"allow_nondefault_port": true, "token_env":`, 1)
	policy, err := LoadPolicy(writePolicyForTest(t, withPort))
	if err != nil || policy.Hosts["git.example.com:8443"].APIBase == "" {
		t.Fatalf("explicit port policy rejected: %#v %v", policy, err)
	}
}

func TestCheckerReportsPackagePolicyNonfatally(t *testing.T) {
	checker := Checker{PolicyReasons: map[string]string{"app-bin": "ambiguous source mapping"}}
	reports := checker.Check(t.Context(), []Request{{Name: "app-bin", PackageBase: "app-bin", AURVersion: "1-1"}})
	if len(reports) != 1 || reports[0].PolicyReason != "ambiguous source mapping" || !strings.Contains(reports[0].UnknownReason, "policy") {
		t.Fatalf("policy diagnostic missing: %#v", reports)
	}
}

func TestConfiguredProviderCarriesEndpointAndTrustPolicy(t *testing.T) {
	fingerprint := "0123456789ABCDEF0123456789ABCDEF01234567"
	policy := Policy{
		Hosts:    map[string]HostPolicy{"git.example.com": {Name: "git.example.com", APIBase: "https://api.git.example.com", AssetRedirectHosts: []string{"assets.git.example.com"}}},
		Packages: map[string]PackagePolicy{"app-bin": {Package: "app-bin", Host: "git.example.com", Repository: "acme/app", Channel: "stable", TagTemplate: "v{version}", AssetTemplates: map[string]string{"x86_64": "app-{version}.zip"}, TrustedFingerprints: []string{fingerprint}}},
	}
	releases := `[{"id":1,"tag_name":"v1.0.0","assets":[{"id":10,"name":"app-1.0.0.zip","size":3,"state":"uploaded","browser_download_url":"https://git.example.com/acme/app/releases/download/v1.0.0/app-1.0.0.zip","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]},{"id":2,"tag_name":"v1.1.0","assets":[{"id":20,"name":"app-1.1.0.zip","size":3,"state":"uploaded","browser_download_url":"https://git.example.com/acme/app/releases/download/v1.1.0/app-1.1.0.zip","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}]`
	provider := GitHubProvider{Policy: policy, Client: &GitHubClient{HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return testHTTPResponse(http.StatusOK, releases), nil
	})}}}
	recipe := Recipe{PackageBase: "app-bin", Version: "1.0.0", Release: "1", Architectures: []string{"x86_64"}, Sources: []Source{{Architecture: "x86_64", URL: "https://git.example.com/acme/app/releases/download/v1.0.0/app-1.0.0.zip"}}}
	candidate, found, err := provider.Detect(context.Background(), recipe, "1.0.0-1", numericCompare)
	if err != nil || !found || !candidate.Configured || candidate.Host != "git.example.com" || candidate.APIOrigin != "https://api.git.example.com" || len(candidate.TrustedKeys) != 1 || candidate.TrustedKeys[0] != fingerprint {
		t.Fatalf("configured endpoint identity was lost: candidate=%#v found=%v err=%v", candidate, found, err)
	}
}
