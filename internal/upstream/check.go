package upstream

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxRecipeBody = 1 << 20

type Checker struct {
	Provider      Provider
	HTTP          *http.Client
	AURBaseURL    string
	Compare       VersionComparator
	RecipeFetcher func(context.Context, string) (Recipe, error)
	PolicyReasons map[string]string
	PolicyError   string
}

func (c Checker) Check(ctx context.Context, requests []Request) []Report {
	reports := make([]Report, 0, len(requests))
	for _, request := range requests {
		report := Report{Package: request.Name, LocalVersion: request.LocalVersion, AURVersion: request.AURVersion}
		if c.PolicyError != "" {
			report.UnknownReason = c.PolicyError
			report.PolicyReason = c.PolicyError
			reports = append(reports, report)
			continue
		}
		if reason := c.PolicyReasons[request.PackageBase]; reason != "" {
			report.UnknownReason = "GitHub upstream policy: " + reason
			report.PolicyReason = reason
			reports = append(reports, report)
			continue
		}
		if request.PackageBase == "" || request.AURVersion == "" {
			report.UnknownReason = "AUR package metadata is incomplete"
			reports = append(reports, report)
			continue
		}
		fetch := c.RecipeFetcher
		if fetch == nil {
			fetch = c.fetchRecipe
		}
		recipe, err := fetch(ctx, request.PackageBase)
		if err != nil {
			report.UnknownReason = err.Error()
			reports = append(reports, report)
			continue
		}
		if recipe.PackageBase != request.PackageBase {
			report.UnknownReason = fmt.Sprintf("AUR recipe package base %q does not match requested %q", recipe.PackageBase, request.PackageBase)
			reports = append(reports, report)
			continue
		}
		cmp, err := c.Compare(recipe.FullVersion(), request.AURVersion)
		if err != nil {
			report.UnknownReason = fmt.Sprintf("compare AUR recipe snapshot version: %v", err)
			reports = append(reports, report)
			continue
		}
		if cmp != 0 {
			report.UnknownReason = fmt.Sprintf("AUR recipe snapshot version %s does not match RPC version %s", recipe.FullVersion(), request.AURVersion)
			reports = append(reports, report)
			continue
		}
		candidate, found, err := c.Provider.Detect(ctx, recipe, request.AURVersion, c.Compare)
		if err != nil {
			report.UnknownReason = err.Error()
			reports = append(reports, report)
			continue
		}
		if !found {
			continue
		}
		report.Source = candidate.Provider + ":" + candidate.Repository
		cmp, err = c.Compare(request.LocalVersion, candidate.FullVersion)
		if err != nil {
			report.UnknownReason = fmt.Sprintf("compare local and upstream versions: %v", err)
			reports = append(reports, report)
			continue
		}
		candidate.NewerThanLocal = cmp < 0
		report.LocalCompare = cmp
		report.Candidate = &candidate
		reports = append(reports, report)
	}
	return reports
}

func (c Checker) fetchRecipe(ctx context.Context, packageBase string) (Recipe, error) {
	body, err := FetchAURFile(ctx, c.HTTP, c.AURBaseURL, packageBase, ".SRCINFO")
	if err != nil {
		return Recipe{}, err
	}
	recipe, err := ParseSRCINFO(body)
	if err != nil {
		return Recipe{}, fmt.Errorf("parse AUR .SRCINFO: %w", err)
	}
	if recipe.PackageBase != packageBase {
		return Recipe{}, fmt.Errorf("AUR recipe package base %q does not match requested %q", recipe.PackageBase, packageBase)
	}
	return recipe, nil
}

// FetchAURFile retrieves a bounded recipe file from the canonical AUR cgit
// endpoint. Only PKGBUILD and .SRCINFO are exposed to callers.
func FetchAURFile(ctx context.Context, client *http.Client, baseURL, packageBase, name string) ([]byte, error) {
	if !validPackageBase(packageBase) {
		return nil, fmt.Errorf("invalid AUR package base %q", packageBase)
	}
	if name != "PKGBUILD" && name != ".SRCINFO" {
		return nil, fmt.Errorf("unsupported AUR recipe file %q", name)
	}
	base, err := validatedAURBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	u := *base
	u.Path = "/cgit/aur.git/plain/" + name
	u.RawQuery = url.Values{"h": []string{packageBase}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	requestClient := *client
	requestClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return fmt.Errorf("AUR cgit redirect refused")
	}
	resp, err := requestClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch AUR %s: %w", name, err)
	}
	if resp.Request != nil && (resp.Request.URL.Scheme != u.Scheme || resp.Request.URL.Host != u.Host || resp.Request.URL.Path != u.Path || resp.Request.URL.RawQuery != u.RawQuery) {
		resp.Body.Close()
		return nil, fmt.Errorf("AUR cgit response origin or path changed")
	}
	body, readErr := readLimited(resp.Body, maxRecipeBody)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AUR %s HTTP %d", name, resp.StatusCode)
	}
	if readErr != nil {
		return nil, fmt.Errorf("read AUR %s: %w", name, readErr)
	}
	return body, nil
}

func validatedAURBaseURL(value string) (*url.URL, error) {
	if value == "" {
		value = "https://aur.archlinux.org"
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return nil, fmt.Errorf("invalid AUR cgit base URL")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("AUR cgit base URL must not contain a path")
	}
	if !isASCII(u.Host) || strings.Contains(u.Host, "\\") {
		return nil, fmt.Errorf("invalid AUR cgit host")
	}
	hostname := u.Hostname()
	if strings.EqualFold(hostname, "aur.archlinux.org") && u.Host != "aur.archlinux.org" {
		return nil, fmt.Errorf("AUR cgit production host must be canonical")
	}
	if hostname != "aur.archlinux.org" && strings.Contains(strings.ToLower(hostname), "aur.archlinux.org") {
		return nil, fmt.Errorf("refusing confusing AUR cgit host")
	}
	u.Path = ""
	return u, nil
}

func validPackageBase(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("@._+-", r)) {
			return false
		}
	}
	return true
}

func DefaultCacheDir() string {
	home, _ := os.UserHomeDir()
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, "rua", "upstream", "github")
}

func DefaultChecker(compare VersionComparator) Checker {
	client := &http.Client{Timeout: 15 * time.Second}
	policy, policyErr := LoadPolicy("")
	githubClient := &GitHubClient{
		WebHost: "github.com", BaseURL: defaultGitHubAPI, Token: os.Getenv("RUA_GITHUB_TOKEN"), CacheDir: DefaultCacheDir(), HTTP: client,
	}
	checker := Checker{Provider: GitHubProvider{Client: githubClient, Policy: policy}, HTTP: client, Compare: compare, PolicyReasons: policy.Diagnostics}
	if policyErr != nil {
		checker.PolicyError = "GitHub upstream policy: " + policyErr.Error()
	}
	return checker
}
