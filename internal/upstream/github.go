package upstream

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	defaultGitHubAPI  = "https://api.github.com"
	maxGitHubBody     = 4 << 20
	maxGitHubCache    = maxGitHubBody + 256<<10
	maxGitHubReleases = 20
	maxReleaseHistory = 256
)

var (
	stableVersionPattern      = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,3}$`)
	assetDigestPattern        = regexp.MustCompile(`^sha256:[0-9a-fA-F]{64}$`)
	githubCacheBeforeLock     = func(string) {}
	githubCacheAfterLock      = func(string) {}
	githubCacheLockOwnerCheck = validateFDOwner
)

type GitHubRepository struct {
	Owner string
	Name  string
}

type GitHubEndpoint struct {
	WebHost            string
	APIOrigin          string
	AssetRedirectHosts []string
}

func (r GitHubRepository) String() string { return r.Owner + "/" + r.Name }

type GitHubAssetURL struct {
	Repository GitHubRepository
	Tag        string
	Name       string
}

// ParseGitHubRepository accepts only canonical HTTPS github.com URLs.
func ParseGitHubRepository(rawURL string) (GitHubRepository, error) {
	return ParseGitHubRepositoryAt(rawURL, "github.com")
}

func ParseGitHubRepositoryAt(rawURL, host string) (GitHubRepository, error) {
	u, err := strictGitHubURLAt(rawURL, host)
	if err != nil {
		return GitHubRepository{}, err
	}
	parts := splitPath(u.Path)
	if len(parts) < 2 || !validGitHubComponent(parts[0]) || !validGitHubComponent(parts[1]) {
		return GitHubRepository{}, fmt.Errorf("GitHub URL does not identify an owner and repository")
	}
	name := strings.TrimSuffix(parts[1], ".git")
	if name == "" {
		return GitHubRepository{}, fmt.Errorf("empty GitHub repository")
	}
	return GitHubRepository{Owner: parts[0], Name: name}, nil
}

func ParseGitHubReleaseAssetURL(rawURL string) (GitHubAssetURL, error) {
	return ParseGitHubReleaseAssetURLAt(rawURL, "github.com")
}

func ParseGitHubReleaseAssetURLAt(rawURL, host string) (GitHubAssetURL, error) {
	u, err := strictGitHubURLAt(rawURL, host)
	if err != nil {
		return GitHubAssetURL{}, err
	}
	parts := splitPath(u.Path)
	if len(parts) != 6 || parts[2] != "releases" || parts[3] != "download" {
		return GitHubAssetURL{}, fmt.Errorf("not a canonical GitHub release asset URL")
	}
	for _, part := range []string{parts[0], parts[1], parts[4], parts[5]} {
		if !validGitHubComponent(part) {
			return GitHubAssetURL{}, fmt.Errorf("invalid GitHub release asset component")
		}
	}
	repositoryName := strings.TrimSuffix(parts[1], ".git")
	if repositoryName == "" {
		return GitHubAssetURL{}, fmt.Errorf("empty GitHub repository")
	}
	return GitHubAssetURL{
		Repository: GitHubRepository{Owner: parts[0], Name: repositoryName},
		Tag:        parts[4], Name: parts[5],
	}, nil
}

func strictGitHubURL(rawURL string) (*url.URL, error) {
	return strictGitHubURLAt(rawURL, "github.com")
}

func strictGitHubURLAt(rawURL, host string) (*url.URL, error) {
	if !isASCII(rawURL) {
		return nil, fmt.Errorf("GitHub URL must be ASCII")
	}
	canonical, err := canonicalHost(host, strings.Contains(host, ":"))
	if err != nil {
		return nil, fmt.Errorf("invalid configured GitHub host")
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host != canonical || u.User != nil {
		return nil, fmt.Errorf("GitHub URL must use canonical https://%s host", canonical)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || strings.Contains(u.Path, "//") {
		return nil, fmt.Errorf("GitHub URL contains ambiguous path, query, or fragment")
	}
	return u, nil
}

func isASCII(value string) bool {
	for _, r := range value {
		if r > 127 {
			return false
		}
	}
	return true
}

func validGitHubComponent(value string) bool {
	if value == "" || value == "." || value == ".." || strings.ContainsAny(value, "/\\%") {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-+", r)) {
			return false
		}
	}
	return true
}

func splitPath(path string) []string {
	if !strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") {
		return nil
	}
	return strings.Split(strings.TrimPrefix(path, "/"), "/")
}

type GitHubClient struct {
	BaseURL            string
	WebHost            string
	AssetRedirectHosts []string
	Token              string
	TokenOrigin        string
	AllowPort          bool
	CacheDir           string
	HTTP               *http.Client
}

type githubRelease struct {
	ID              int64         `json:"id"`
	TagName         string        `json:"tag_name"`
	Draft           bool          `json:"draft"`
	Prerelease      bool          `json:"prerelease"`
	Assets          []githubAsset `json:"assets"`
	AddedAssetCount int           `json:"-"`
}

type githubAsset struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Digest             string `json:"digest"`
	State              string `json:"state"`
}

type githubCacheRecord struct {
	ETag    string            `json:"etag"`
	Body    json.RawMessage   `json:"body"`
	History []releaseEvidence `json:"history,omitempty"`
}

type releaseEvidence struct {
	ID          int64  `json:"id"`
	TagHash     string `json:"tag_hash"`
	Fingerprint string `json:"fingerprint"`
}

func (c *GitHubClient) Releases(ctx context.Context, repository GitHubRepository) ([]githubRelease, error) {
	base, parsedBase, err := c.apiBase()
	if err != nil {
		return nil, err
	}
	webHost := c.WebHost
	if webHost == "" {
		webHost = "github.com"
	}
	u := releaseListEndpoint(base, repository)
	cachePath := c.cachePath(u)
	cached, _ := readGitHubCache(cachePath)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if cached.ETag != "" {
		req.Header.Set("If-None-Match", cached.ETag)
	}
	if c.Token != "" && (c.TokenOrigin == base || c.TokenOrigin == "" && base == defaultGitHubAPI) {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	requestClient := *client
	requestClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return fmt.Errorf("GitHub API redirect refused")
	}
	resp, err := requestClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub releases request: %w", err)
	}
	defer resp.Body.Close()
	if resp.Request != nil && (resp.Request.URL.Scheme != parsedBase.Scheme || resp.Request.URL.Host != parsedBase.Host || resp.Request.URL.Path != req.URL.Path || resp.Request.URL.RawQuery != req.URL.RawQuery) {
		return nil, fmt.Errorf("GitHub API response origin or path changed")
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotModified {
		return nil, fmt.Errorf("GitHub releases API HTTP %d", resp.StatusCode)
	}
	var responseBody []byte
	if resp.StatusCode == http.StatusOK {
		responseBody, err = readLimited(resp.Body, maxGitHubBody)
		if err != nil {
			return nil, fmt.Errorf("GitHub releases response: %w", err)
		}
	}
	if cachePath == "" {
		return reconcileGitHubCache("", resp.StatusCode, resp.Header.Get("ETag"), responseBody, cached, repository, webHost)
	}
	lock, err := acquireGitHubCacheLock(cachePath)
	if err != nil {
		return nil, err
	}
	defer releaseEvidenceLock(lock)
	latest, err := readGitHubCache(cachePath)
	if os.IsNotExist(err) {
		latest = githubCacheRecord{}
	} else if err != nil {
		return nil, fmt.Errorf("read current GitHub cache: %w", err)
	}
	return reconcileGitHubCache(cachePath, resp.StatusCode, resp.Header.Get("ETag"), responseBody, latest, repository, webHost)
}

func (c *GitHubClient) ReleaseByTag(ctx context.Context, repository GitHubRepository, tag string) (githubRelease, error) {
	if !validGitHubComponent(tag) {
		return githubRelease{}, fmt.Errorf("invalid GitHub release tag")
	}
	base, parsedBase, err := c.apiBase()
	if err != nil {
		return githubRelease{}, err
	}
	webHost := c.WebHost
	if webHost == "" {
		webHost = "github.com"
	}
	endpoint := fmt.Sprintf("%s/repos/%s/%s/releases/tags/%s", base, url.PathEscape(repository.Owner), url.PathEscape(repository.Name), url.PathEscape(tag))
	cachePath := c.cachePath(endpoint)
	cached, _ := readGitHubCache(cachePath)
	status, etag, body, err := c.apiGET(ctx, parsedBase, endpoint, cached.ETag, maxGitHubBody-2)
	if err != nil {
		return githubRelease{}, fmt.Errorf("GitHub release-by-tag request: %w", err)
	}
	if status != http.StatusOK && status != http.StatusNotModified {
		return githubRelease{}, fmt.Errorf("GitHub release-by-tag API HTTP %d", status)
	}
	if status == http.StatusOK {
		body = wrapReleaseResponse(body)
		if _, err := exactReleaseFromBody(body, repository, webHost, tag); err != nil {
			return githubRelease{}, err
		}
	}
	if cachePath == "" {
		releases, err := reconcileGitHubCache("", status, etag, body, cached, repository, webHost)
		if err != nil {
			return githubRelease{}, err
		}
		return exactRelease(releases, tag)
	}
	lock, err := acquireGitHubCacheLock(cachePath)
	if err != nil {
		return githubRelease{}, err
	}
	defer releaseEvidenceLock(lock)
	latest, err := readGitHubCache(cachePath)
	if os.IsNotExist(err) {
		latest = githubCacheRecord{}
		history, historyErr := c.recentReleaseHistory(base, repository, webHost)
		if historyErr != nil {
			return githubRelease{}, historyErr
		}
		latest.History = history
	} else if err != nil {
		return githubRelease{}, fmt.Errorf("read current GitHub release-by-tag cache: %w", err)
	}
	releases, err := reconcileGitHubCache(cachePath, status, etag, body, latest, repository, webHost)
	if err != nil {
		return githubRelease{}, err
	}
	return exactRelease(releases, tag)
}

func releaseListEndpoint(base string, repository GitHubRepository) string {
	return fmt.Sprintf("%s/repos/%s/%s/releases?per_page=%d", base, url.PathEscape(repository.Owner), url.PathEscape(repository.Name), maxGitHubReleases)
}

func wrapReleaseResponse(body []byte) []byte {
	wrapped := make([]byte, 0, len(body)+2)
	wrapped = append(wrapped, '[')
	wrapped = append(wrapped, body...)
	return append(wrapped, ']')
}

func exactReleaseFromBody(body []byte, repository GitHubRepository, webHost, tag string) (githubRelease, error) {
	releases, err := decodeAndValidateReleasesAt(body, repository, webHost)
	if err != nil {
		return githubRelease{}, err
	}
	return exactRelease(releases, tag)
}

func exactRelease(releases []githubRelease, tag string) (githubRelease, error) {
	if len(releases) != 1 || releases[0].TagName != tag {
		return githubRelease{}, fmt.Errorf("GitHub release-by-tag response does not match requested tag %s", tag)
	}
	return releases[0], nil
}

func (c *GitHubClient) recentReleaseHistory(base string, repository GitHubRepository, webHost string) ([]releaseEvidence, error) {
	record, err := readGitHubCache(c.cachePath(releaseListEndpoint(base, repository)))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read recent GitHub release history: %w", err)
	}
	if len(record.Body) > 0 {
		releases, decodeErr := decodeAndValidateReleasesAt(record.Body, repository, webHost)
		if decodeErr != nil {
			return nil, fmt.Errorf("recent GitHub release cache is invalid: %w", decodeErr)
		}
		if historyErr := detectHistoricalMutation(record.History, releases); historyErr != nil {
			return nil, fmt.Errorf("recent GitHub release cache conflicts with retained history: %w", historyErr)
		}
	}
	return append([]releaseEvidence(nil), record.History...), nil
}

func reconcileGitHubCache(cachePath string, status int, etag string, responseBody []byte, cached githubCacheRecord, repository GitHubRepository, webHost string) ([]githubRelease, error) {
	if status == http.StatusNotModified {
		if len(cached.Body) == 0 {
			return nil, fmt.Errorf("GitHub returned 304 without a cached response")
		}
		return decodeAndValidateReleasesAt(cached.Body, repository, webHost)
	}
	releases, err := decodeAndValidateReleasesAt(responseBody, repository, webHost)
	if err != nil {
		return nil, err
	}
	history := cached.History
	if len(cached.Body) > 0 {
		oldReleases, decodeErr := decodeAndValidateReleasesAt(cached.Body, repository, webHost)
		if decodeErr != nil {
			return nil, fmt.Errorf("cached GitHub metadata is invalid: %w", decodeErr)
		}
		if err := detectHistoricalMutation(history, oldReleases); err != nil {
			return nil, fmt.Errorf("cached GitHub metadata conflicts with retained history: %w", err)
		}
		reconciled, additions, reconcileErr := reconcileReleaseSnapshots(oldReleases, releases)
		if reconcileErr != nil {
			return nil, reconcileErr
		}
		history = removeReleaseEvidence(history, reconciled)
		for index := range releases {
			releases[index].AddedAssetCount = additions[releases[index].ID]
		}
	}
	if err := detectHistoricalMutation(history, releases); err != nil {
		return nil, err
	}
	history = mergeReleaseEvidence(history, releases)
	if cachePath != "" {
		if err := writeGitHubCache(cachePath, githubCacheRecord{ETag: etag, Body: responseBody, History: history}); err != nil {
			return nil, fmt.Errorf("write GitHub cache: %w", err)
		}
	}
	return releases, nil
}

func removeReleaseEvidence(history, reconciled []releaseEvidence) []releaseEvidence {
	if len(reconciled) == 0 {
		return history
	}
	remove := make(map[releaseEvidence]bool, len(reconciled))
	for _, evidence := range reconciled {
		remove[evidence] = true
	}
	retained := make([]releaseEvidence, 0, len(history))
	for _, evidence := range history {
		if !remove[evidence] {
			retained = append(retained, evidence)
		}
	}
	return retained
}

func acquireGitHubCacheLock(cachePath string) (*os.File, error) {
	dir := filepath.Dir(cachePath)
	if err := rejectSymlinkComponents(dir); err != nil {
		return nil, fmt.Errorf("GitHub cache lock directory: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("GitHub cache lock directory is not a regular directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	if err := validateOpenedDirectory(dir, true, "GitHub cache lock directory"); err != nil {
		return nil, err
	}
	return acquirePrivateLock(cachePath+".lock", "GitHub cache lock", func() { githubCacheBeforeLock(cachePath) }, func() { githubCacheAfterLock(cachePath) }, githubCacheLockOwnerCheck)
}

func decodeAndValidateReleases(body []byte, repository GitHubRepository) ([]githubRelease, error) {
	return decodeAndValidateReleasesAt(body, repository, "github.com")
}

func decodeAndValidateReleasesAt(body []byte, repository GitHubRepository, webHost string) ([]githubRelease, error) {
	var releases []githubRelease
	if err := json.Unmarshal(body, &releases); err != nil {
		return nil, fmt.Errorf("decode GitHub releases: %w", err)
	}
	if len(releases) > maxGitHubReleases {
		return nil, fmt.Errorf("GitHub returned more than %d releases", maxGitHubReleases)
	}
	seenReleaseIDs := map[int64]bool{}
	seenTags := map[string]bool{}
	seenGlobalAssetIDs := map[int64]bool{}
	for _, release := range releases {
		if release.ID <= 0 || release.TagName == "" {
			return nil, fmt.Errorf("GitHub release metadata is missing id or tag")
		}
		if seenReleaseIDs[release.ID] || seenTags[release.TagName] {
			return nil, fmt.Errorf("GitHub release metadata contains duplicate id or tag")
		}
		seenReleaseIDs[release.ID], seenTags[release.TagName] = true, true
		seenAssetIDs := map[int64]bool{}
		seenAssetNames := map[string]bool{}
		for _, asset := range release.Assets {
			if asset.ID <= 0 || asset.Name == "" || asset.Size < 0 || asset.BrowserDownloadURL == "" || asset.State == "" {
				return nil, fmt.Errorf("GitHub release asset metadata is malformed")
			}
			if asset.Digest != "" && !assetDigestPattern.MatchString(asset.Digest) {
				return nil, fmt.Errorf("GitHub release asset digest is malformed")
			}
			if seenAssetIDs[asset.ID] || seenAssetNames[asset.Name] {
				return nil, fmt.Errorf("GitHub release metadata contains duplicate asset id or name")
			}
			if seenGlobalAssetIDs[asset.ID] {
				return nil, fmt.Errorf("GitHub release metadata reuses an asset id across releases")
			}
			seenAssetIDs[asset.ID], seenAssetNames[asset.Name] = true, true
			seenGlobalAssetIDs[asset.ID] = true
			parsed, err := ParseGitHubReleaseAssetURLAt(asset.BrowserDownloadURL, webHost)
			if err != nil || parsed.Repository != repository || parsed.Tag != release.TagName || parsed.Name != asset.Name {
				return nil, fmt.Errorf("GitHub release asset URL is inconsistent with API metadata")
			}
		}
	}
	return releases, nil
}

func detectHistoricalMutation(history []releaseEvidence, releases []githubRelease) error {
	for _, release := range releases {
		current := evidenceForRelease(release)
		for _, previous := range history {
			if previous.ID != current.ID && previous.TagHash != current.TagHash {
				continue
			}
			if previous.ID != current.ID || previous.TagHash != current.TagHash || previous.Fingerprint != current.Fingerprint {
				return fmt.Errorf("GitHub release or asset identity mutated for tag %s", release.TagName)
			}
		}
	}
	return nil
}

func mergeReleaseEvidence(history []releaseEvidence, releases []githubRelease) []releaseEvidence {
	for _, release := range releases {
		evidence := evidenceForRelease(release)
		refreshed := make([]releaseEvidence, 0, len(history)+1)
		for _, existing := range history {
			if existing != evidence {
				refreshed = append(refreshed, existing)
			}
		}
		history = append(refreshed, evidence)
	}
	if len(history) > maxReleaseHistory {
		history = append([]releaseEvidence(nil), history[len(history)-maxReleaseHistory:]...)
	}
	return history
}

func evidenceForRelease(release githubRelease) releaseEvidence {
	assets := append([]githubAsset(nil), release.Assets...)
	sort.Slice(assets, func(i, j int) bool {
		if assets[i].ID != assets[j].ID {
			return assets[i].ID < assets[j].ID
		}
		return assets[i].Name < assets[j].Name
	})
	payload, _ := json.Marshal(struct {
		ID     int64
		Tag    string
		Assets []githubAsset
	}{ID: release.ID, Tag: release.TagName, Assets: assets})
	tagHash := sha256.Sum256([]byte(release.TagName))
	fingerprint := sha256.Sum256(payload)
	return releaseEvidence{ID: release.ID, TagHash: hex.EncodeToString(tagHash[:]), Fingerprint: hex.EncodeToString(fingerprint[:])}
}

func reconcileReleaseSnapshots(oldReleases, newReleases []githubRelease) ([]releaseEvidence, map[int64]int, error) {
	newByID := make(map[int64]githubRelease, len(newReleases))
	newByTag := make(map[string]githubRelease, len(newReleases))
	for _, release := range newReleases {
		newByID[release.ID], newByTag[release.TagName] = release, release
	}
	reconciled := make([]releaseEvidence, 0, len(oldReleases))
	additions := make(map[int64]int)
	for _, oldRelease := range oldReleases {
		byID, hasID := newByID[oldRelease.ID]
		byTag, hasTag := newByTag[oldRelease.TagName]
		if !hasID && !hasTag {
			continue
		}
		if !hasID || !hasTag || byID.ID != byTag.ID || byID.TagName != oldRelease.TagName {
			return nil, nil, fmt.Errorf("GitHub release identity mutated for tag %s", oldRelease.TagName)
		}
		added, err := reconcileReleaseAssets(oldRelease, byID)
		if err != nil {
			return nil, nil, err
		}
		reconciled = append(reconciled, evidenceForRelease(oldRelease))
		if added > 0 {
			additions[oldRelease.ID] = added
		}
	}
	return reconciled, additions, nil
}

func reconcileReleaseAssets(oldRelease, newRelease githubRelease) (int, error) {
	newByID := make(map[int64]githubAsset, len(newRelease.Assets))
	newByName := make(map[string]githubAsset, len(newRelease.Assets))
	for _, asset := range newRelease.Assets {
		newByID[asset.ID], newByName[asset.Name] = asset, asset
	}
	for _, oldAsset := range oldRelease.Assets {
		byID, hasID := newByID[oldAsset.ID]
		byName, hasName := newByName[oldAsset.Name]
		if !hasID && !hasName {
			return 0, fmt.Errorf("GitHub asset %s was removed from existing release %s", oldAsset.Name, oldRelease.TagName)
		}
		if !hasID || !hasName || byID.ID != byName.ID || byID != oldAsset {
			return 0, fmt.Errorf("GitHub asset %s mutated under existing release %s", oldAsset.Name, oldRelease.TagName)
		}
	}
	return len(newRelease.Assets) - len(oldRelease.Assets), nil
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return data, nil
}

func (c *GitHubClient) cachePath(key string) string {
	if c.CacheDir == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(c.CacheDir, hex.EncodeToString(sum[:])+".json")
}

func readGitHubCache(path string) (githubCacheRecord, error) {
	if path == "" {
		return githubCacheRecord{}, os.ErrNotExist
	}
	f, err := os.Open(path)
	if err != nil {
		return githubCacheRecord{}, err
	}
	defer f.Close()
	data, err := readLimited(f, maxGitHubCache)
	if err != nil {
		return githubCacheRecord{}, fmt.Errorf("read GitHub cache: %w", err)
	}
	var record githubCacheRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return githubCacheRecord{}, err
	}
	return record, nil
}

func writeGitHubCache(path string, record githubCacheRecord) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if int64(len(data)) > maxGitHubCache {
		return fmt.Errorf("cache record exceeds %d bytes", maxGitHubCache)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".github-cache-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

type GitHubProvider struct {
	Client *GitHubClient
	Policy Policy
}

func (p GitHubProvider) Detect(ctx context.Context, recipe Recipe, aurVersion string, compare VersionComparator) (Candidate, bool, error) {
	packagePolicy, configured := p.Policy.Package(recipe.PackageBase)
	host := "github.com"
	client := p.Client
	var repository GitHubRepository
	var templates []githubTemplate
	var err error
	if configured {
		hostPolicy := p.Policy.Hosts[packagePolicy.Host]
		host = hostPolicy.Name
		repository, templates, err = configuredGitHubTemplates(recipe, packagePolicy)
		if client == nil {
			return Candidate{}, false, errors.New("GitHub client is not configured")
		}
		copyClient := *client
		copyClient.WebHost = hostPolicy.Name
		copyClient.BaseURL = hostPolicy.APIBase
		copyClient.AssetRedirectHosts = append([]string(nil), hostPolicy.AssetRedirectHosts...)
		copyClient.AllowPort = hostPolicy.AllowPort
		copyClient.Token = ""
		copyClient.TokenOrigin = hostPolicy.APIBase
		if hostPolicy.TokenEnv != "" {
			copyClient.Token = os.Getenv(hostPolicy.TokenEnv)
		}
		client = &copyClient
	} else {
		repository, templates, err = githubTemplates(recipe)
	}
	if err != nil {
		return Candidate{}, false, err
	}
	if len(templates) == 0 {
		return Candidate{}, false, nil
	}
	if client == nil {
		return Candidate{}, false, errors.New("GitHub client is not configured")
	}
	hasAssets, hasGit := templateKinds(templates)
	releases, err := client.Releases(ctx, repository)
	if err != nil {
		return Candidate{}, false, err
	}
	var tags []githubTagSummary
	if hasGit {
		tags, err = client.Tags(ctx, repository)
		if err != nil {
			return Candidate{}, false, err
		}
	}
	currentTag := templates[0].TagTemplate.Apply(recipe.Version)
	if hasAssets {
		baseline, found := releaseByTag(releases, currentTag)
		if !found {
			baseline, err = client.ReleaseByTag(ctx, repository, currentTag)
			if err != nil {
				return Candidate{}, false, fmt.Errorf("resolve current recipe release %s: %w", currentTag, err)
			}
		}
		if !releaseAllowed(baseline, configured, packagePolicy.Channel) {
			return Candidate{}, false, fmt.Errorf("current recipe release is not a stable published release")
		}
		if _, ok := matchGitHubReleaseAt(recipe, repository, templates, baseline, recipe.Version, host); !ok {
			return Candidate{}, false, fmt.Errorf("current recipe assets are missing or not uploaded in GitHub release %s", baseline.TagName)
		}
	} else {
		baselineFound := tagSummaryExists(tags, currentTag)
		if known, allowed := releaseTagDisposition(releases, currentTag, configured, packagePolicy.Channel); known && !allowed {
			return Candidate{}, false, fmt.Errorf("current recipe tag is attached to a disallowed GitHub release")
		} else if configured && packagePolicy.Channel == "prerelease" && !known {
			return Candidate{}, false, fmt.Errorf("current prerelease recipe tag has no GitHub prerelease metadata")
		}
		if !baselineFound {
			return Candidate{}, false, fmt.Errorf("current recipe tag %s is absent from recent GitHub metadata", currentTag)
		}
	}
	if hasGit {
		currentCommit, ok := tagSummaryCommit(tags, currentTag)
		if !ok {
			return Candidate{}, false, fmt.Errorf("current recipe tag %s is absent from recent GitHub tag metadata", currentTag)
		}
		if _, err := resolveTemplateGitReferences(ctx, client, repository, templates, currentTag, currentCommit); err != nil {
			return Candidate{}, false, fmt.Errorf("resolve current recipe Git tag: %w", err)
		}
	}
	var candidates []Candidate
	if hasAssets {
		for _, release := range releases {
			version, ok := templates[0].TagTemplate.Extract(release.TagName)
			if !releaseAllowed(release, configured, packagePolicy.Channel) || !ok || !stableVersionPattern.MatchString(version) {
				continue
			}
			candidate, ok := matchGitHubReleaseAt(recipe, repository, templates, release, version, host)
			if ok {
				candidates = append(candidates, candidate)
			}
		}
	} else {
		for _, tag := range tags {
			known, allowed := releaseTagDisposition(releases, tag.Name, configured, packagePolicy.Channel)
			if (known && !allowed) || (configured && packagePolicy.Channel == "prerelease" && !known) {
				continue
			}
			version, ok := templates[0].TagTemplate.Extract(tag.Name)
			if !ok || !stableVersionPattern.MatchString(version) {
				continue
			}
			candidates = append(candidates, Candidate{Provider: "github", Repository: repository.String(), Tag: tag.Name, Version: version, FullVersion: candidateFullVersion(recipe, version), Confidence: "report-only", Reasons: []string{"GitHub Git tag matched pkgver", "tag resolves to an immutable Git commit"}})
		}
	}
	if len(candidates) == 0 {
		return Candidate{}, false, fmt.Errorf("no stable GitHub release or tag matched every declared source")
	}
	selected := candidates[0]
	for _, candidate := range candidates[1:] {
		cmp, err := compare(candidate.FullVersion, selected.FullVersion)
		if err != nil {
			return Candidate{}, false, fmt.Errorf("compare upstream versions: %w", err)
		}
		if cmp > 0 {
			selected = candidate
		}
	}
	if hasGit {
		selectedCommit, ok := tagSummaryCommit(tags, selected.Tag)
		if !ok {
			return Candidate{}, false, fmt.Errorf("selected Git tag %s is absent from recent GitHub tag metadata", selected.Tag)
		}
		selected.GitReferences, err = resolveTemplateGitReferences(ctx, client, repository, templates, selected.Tag, selectedCommit)
		if err != nil {
			return Candidate{}, false, fmt.Errorf("resolve selected Git tag: %w", err)
		}
		for _, reference := range selected.GitReferences {
			if reference.SignatureRequired && !reference.SignaturePresent {
				selected.Reasons = append(selected.Reasons, "recipe requests signed Git verification but selected tag has no annotated signature")
				break
			}
		}
		if anySignatureRequired(selected.GitReferences) && len(recipe.ValidPGPKeys) == 0 && len(packagePolicy.TrustedFingerprints) == 0 {
			selected.Reasons = append(selected.Reasons, "recipe requests signed Git verification but has no anchored fingerprint")
		}
	}
	selected.Host = host
	selected.APIOrigin = strings.TrimSuffix(client.BaseURL, "/")
	if selected.APIOrigin == "" {
		selected.APIOrigin = defaultGitHubAPI
	}
	selected.AssetHosts = append([]string(nil), client.AssetRedirectHosts...)
	selected.TrustedKeys = append([]string(nil), packagePolicy.TrustedFingerprints...)
	selected.Configured = configured
	if configured {
		selected.PolicyReason = "matched versioned per-package policy"
	}
	if cmp, err := compare(aurVersion, selected.FullVersion); err == nil {
		selected.NewerThanAUR = cmp < 0
	} else {
		return Candidate{}, false, fmt.Errorf("compare AUR and upstream versions: %w", err)
	}
	return selected, true, nil
}

func releaseTagDisposition(releases []githubRelease, tag string, configured bool, channel string) (bool, bool) {
	for _, release := range releases {
		if release.TagName == tag {
			return true, releaseAllowed(release, configured, channel)
		}
	}
	return false, false
}

func releaseByTag(releases []githubRelease, tag string) (githubRelease, bool) {
	for _, release := range releases {
		if release.TagName == tag {
			return release, true
		}
	}
	return githubRelease{}, false
}

func releaseAllowed(release githubRelease, configured bool, channel string) bool {
	if release.Draft {
		return false
	}
	if configured && channel == "prerelease" {
		return release.Prerelease
	}
	return !release.Prerelease
}

type githubTemplate struct {
	Source        Source
	Parsed        GitHubAssetURL
	ParsedGit     GitHubGitSourceURL
	Kind          string
	TagTemplate   stringTemplate
	AssetTemplate stringTemplate
}

type stringTemplate struct {
	Prefix string
	Suffix string
}

func newStringTemplate(value, token string, requireBoundaries bool) (stringTemplate, error) {
	if token == "" || strings.Count(value, token) != 1 {
		return stringTemplate{}, fmt.Errorf("value %q must contain pkgver %q exactly once", value, token)
	}
	index := strings.Index(value, token)
	if embeddedBefore(value, index) || embeddedAfter(value, index+len(token)) {
		return stringTemplate{}, fmt.Errorf("pkgver in %q is embedded in another version", value)
	}
	if requireBoundaries {
		if index > 0 && isASCIILetterOrDigit(value[index-1]) {
			return stringTemplate{}, fmt.Errorf("pkgver in %q is not a distinct token", value)
		}
		after := index + len(token)
		if after < len(value) && isASCIILetterOrDigit(value[after]) {
			return stringTemplate{}, fmt.Errorf("pkgver in %q is not a distinct token", value)
		}
	}
	return stringTemplate{Prefix: value[:index], Suffix: value[index+len(token):]}, nil
}

func embeddedBefore(value string, index int) bool {
	if index == 0 {
		return false
	}
	if value[index-1] >= '0' && value[index-1] <= '9' {
		return true
	}
	return index >= 2 && value[index-1] == '.' && value[index-2] >= '0' && value[index-2] <= '9'
}

func embeddedAfter(value string, index int) bool {
	if index == len(value) {
		return false
	}
	if value[index] >= '0' && value[index] <= '9' {
		return true
	}
	return index+1 < len(value) && value[index] == '.' && value[index+1] >= '0' && value[index+1] <= '9'
}

func (t stringTemplate) Apply(value string) string { return t.Prefix + value + t.Suffix }

func (t stringTemplate) Extract(value string) (string, bool) {
	if !strings.HasPrefix(value, t.Prefix) || !strings.HasSuffix(value, t.Suffix) || len(value) < len(t.Prefix)+len(t.Suffix) {
		return "", false
	}
	return value[len(t.Prefix) : len(value)-len(t.Suffix)], true
}

func isASCIILetterOrDigit(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func githubTemplates(recipe Recipe) (GitHubRepository, []githubTemplate, error) {
	var repository GitHubRepository
	var templates []githubTemplate
	var versionedNonGitHubSources []string
	for _, source := range recipe.Sources {
		parsed, err := ParseGitHubReleaseAssetURL(source.URL)
		if err != nil {
			parsedGit, gitErr := ParseGitHubGitSourceURL(source.URL)
			if gitErr == nil {
				if !stableVersionPattern.MatchString(recipe.Version) {
					return GitHubRepository{}, nil, fmt.Errorf("pkgver %q is outside the supported stable version grammar", recipe.Version)
				}
				if source.Alias != "" && strings.Contains(source.Alias, recipe.Version) {
					return GitHubRepository{}, nil, fmt.Errorf("Git source alias must not depend on pkgver")
				}
				tagTemplate, templateErr := newStringTemplate(parsedGit.Tag, recipe.Version, false)
				if templateErr != nil {
					return GitHubRepository{}, nil, fmt.Errorf("Git tag template: %w", templateErr)
				}
				if repository.Name == "" {
					repository = parsedGit.Repository
				} else if repository != parsedGit.Repository {
					return GitHubRepository{}, nil, fmt.Errorf("sources use multiple GitHub repositories")
				}
				if len(templates) > 0 && templates[0].TagTemplate != tagTemplate {
					return GitHubRepository{}, nil, fmt.Errorf("GitHub sources use inconsistent tag templates")
				}
				templates = append(templates, githubTemplate{Source: source, ParsedGit: parsedGit, Kind: "git", TagTemplate: tagTemplate})
				continue
			}
			if strings.Contains(source.URL, "github.com") {
				return GitHubRepository{}, nil, fmt.Errorf("ambiguous GitHub source %q: %v; %v", source.URL, err, gitErr)
			}
			if isRemoteSource(source.URL) && strings.Contains(source.URL, recipe.Version) {
				versionedNonGitHubSources = append(versionedNonGitHubSources, source.URL)
			}
			continue
		}
		if repository.Name == "" {
			repository = parsed.Repository
		} else if repository != parsed.Repository {
			return GitHubRepository{}, nil, fmt.Errorf("sources use multiple GitHub repositories")
		}
		assetTemplate, err := newStringTemplate(parsed.Name, recipe.Version, true)
		if err != nil {
			return GitHubRepository{}, nil, fmt.Errorf("asset template: %w", err)
		}
		tagTemplate, err := newStringTemplate(parsed.Tag, recipe.Version, false)
		if err != nil {
			return GitHubRepository{}, nil, fmt.Errorf("release tag template: %w", err)
		}
		if !stableVersionPattern.MatchString(recipe.Version) {
			return GitHubRepository{}, nil, fmt.Errorf("pkgver %q is outside the supported stable version grammar", recipe.Version)
		}
		if len(templates) > 0 && templates[0].TagTemplate != tagTemplate {
			return GitHubRepository{}, nil, fmt.Errorf("GitHub sources use inconsistent release tag templates")
		}
		templates = append(templates, githubTemplate{Source: source, Parsed: parsed, Kind: "asset", TagTemplate: tagTemplate, AssetTemplate: assetTemplate})
	}
	if len(templates) > 0 && len(versionedNonGitHubSources) > 0 {
		return GitHubRepository{}, nil, fmt.Errorf("version-dependent remote source %q is outside the selected GitHub release", versionedNonGitHubSources[0])
	}
	for _, arch := range recipe.Architectures {
		if arch == "any" {
			continue
		}
		covered := false
		for _, template := range templates {
			if template.Source.Architecture == "any" || template.Source.Architecture == arch {
				covered = true
				break
			}
		}
		if !covered {
			return GitHubRepository{}, nil, fmt.Errorf("no GitHub release source covers declared architecture %s", arch)
		}
	}
	return repository, templates, nil
}

func isRemoteSource(rawURL string) bool {
	u, err := url.Parse(rawURL)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func matchGitHubRelease(recipe Recipe, repository GitHubRepository, templates []githubTemplate, release githubRelease, version string) (Candidate, bool) {
	return matchGitHubReleaseAt(recipe, repository, templates, release, version, "github.com")
}

func matchGitHubReleaseAt(recipe Recipe, repository GitHubRepository, templates []githubTemplate, release githubRelease, version, host string) (Candidate, bool) {
	assetsByName := make(map[string]githubAsset, len(release.Assets))
	for _, asset := range release.Assets {
		assetsByName[asset.Name] = asset
	}
	var assets []Asset
	seen := map[string]bool{}
	for _, template := range templates {
		if template.Kind == "git" {
			continue
		}
		expected := template.AssetTemplate.Apply(version)
		asset, ok := assetsByName[expected]
		if !ok || asset.State != "uploaded" {
			return Candidate{}, false
		}
		key := template.Source.Architecture + "\x00" + expected
		if seen[key] {
			continue
		}
		seen[key] = true
		assets = append(assets, Asset{
			ID:           asset.ID,
			Architecture: template.Source.Architecture,
			Name:         expected, URL: asset.BrowserDownloadURL, Digest: asset.Digest, State: asset.State, Size: asset.Size,
			Sidecars: Sidecars{
				SHA256:       hasExactAsset(assetsByName, expected+".sha256"),
				Signature:    hasExactAsset(assetsByName, expected+".asc"),
				SHA256Signed: hasExactAsset(assetsByName, expected+".sha256.asc"),
			},
			SidecarAssets: collectSidecarAssets(assetsByName, expected),
		})
	}
	fullVersion := candidateFullVersion(recipe, version)
	reasons := []string{"stable release tag matched pkgver", "all declared GitHub release assets are present"}
	if release.AddedAssetCount > 0 {
		reasons = append(reasons, fmt.Sprintf("%d assets were added after initial observation; all previously observed assets are unchanged", release.AddedAssetCount))
	}
	return Candidate{
		Provider: "github", Repository: repository.String(), ReleaseID: release.ID,
		Tag: release.TagName, Version: version, FullVersion: fullVersion, Confidence: "report-only",
		Reasons: reasons, Assets: assets,
	}, true
}

func configuredGitHubTemplates(recipe Recipe, policy PackagePolicy) (GitHubRepository, []githubTemplate, error) {
	parts := strings.Split(policy.Repository, "/")
	repository := GitHubRepository{Owner: parts[0], Name: parts[1]}
	tagTemplate := stringTemplate{Prefix: strings.Split(policy.TagTemplate, "{version}")[0], Suffix: strings.Split(policy.TagTemplate, "{version}")[1]}
	var templates []githubTemplate
	seenMappings := map[string]bool{}
	for _, source := range recipe.Sources {
		if !isRemoteSource(source.URL) || !strings.Contains(source.URL, recipe.Version) {
			continue
		}
		if parsedGit, gitErr := ParseGitHubGitSourceURLAt(source.URL, policy.Host); gitErr == nil {
			if parsedGit.Repository != repository || parsedGit.Tag != tagTemplate.Apply(recipe.Version) {
				return GitHubRepository{}, nil, fmt.Errorf("policy Git source %q does not match configured repository and tag", source.URL)
			}
			if source.Alias != "" && strings.Contains(source.Alias, recipe.Version) {
				return GitHubRepository{}, nil, fmt.Errorf("Git source alias must not depend on pkgver")
			}
			templates = append(templates, githubTemplate{Source: source, ParsedGit: parsedGit, Kind: "git", TagTemplate: tagTemplate})
			continue
		}
		assetPattern, mapped := policy.AssetTemplates[source.Architecture]
		if !mapped {
			assetPattern, mapped = policy.AssetTemplates["any"]
		}
		if !mapped {
			return GitHubRepository{}, nil, fmt.Errorf("policy does not map versioned remote source architecture %s", source.Architecture)
		}
		parsed, err := ParseGitHubReleaseAssetURLAt(source.URL, policy.Host)
		if err != nil || parsed.Repository != repository {
			return GitHubRepository{}, nil, fmt.Errorf("policy source %q is not an unambiguous configured release asset", source.URL)
		}
		assetParts := strings.Split(assetPattern, "{version}")
		assetTemplate := stringTemplate{Prefix: assetParts[0], Suffix: assetParts[1]}
		if parsed.Tag != tagTemplate.Apply(recipe.Version) || parsed.Name != assetTemplate.Apply(recipe.Version) {
			return GitHubRepository{}, nil, fmt.Errorf("policy templates do not match current source %q", source.URL)
		}
		mappingKey := source.Architecture + "\x00" + parsed.Name
		if seenMappings[mappingKey] {
			return GitHubRepository{}, nil, fmt.Errorf("policy maps multiple versioned sources to %s for architecture %s", parsed.Name, source.Architecture)
		}
		seenMappings[mappingKey] = true
		templates = append(templates, githubTemplate{Source: source, Parsed: parsed, Kind: "asset", TagTemplate: tagTemplate, AssetTemplate: assetTemplate})
	}
	if len(templates) == 0 {
		return GitHubRepository{}, nil, fmt.Errorf("policy maps no versioned remote release sources")
	}
	return repository, templates, nil
}

func collectSidecarAssets(assets map[string]githubAsset, name string) []SidecarAsset {
	var result []SidecarAsset
	for _, suffix := range []string{".sha256", ".asc", ".sha256.asc"} {
		asset, ok := assets[name+suffix]
		if !ok || asset.State != "uploaded" {
			continue
		}
		result = append(result, SidecarAsset{ID: asset.ID, Kind: suffix, Name: asset.Name, URL: asset.BrowserDownloadURL, Digest: asset.Digest, State: asset.State, Size: asset.Size})
	}
	return result
}

func candidateFullVersion(recipe Recipe, version string) string {
	value := version + "-1"
	if recipe.Epoch != "" && recipe.Epoch != "0" {
		value = recipe.Epoch + ":" + value
	}
	return value
}

func hasExactAsset(assets map[string]githubAsset, name string) bool {
	asset, ok := assets[name]
	return ok && asset.State == "uploaded"
}
