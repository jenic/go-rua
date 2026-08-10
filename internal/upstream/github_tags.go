package upstream

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxGitHubTags = 100

type githubTagSummary struct {
	Name   string `json:"name"`
	Commit struct {
		SHA string `json:"sha"`
		URL string `json:"url"`
	} `json:"commit"`
}

type githubTagCacheRecord struct {
	ETag    string          `json:"etag"`
	Body    json.RawMessage `json:"body"`
	History []tagEvidence   `json:"history,omitempty"`
}

type tagEvidence struct {
	NameHash  string `json:"name_hash"`
	CommitSHA string `json:"commit_sha"`
	RefSHA    string `json:"ref_sha,omitempty"`
}

type githubReferenceResponse struct {
	Ref    string `json:"ref"`
	Object struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
		URL  string `json:"url"`
	} `json:"object"`
}

type githubTagObjectResponse struct {
	Tag    string `json:"tag"`
	SHA    string `json:"sha"`
	Object struct {
		Type string `json:"type"`
		SHA  string `json:"sha"`
		URL  string `json:"url"`
	} `json:"object"`
	Verification struct {
		Verified  bool   `json:"verified"`
		Reason    string `json:"reason"`
		Signature string `json:"signature"`
		Payload   string `json:"payload"`
	} `json:"verification"`
}

func (c *GitHubClient) Tags(ctx context.Context, repository GitHubRepository) ([]githubTagSummary, error) {
	base, parsedBase, err := c.apiBase()
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("%s/repos/%s/%s/tags?per_page=%d", base, url.PathEscape(repository.Owner), url.PathEscape(repository.Name), maxGitHubTags)
	cachePath := c.cachePath(u)
	cached, _ := readGitHubTagCache(cachePath)
	status, etag, body, err := c.apiGET(ctx, parsedBase, u, cached.ETag, maxGitHubBody)
	if err != nil {
		return nil, fmt.Errorf("GitHub tags request: %w", err)
	}
	if cachePath == "" {
		return reconcileGitHubTagCache("", status, etag, body, cached, repository, base)
	}
	lock, err := acquireGitHubCacheLock(cachePath)
	if err != nil {
		return nil, err
	}
	defer releaseEvidenceLock(lock)
	latest, err := readGitHubTagCache(cachePath)
	if os.IsNotExist(err) {
		latest = githubTagCacheRecord{}
	} else if err != nil {
		return nil, fmt.Errorf("read current GitHub tag cache: %w", err)
	}
	return reconcileGitHubTagCache(cachePath, status, etag, body, latest, repository, base)
}

func (c *GitHubClient) ResolveTag(ctx context.Context, repository GitHubRepository, tag string) (GitReference, error) {
	if !validGitRefName(tag) {
		return GitReference{}, fmt.Errorf("invalid Git tag name")
	}
	base, parsedBase, err := c.apiBase()
	if err != nil {
		return GitReference{}, err
	}
	refURL := fmt.Sprintf("%s/repos/%s/%s/git/ref/tags/%s", base, url.PathEscape(repository.Owner), url.PathEscape(repository.Name), url.PathEscape(tag))
	status, _, body, err := c.apiGET(ctx, parsedBase, refURL, "", maxGitHubBody)
	if err != nil {
		return GitReference{}, fmt.Errorf("resolve Git tag reference: %w", err)
	}
	if status != http.StatusOK {
		return GitReference{}, fmt.Errorf("GitHub Git reference API HTTP %d", status)
	}
	var ref githubReferenceResponse
	if err := json.Unmarshal(body, &ref); err != nil {
		return GitReference{}, fmt.Errorf("decode Git tag reference: %w", err)
	}
	if ref.Ref != "refs/tags/"+tag || !validGitObjectID(ref.Object.SHA) || (ref.Object.Type != "tag" && ref.Object.Type != "commit") {
		return GitReference{}, fmt.Errorf("GitHub Git reference metadata is inconsistent")
	}
	result := GitReference{Tag: tag, RefSHA: strings.ToLower(ref.Object.SHA), CommitSHA: strings.ToLower(ref.Object.SHA), ObjectType: ref.Object.Type}
	if ref.Object.Type == "commit" {
		if err := validateGitAPIObjectURL(ref.Object.URL, base, repository, "commits", ref.Object.SHA); err != nil {
			return GitReference{}, err
		}
		if err := c.recordResolvedTag(repository, result); err != nil {
			return GitReference{}, err
		}
		return result, nil
	}
	if err := validateGitAPIObjectURL(ref.Object.URL, base, repository, "tags", ref.Object.SHA); err != nil {
		return GitReference{}, err
	}
	tagURL := fmt.Sprintf("%s/repos/%s/%s/git/tags/%s", base, url.PathEscape(repository.Owner), url.PathEscape(repository.Name), strings.ToLower(ref.Object.SHA))
	status, _, body, err = c.apiGET(ctx, parsedBase, tagURL, "", maxGitHubBody)
	if err != nil {
		return GitReference{}, fmt.Errorf("resolve annotated Git tag: %w", err)
	}
	if status != http.StatusOK {
		return GitReference{}, fmt.Errorf("GitHub Git tag API HTTP %d", status)
	}
	var object githubTagObjectResponse
	if err := json.Unmarshal(body, &object); err != nil {
		return GitReference{}, fmt.Errorf("decode annotated Git tag: %w", err)
	}
	if object.Tag != tag || !strings.EqualFold(object.SHA, ref.Object.SHA) || object.Object.Type != "commit" || !validGitObjectID(object.Object.SHA) {
		return GitReference{}, fmt.Errorf("annotated Git tag metadata is inconsistent")
	}
	if err := validateGitAPIObjectURL(object.Object.URL, base, repository, "commits", object.Object.SHA); err != nil {
		return GitReference{}, err
	}
	if (object.Verification.Signature == "") != (object.Verification.Payload == "") {
		return GitReference{}, fmt.Errorf("annotated Git tag signature metadata is incomplete")
	}
	result.CommitSHA = strings.ToLower(object.Object.SHA)
	result.SignaturePresent = object.Verification.Signature != "" && object.Verification.Payload != ""
	if result.SignaturePresent {
		result.Signature = []byte(object.Verification.Signature)
		result.Payload = []byte(object.Verification.Payload)
	}
	if err := c.recordResolvedTag(repository, result); err != nil {
		return GitReference{}, err
	}
	return result, nil
}

func (c *GitHubClient) recordResolvedTag(repository GitHubRepository, reference GitReference) error {
	if c.CacheDir == "" {
		return nil
	}
	base, _, err := c.apiBase()
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/repos/%s/%s/tags?per_page=%d", base, url.PathEscape(repository.Owner), url.PathEscape(repository.Name), maxGitHubTags)
	cachePath := c.cachePath(endpoint)
	lock, err := acquireGitHubCacheLock(cachePath)
	if err != nil {
		return err
	}
	defer releaseEvidenceLock(lock)
	record, err := readGitHubTagCache(cachePath)
	if os.IsNotExist(err) {
		record = githubTagCacheRecord{}
	} else if err != nil {
		return fmt.Errorf("read current GitHub tag cache: %w", err)
	}
	current := evidenceForResolvedTag(reference)
	for _, previous := range record.History {
		if previous.NameHash != current.NameHash {
			continue
		}
		if previous.CommitSHA != current.CommitSHA || (previous.RefSHA != "" && previous.RefSHA != current.RefSHA) {
			return fmt.Errorf("GitHub tag or reference identity mutated for %s", reference.Tag)
		}
	}
	record.History = mergeResolvedTagEvidence(record.History, current)
	if err := writeGitHubTagCache(cachePath, record); err != nil {
		return fmt.Errorf("write resolved GitHub tag cache: %w", err)
	}
	return nil
}

func (c *GitHubClient) apiBase() (string, *url.URL, error) {
	base := strings.TrimSuffix(c.BaseURL, "/")
	if base == "" {
		base = defaultGitHubAPI
	}
	parsed, err := parseOrigin(base, c.AllowPort)
	if err != nil {
		return "", nil, fmt.Errorf("invalid GitHub API base URL")
	}
	return base, parsed, nil
}

func (c *GitHubClient) apiGET(ctx context.Context, base *url.URL, requestURL, etag string, limit int64) (int, string, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return 0, "", nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	origin := base.Scheme + "://" + base.Host
	if c.Token != "" && (c.TokenOrigin == origin || c.TokenOrigin == "" && origin == defaultGitHubAPI) {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	requestClient := *client
	requestClient.CheckRedirect = func(*http.Request, []*http.Request) error { return fmt.Errorf("GitHub API redirect refused") }
	resp, err := requestClient.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	if resp.Request != nil && (resp.Request.URL.Scheme != base.Scheme || resp.Request.URL.Host != base.Host || resp.Request.URL.Path != req.URL.Path || resp.Request.URL.RawQuery != req.URL.RawQuery) {
		return 0, "", nil, fmt.Errorf("GitHub API response origin or path changed")
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotModified {
		return resp.StatusCode, resp.Header.Get("ETag"), nil, nil
	}
	if resp.StatusCode == http.StatusNotModified {
		return resp.StatusCode, resp.Header.Get("ETag"), nil, nil
	}
	body, err := readLimited(resp.Body, limit)
	return resp.StatusCode, resp.Header.Get("ETag"), body, err
}

func reconcileGitHubTagCache(path string, status int, etag string, body []byte, cached githubTagCacheRecord, repository GitHubRepository, base string) ([]githubTagSummary, error) {
	if status == http.StatusNotModified {
		if len(cached.Body) == 0 {
			return nil, fmt.Errorf("GitHub returned 304 without cached tags")
		}
		return decodeAndValidateTags(cached.Body, repository, base)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("GitHub tags API HTTP %d", status)
	}
	tags, err := decodeAndValidateTags(body, repository, base)
	if err != nil {
		return nil, err
	}
	if err := detectTagMutation(cached.History, tags); err != nil {
		return nil, err
	}
	history := mergeTagEvidence(cached.History, tags)
	if path != "" {
		if err := writeGitHubTagCache(path, githubTagCacheRecord{ETag: etag, Body: body, History: history}); err != nil {
			return nil, err
		}
	}
	return tags, nil
}

func decodeAndValidateTags(body []byte, repository GitHubRepository, base string) ([]githubTagSummary, error) {
	var tags []githubTagSummary
	if err := json.Unmarshal(body, &tags); err != nil {
		return nil, fmt.Errorf("decode GitHub tags: %w", err)
	}
	if len(tags) > maxGitHubTags {
		return nil, fmt.Errorf("GitHub returned more than %d tags", maxGitHubTags)
	}
	seen := map[string]bool{}
	for _, tag := range tags {
		if !validGitRefName(tag.Name) || !validGitObjectID(tag.Commit.SHA) || seen[tag.Name] {
			return nil, fmt.Errorf("GitHub tag metadata is malformed or duplicated")
		}
		seen[tag.Name] = true
		if err := validateRepositoryCommitURL(tag.Commit.URL, base, repository, tag.Commit.SHA); err != nil {
			return nil, err
		}
	}
	return tags, nil
}

func validateRepositoryCommitURL(raw, base string, repository GitHubRepository, sha string) error {
	want := fmt.Sprintf("%s/repos/%s/%s/commits/%s", base, url.PathEscape(repository.Owner), url.PathEscape(repository.Name), strings.ToLower(sha))
	if raw != want {
		return fmt.Errorf("GitHub tag commit URL is inconsistent")
	}
	return nil
}

func validateGitAPIObjectURL(raw, base string, repository GitHubRepository, kind, sha string) error {
	want := fmt.Sprintf("%s/repos/%s/%s/git/%s/%s", base, url.PathEscape(repository.Owner), url.PathEscape(repository.Name), kind, strings.ToLower(sha))
	if raw != want {
		return fmt.Errorf("GitHub Git object URL is inconsistent")
	}
	return nil
}

func detectTagMutation(history []tagEvidence, tags []githubTagSummary) error {
	for _, tag := range tags {
		current := evidenceForTag(tag)
		for _, previous := range history {
			if previous.NameHash == current.NameHash && previous.CommitSHA != current.CommitSHA {
				return fmt.Errorf("GitHub tag identity mutated for %s", tag.Name)
			}
		}
	}
	return nil
}

func mergeTagEvidence(history []tagEvidence, tags []githubTagSummary) []tagEvidence {
	for _, tag := range tags {
		evidence := evidenceForTag(tag)
		var refreshed []tagEvidence
		for _, existing := range history {
			if existing.NameHash == evidence.NameHash {
				if existing.RefSHA != "" {
					evidence.RefSHA = existing.RefSHA
				}
				continue
			}
			refreshed = append(refreshed, existing)
		}
		history = append(refreshed, evidence)
	}
	if len(history) > maxReleaseHistory {
		history = append([]tagEvidence(nil), history[len(history)-maxReleaseHistory:]...)
	}
	return history
}

func evidenceForTag(tag githubTagSummary) tagEvidence {
	sum := sha256.Sum256([]byte(tag.Name))
	return tagEvidence{NameHash: hex.EncodeToString(sum[:]), CommitSHA: strings.ToLower(tag.Commit.SHA)}
}

func evidenceForResolvedTag(reference GitReference) tagEvidence {
	sum := sha256.Sum256([]byte(reference.Tag))
	return tagEvidence{NameHash: hex.EncodeToString(sum[:]), CommitSHA: strings.ToLower(reference.CommitSHA), RefSHA: strings.ToLower(reference.RefSHA)}
}

func mergeResolvedTagEvidence(history []tagEvidence, current tagEvidence) []tagEvidence {
	result := make([]tagEvidence, 0, len(history)+1)
	for _, existing := range history {
		if existing.NameHash != current.NameHash {
			result = append(result, existing)
		}
	}
	result = append(result, current)
	if len(result) > maxReleaseHistory {
		result = append([]tagEvidence(nil), result[len(result)-maxReleaseHistory:]...)
	}
	return result
}

func readGitHubTagCache(path string) (githubTagCacheRecord, error) {
	if path == "" {
		return githubTagCacheRecord{}, os.ErrNotExist
	}
	f, err := os.Open(path)
	if err != nil {
		return githubTagCacheRecord{}, err
	}
	defer f.Close()
	data, err := readLimited(f, maxGitHubCache)
	if err != nil {
		return githubTagCacheRecord{}, err
	}
	var record githubTagCacheRecord
	if err := decodeStrict(data, &record); err != nil {
		return githubTagCacheRecord{}, err
	}
	return record, nil
}

func writeGitHubTagCache(path string, record githubTagCacheRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if int64(len(data)) > maxGitHubCache {
		return fmt.Errorf("tag cache exceeds %d bytes", maxGitHubCache)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".github-tag-cache-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
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
	return os.Rename(name, path)
}

func templateKinds(templates []githubTemplate) (assets, git bool) {
	for _, template := range templates {
		switch template.Kind {
		case "asset":
			assets = true
		case "git":
			git = true
		}
	}
	return assets, git
}

func tagSummaryExists(tags []githubTagSummary, name string) bool {
	_, ok := tagSummaryCommit(tags, name)
	return ok
}

func tagSummaryCommit(tags []githubTagSummary, name string) (string, bool) {
	for _, tag := range tags {
		if tag.Name == name {
			return strings.ToLower(tag.Commit.SHA), true
		}
	}
	return "", false
}

func resolveTemplateGitReferences(ctx context.Context, client *GitHubClient, repository GitHubRepository, templates []githubTemplate, tag, expectedCommit string) ([]GitReference, error) {
	resolved, err := client.ResolveTag(ctx, repository, tag)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(resolved.CommitSHA, expectedCommit) {
		return nil, fmt.Errorf("GitHub tag list and exact Git reference disagree for %s", tag)
	}
	var references []GitReference
	for _, template := range templates {
		if template.Kind != "git" {
			continue
		}
		item := resolved
		item.Architecture = template.Source.Architecture
		item.SourceKey = template.Source.Key
		item.SourceIndex = template.Source.Index
		item.SourceName = template.Source.Name
		item.SignatureRequired = template.ParsedGit.Signed
		references = append(references, item)
	}
	sort.Slice(references, func(i, j int) bool {
		if references[i].SourceKey != references[j].SourceKey {
			return references[i].SourceKey < references[j].SourceKey
		}
		return references[i].SourceIndex < references[j].SourceIndex
	})
	return references, nil
}

func anySignatureRequired(references []GitReference) bool {
	for _, reference := range references {
		if reference.SignatureRequired {
			return true
		}
	}
	return false
}
