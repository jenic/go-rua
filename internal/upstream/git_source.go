package upstream

import (
	"fmt"
	"net/url"
	"strings"
)

type GitHubGitSourceURL struct {
	Repository GitHubRepository
	Tag        string
	Signed     bool
	CloneURL   string
}

func ParseGitHubGitSourceURL(rawURL string) (GitHubGitSourceURL, error) {
	return ParseGitHubGitSourceURLAt(rawURL, "github.com")
}

func ParseGitHubGitSourceURLAt(rawURL, host string) (GitHubGitSourceURL, error) {
	if !isASCII(rawURL) || !strings.HasPrefix(rawURL, "git+https://") {
		return GitHubGitSourceURL{}, fmt.Errorf("Git source must use git+https")
	}
	if strings.ContainsAny(rawURL, "\r\n\x00") || strings.Contains(rawURL, "%") {
		return GitHubGitSourceURL{}, fmt.Errorf("Git source contains ambiguous encoding or control characters")
	}
	ordinary := strings.TrimPrefix(rawURL, "git+")
	u, err := url.Parse(ordinary)
	if err != nil {
		return GitHubGitSourceURL{}, fmt.Errorf("invalid Git source URL: %w", err)
	}
	canonical, err := canonicalHost(host, strings.Contains(host, ":"))
	if err != nil || u.Scheme != "https" || u.Host != canonical || u.User != nil || u.RawPath != "" {
		return GitHubGitSourceURL{}, fmt.Errorf("Git source must use canonical git+https://%s", host)
	}
	parts := splitPath(u.Path)
	if len(parts) != 2 || !validGitHubComponent(parts[0]) || !validGitHubComponent(parts[1]) {
		return GitHubGitSourceURL{}, fmt.Errorf("Git source does not identify one GitHub repository")
	}
	repositoryName := strings.TrimSuffix(parts[1], ".git")
	if repositoryName == "" {
		return GitHubGitSourceURL{}, fmt.Errorf("empty GitHub repository")
	}

	fragment := u.Fragment
	signed := false
	if strings.HasSuffix(fragment, "?signed") {
		signed = true
		fragment = strings.TrimSuffix(fragment, "?signed")
	}
	if u.RawQuery != "" {
		if u.RawQuery != "signed" || signed {
			return GitHubGitSourceURL{}, fmt.Errorf("Git source has unsupported or duplicate query")
		}
		signed = true
	}
	if !strings.HasPrefix(fragment, "tag=") || strings.Count(fragment, "=") != 1 {
		return GitHubGitSourceURL{}, fmt.Errorf("Git source must pin exactly one tag fragment")
	}
	tag := strings.TrimPrefix(fragment, "tag=")
	if !validGitRefName(tag) {
		return GitHubGitSourceURL{}, fmt.Errorf("Git source tag is not a conservative ref name")
	}
	clone := "git+https://" + canonical + "/" + parts[0] + "/" + parts[1]
	return GitHubGitSourceURL{Repository: GitHubRepository{Owner: parts[0], Name: repositoryName}, Tag: tag, Signed: signed, CloneURL: clone}, nil
}

func validGitRefName(value string) bool {
	if value == "" || len(value) > 1024 || value == "@" || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return false
	}
	if strings.Contains(value, "..") || strings.Contains(value, "@{") || strings.Contains(value, "//") || strings.ContainsAny(value, " ~^:?*[\\") {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || strings.HasPrefix(component, ".") || strings.HasSuffix(component, ".") || strings.HasSuffix(component, ".lock") {
			return false
		}
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func rewriteGitSourceToCommit(source, commit, host string) (string, error) {
	alias, rawURL := "", source
	if left, right, ok := strings.Cut(source, "::"); ok {
		alias, rawURL = left, right
	}
	parsed, err := ParseGitHubGitSourceURLAt(rawURL, host)
	if err != nil {
		return "", err
	}
	if !validGitObjectID(commit) {
		return "", fmt.Errorf("invalid immutable Git commit identity")
	}
	next := parsed.CloneURL + "#commit=" + strings.ToLower(commit)
	if alias != "" {
		next = alias + "::" + next
	}
	return next, nil
}

func validGitObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}
