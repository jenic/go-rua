package upstream

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

const (
	gitCommit123 = "0123456789abcdef0123456789abcdef01234567"
	gitCommit124 = "1123456789abcdef0123456789abcdef01234567"
	gitTagObject = "2123456789abcdef0123456789abcdef01234567"
)

func TestGitHubClientListsTagsAndResolvesLightweightReference(t *testing.T) {
	repository := GitHubRepository{Owner: "acme", Name: "app"}
	client := &GitHubClient{BaseURL: "https://api.github.test", HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/repos/acme/app/tags":
			if request.URL.Query().Get("per_page") != "100" {
				t.Fatalf("per_page = %q", request.URL.Query().Get("per_page"))
			}
			return testHTTPResponse(http.StatusOK, tagListJSON("v1.2.3", gitCommit123)), nil
		case "/repos/acme/app/git/ref/tags/v1.2.3":
			return testHTTPResponse(http.StatusOK, referenceJSON("v1.2.3", "commit", gitCommit123)), nil
		default:
			return nil, fmt.Errorf("unexpected request %s", request.URL.String())
		}
	})}}
	tags, err := client.Tags(context.Background(), repository)
	if err != nil || len(tags) != 1 || tags[0].Commit.SHA != gitCommit123 {
		t.Fatalf("tags=%#v err=%v", tags, err)
	}
	reference, err := client.ResolveTag(context.Background(), repository, "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if reference.ObjectType != "commit" || reference.RefSHA != gitCommit123 || reference.CommitSHA != gitCommit123 || reference.SignaturePresent {
		t.Fatalf("reference=%#v", reference)
	}
}

func TestGitHubClientResolvesAnnotatedTagSignatureMetadata(t *testing.T) {
	client := &GitHubClient{BaseURL: "https://api.github.test", HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/repos/acme/app/git/ref/tags/v1.2.4":
			return testHTTPResponse(http.StatusOK, referenceJSON("v1.2.4", "tag", gitTagObject)), nil
		case "/repos/acme/app/git/tags/" + gitTagObject:
			return testHTTPResponse(http.StatusOK, annotatedTagJSON("v1.2.4", gitTagObject, gitCommit124, "signature", "payload")), nil
		default:
			return nil, fmt.Errorf("unexpected request %s", request.URL.String())
		}
	})}}
	reference, err := client.ResolveTag(context.Background(), GitHubRepository{Owner: "acme", Name: "app"}, "v1.2.4")
	if err != nil {
		t.Fatal(err)
	}
	if reference.ObjectType != "tag" || reference.RefSHA != gitTagObject || reference.CommitSHA != gitCommit124 || !reference.SignaturePresent || string(reference.Signature) != "signature" || string(reference.Payload) != "payload" {
		t.Fatalf("reference=%#v", reference)
	}
}

func TestGitHubClientRejectsIncompleteTagSignatureAndCachedMutation(t *testing.T) {
	t.Run("incomplete signature", func(t *testing.T) {
		client := &GitHubClient{BaseURL: "https://api.github.test", HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if strings.Contains(request.URL.Path, "/git/ref/") {
				return testHTTPResponse(http.StatusOK, referenceJSON("v1.2.4", "tag", gitTagObject)), nil
			}
			return testHTTPResponse(http.StatusOK, annotatedTagJSON("v1.2.4", gitTagObject, gitCommit124, "signature", "")), nil
		})}}
		_, err := client.ResolveTag(context.Background(), GitHubRepository{Owner: "acme", Name: "app"}, "v1.2.4")
		if err == nil || !strings.Contains(err.Error(), "incomplete") {
			t.Fatalf("incomplete signature metadata accepted: %v", err)
		}
	})

	t.Run("tag mutation", func(t *testing.T) {
		calls := 0
		client := &GitHubClient{BaseURL: "https://api.github.test", CacheDir: prepareGitHubCacheDir(t), HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			commit := gitCommit123
			if calls == 2 {
				commit = gitCommit124
			}
			return testHTTPResponse(http.StatusOK, tagListJSON("v1.2.3", commit)), nil
		})}}
		repository := GitHubRepository{Owner: "acme", Name: "app"}
		if _, err := client.Tags(context.Background(), repository); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Tags(context.Background(), repository); err == nil || !strings.Contains(err.Error(), "mutated") {
			t.Fatalf("mutated tag accepted: %v", err)
		}
	})

	t.Run("annotated ref mutation with same commit", func(t *testing.T) {
		calls := 0
		secondTagObject := "3123456789abcdef0123456789abcdef01234567"
		client := &GitHubClient{BaseURL: "https://api.github.test", CacheDir: prepareGitHubCacheDir(t), HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if strings.Contains(request.URL.Path, "/git/ref/") {
				calls++
				object := gitTagObject
				if calls == 2 {
					object = secondTagObject
				}
				return testHTTPResponse(http.StatusOK, referenceJSON("v1.2.4", "tag", object)), nil
			}
			object := gitTagObject
			if strings.HasSuffix(request.URL.Path, secondTagObject) {
				object = secondTagObject
			}
			return testHTTPResponse(http.StatusOK, annotatedTagJSON("v1.2.4", object, gitCommit124, "", "")), nil
		})}}
		repository := GitHubRepository{Owner: "acme", Name: "app"}
		if _, err := client.ResolveTag(context.Background(), repository, "v1.2.4"); err != nil {
			t.Fatal(err)
		}
		if _, err := client.ResolveTag(context.Background(), repository, "v1.2.4"); err == nil || !strings.Contains(err.Error(), "mutated") {
			t.Fatalf("mutated annotated ref accepted: %v", err)
		}
	})
}

func TestGitHubProviderDetectsGitSourceAndPinsSelectedCommit(t *testing.T) {
	client := &GitHubClient{BaseURL: "https://api.github.test", HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/repos/acme/app/releases":
			return testHTTPResponse(http.StatusOK, `[{"id":25,"tag_name":"v1.2.5","draft":false,"prerelease":true,"assets":[]}]`), nil
		case "/repos/acme/app/tags":
			body := "[" + strings.Trim(tagListJSON("v1.2.3", gitCommit123), "[]") + "," + strings.Trim(tagListJSON("v1.2.4", gitCommit124), "[]") + "," + strings.Trim(tagListJSON("v1.2.5", gitTagObject), "[]") + "]"
			return testHTTPResponse(http.StatusOK, body), nil
		case "/repos/acme/app/git/ref/tags/v1.2.3":
			return testHTTPResponse(http.StatusOK, referenceJSON("v1.2.3", "commit", gitCommit123)), nil
		case "/repos/acme/app/git/ref/tags/v1.2.4":
			return testHTTPResponse(http.StatusOK, referenceJSON("v1.2.4", "commit", gitCommit124)), nil
		default:
			return nil, fmt.Errorf("unexpected request %s", request.URL.String())
		}
	})}}
	recipe := Recipe{
		PackageBase: "app-git", Version: "1.2.3", Release: "1", Architectures: []string{"any"},
		Sources:   []Source{{Architecture: "any", Key: "source", Index: 0, Name: "checkout", Alias: "checkout", URL: "git+https://github.com/acme/app.git#tag=v1.2.3"}},
		Checksums: map[string][]string{"sha256sums": {"SKIP"}},
	}
	candidate, found, err := (GitHubProvider{Client: client}).Detect(context.Background(), recipe, "1.2.3-1", numericCompare)
	if err != nil || !found {
		t.Fatalf("candidate=%#v found=%v err=%v", candidate, found, err)
	}
	if candidate.Tag != "v1.2.4" || candidate.Version != "1.2.4" || !candidate.NewerThanAUR || len(candidate.GitReferences) != 1 || candidate.GitReferences[0].CommitSHA != gitCommit124 {
		t.Fatalf("candidate=%#v", candidate)
	}
}

func TestGitHubProviderRejectsTagListAndReferenceDisagreement(t *testing.T) {
	client := &GitHubClient{BaseURL: "https://api.github.test", HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/repos/acme/app/releases":
			return testHTTPResponse(http.StatusOK, `[]`), nil
		case "/repos/acme/app/tags":
			return testHTTPResponse(http.StatusOK, tagListJSON("v1.2.3", gitCommit123)), nil
		case "/repos/acme/app/git/ref/tags/v1.2.3":
			return testHTTPResponse(http.StatusOK, referenceJSON("v1.2.3", "commit", gitCommit124)), nil
		default:
			return nil, fmt.Errorf("unexpected request %s", request.URL.String())
		}
	})}}
	recipe := Recipe{PackageBase: "app-git", Version: "1.2.3", Release: "1", Sources: []Source{{Architecture: "any", Key: "source", URL: "git+https://github.com/acme/app.git#tag=v1.2.3"}}}
	_, _, err := (GitHubProvider{Client: client}).Detect(context.Background(), recipe, "1.2.3-1", numericCompare)
	if err == nil || !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("inconsistent tag identity accepted: %v", err)
	}
}

func tagListJSON(tag, commit string) string {
	return fmt.Sprintf(`[{"name":%q,"commit":{"sha":%q,"url":%q},"zipball_url":"https://api.github.test/zip","tarball_url":"https://api.github.test/tar","node_id":"tag-node"}]`, tag, commit, "https://api.github.test/repos/acme/app/commits/"+commit)
}

func referenceJSON(tag, kind, sha string) string {
	return fmt.Sprintf(`{"ref":%q,"node_id":"ref-node","url":"https://api.github.test/ref","object":{"type":%q,"sha":%q,"url":%q}}`, "refs/tags/"+tag, kind, sha, "https://api.github.test/repos/acme/app/git/"+kind+"s/"+sha)
}

func annotatedTagJSON(tag, tagSHA, commit, signature, payload string) string {
	return fmt.Sprintf(`{"tag":%q,"sha":%q,"node_id":"tag-node","url":"https://api.github.test/tag","message":"release","tagger":{"name":"Release Bot"},"object":{"type":"commit","sha":%q,"url":%q},"verification":{"verified":true,"reason":"valid","signature":%q,"payload":%q}}`, tag, tagSHA, commit, "https://api.github.test/repos/acme/app/git/commits/"+commit, signature, payload)
}
