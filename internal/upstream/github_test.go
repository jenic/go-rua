package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestStrictGitHubURLParsing(t *testing.T) {
	good := "https://github.com/brave/brave-browser/releases/download/v1.2.3/brave-1.2.3.zip"
	asset, err := ParseGitHubReleaseAssetURL(good)
	if err != nil || asset.Repository.String() != "brave/brave-browser" || asset.Tag != "v1.2.3" {
		t.Fatalf("parse good URL: asset=%#v err=%v", asset, err)
	}
	bad := []string{
		"http://github.com/brave/brave-browser/releases/download/v1/x",
		"https://user@github.com/brave/brave-browser/releases/download/v1/x",
		"https://github.com.evil.test/brave/brave-browser/releases/download/v1/x",
		"https://github.com/brave/brave-browser/releases/latest/download/x",
		"https://github.com/brave/brave-browser/releases/download/v1/x?raw=1",
		"https://github.com/brave/brave-browser/releases/download/v1/a%2Fx",
		"https://githüb.com/brave/brave-browser/releases/download/v1/x",
		"https://github.com/brave/.git/releases/download/v1/x",
	}
	for _, value := range bad {
		if _, err := ParseGitHubReleaseAssetURL(value); err == nil {
			t.Errorf("accepted ambiguous URL %q", value)
		}
	}
}

func TestGitHubClientRetainsMutationEvidenceAcrossAbsentPage(t *testing.T) {
	original := "[" + releaseJSON("v1.2.3", false, false, []string{"app-1.2.3.zip"}) + "]"
	absent := "[" + releaseJSON("v2.0.0", false, false, []string{"app-2.0.0.zip"}) + "]"
	reappeared := releaseJSON("v1.2.3", false, false, []string{"app-1.2.3.zip"})
	reappeared = strings.Replace(reappeared, `"id":`+strconv.Itoa(releaseIDForTag("v1.2.3")), `"id":999`, 1)
	reappeared = "[" + reappeared + "]"
	responses := []string{original, absent, reappeared}
	calls := 0
	client := &GitHubClient{BaseURL: "https://api.github.test", CacheDir: prepareGitHubCacheDir(t), HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		response := testHTTPResponse(http.StatusOK, responses[calls])
		calls++
		response.Header.Set("ETag", fmt.Sprintf(`"etag-%d"`, calls))
		return response, nil
	})}}
	repository := GitHubRepository{Owner: "brave", Name: "brave-browser"}
	if _, err := client.Releases(context.Background(), repository); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Releases(context.Background(), repository); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Releases(context.Background(), repository); err == nil || !strings.Contains(err.Error(), "mutated") {
		t.Fatalf("reappearing mutated release escaped history: %v", err)
	}
}

func TestGitHubClientRejectsAppendOnlyChangeAfterAbsentPage(t *testing.T) {
	original := "[" + releaseJSON("v1.2.3", false, false, []string{"app-1.2.3.zip"}) + "]"
	absent := "[" + releaseJSON("v2.0.0", false, false, []string{"app-2.0.0.zip"}) + "]"
	reappeared := "[" + releaseJSON("v1.2.3", false, false, []string{"app-1.2.3.zip", "app-1.2.3.zip.sha256"}) + "]"
	responses := []string{original, absent, reappeared}
	calls := 0
	client := &GitHubClient{BaseURL: "https://api.github.test", CacheDir: prepareGitHubCacheDir(t), HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		response := testHTTPResponse(http.StatusOK, responses[calls])
		calls++
		response.Header.Set("ETag", fmt.Sprintf(`"etag-%d"`, calls))
		return response, nil
	})}}
	repository := GitHubRepository{Owner: "brave", Name: "brave-browser"}
	if _, err := client.Releases(context.Background(), repository); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Releases(context.Background(), repository); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Releases(context.Background(), repository); err == nil || !strings.Contains(err.Error(), "mutated") {
		t.Fatalf("historically unverifiable asset addition was accepted: %v", err)
	}
}

func TestGitHubClientRejectsAssetIDReusedAcrossReleases(t *testing.T) {
	firstTag, secondTag := "v1.2.3", "v1.2.4"
	first := releaseJSON(firstTag, false, false, []string{"app-1.2.3.zip"})
	second := releaseJSON(secondTag, false, false, []string{"app-1.2.4.zip"})
	second = strings.Replace(second, `"id":`+strconv.Itoa(assetIDForTag(secondTag, 0)), `"id":`+strconv.Itoa(assetIDForTag(firstTag, 0)), 1)
	client := &GitHubClient{BaseURL: "https://api.github.test", HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return testHTTPResponse(http.StatusOK, "["+first+","+second+"]"), nil
	})}}
	if _, err := client.Releases(context.Background(), GitHubRepository{Owner: "brave", Name: "brave-browser"}); err == nil || !strings.Contains(err.Error(), "across releases") {
		t.Fatalf("reused global asset id accepted: %v", err)
	}
}

func TestReleaseEvidenceHistoryIsBounded(t *testing.T) {
	var releases []githubRelease
	for i := 0; i < maxReleaseHistory+20; i++ {
		releases = append(releases, githubRelease{ID: int64(i + 1), TagName: fmt.Sprintf("v1.0.%d", i)})
	}
	history := mergeReleaseEvidence(nil, releases)
	if len(history) != maxReleaseHistory {
		t.Fatalf("history length = %d, want %d", len(history), maxReleaseHistory)
	}
}

func TestReleaseEvidenceRefreshSurvivesSaturatedAbsentPage(t *testing.T) {
	target := githubRelease{ID: 1, TagName: "v1.2.3", Assets: []githubAsset{{ID: 10, Name: "app.zip", Size: 1, State: "uploaded", BrowserDownloadURL: githubAssetURL("v1.2.3", "app.zip")}}}
	history := []releaseEvidence{evidenceForRelease(target)}
	for i := 1; i < maxReleaseHistory; i++ {
		history = append(history, evidenceForRelease(githubRelease{ID: int64(i + 1), TagName: fmt.Sprintf("v2.0.%d", i)}))
	}

	// Refresh the oldest evidence because the release was just observed.
	history = mergeReleaseEvidence(history, []githubRelease{target})
	if history[len(history)-1] != evidenceForRelease(target) {
		t.Fatal("just-observed release was not refreshed to newest history position")
	}

	// The next page omits target and adds a new release while history is full.
	history = mergeReleaseEvidence(history, []githubRelease{{ID: 999, TagName: "v3.0.0"}})
	if len(history) != maxReleaseHistory {
		t.Fatalf("history length = %d, want %d", len(history), maxReleaseHistory)
	}

	recreated := target
	recreated.ID = 1001
	if err := detectHistoricalMutation(history, []githubRelease{recreated}); err == nil || !strings.Contains(err.Error(), "mutated") {
		t.Fatalf("refreshed release mutation escaped saturated history: %v", err)
	}
}

func TestGitHubClientETagRevalidationAndBounds(t *testing.T) {
	var calls atomic.Int32
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("per_page") != "20" {
			t.Errorf("per_page = %q", r.URL.Query().Get("per_page"))
		}
		if calls.Add(1) == 1 {
			response := testHTTPResponse(http.StatusOK, "["+releaseJSON("v1.2.3", false, false, []string{"app-1.2.3.zip"})+"]")
			response.Header.Set("ETag", `"release-v1"`)
			return response, nil
		}
		if r.Header.Get("If-None-Match") != `"release-v1"` {
			t.Errorf("If-None-Match = %q", r.Header.Get("If-None-Match"))
		}
		return testHTTPResponse(http.StatusNotModified, ""), nil
	})
	client := &GitHubClient{BaseURL: "https://api.github.test", CacheDir: prepareGitHubCacheDir(t), HTTP: &http.Client{Transport: transport}}
	for i := 0; i < 2; i++ {
		releases, err := client.Releases(context.Background(), GitHubRepository{Owner: "brave", Name: "brave-browser"})
		if err != nil || len(releases) != 1 || releases[0].TagName != "v1.2.3" {
			t.Fatalf("request %d: releases=%#v err=%v", i, releases, err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestGitHubClientReleaseByTagCachesAndRejectsMutation(t *testing.T) {
	tag := "v1.2.3"
	original := releaseJSON(tag, false, false, []string{"app-1.2.3.zip"})
	mutated := strings.Replace(original, `"size":100`, `"size":101`, 1)
	calls := 0
	client := &GitHubClient{BaseURL: "https://api.github.test", CacheDir: prepareGitHubCacheDir(t), HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/repos/brave/brave-browser/releases/tags/v1.2.3" {
			t.Fatalf("unexpected exact-release path: %s", request.URL.Path)
		}
		calls++
		switch calls {
		case 1:
			response := testHTTPResponse(http.StatusOK, original)
			response.Header.Set("ETag", `"original"`)
			return response, nil
		case 2:
			if request.Header.Get("If-None-Match") != `"original"` {
				t.Fatalf("If-None-Match = %q", request.Header.Get("If-None-Match"))
			}
			return testHTTPResponse(http.StatusNotModified, ""), nil
		default:
			response := testHTTPResponse(http.StatusOK, mutated)
			response.Header.Set("ETag", `"mutated"`)
			return response, nil
		}
	})}}
	repository := GitHubRepository{Owner: "brave", Name: "brave-browser"}
	for call := 0; call < 2; call++ {
		release, err := client.ReleaseByTag(context.Background(), repository, tag)
		if err != nil || release.TagName != tag || len(release.Assets) != 1 {
			t.Fatalf("exact release call %d: release=%#v err=%v", call+1, release, err)
		}
	}
	if _, err := client.ReleaseByTag(context.Background(), repository, tag); err == nil || !strings.Contains(err.Error(), "mutated") {
		t.Fatalf("exact release mutation was accepted: %v", err)
	}
	endpoint := "https://api.github.test/repos/brave/brave-browser/releases/tags/v1.2.3"
	cached, err := readGitHubCache(client.cachePath(endpoint))
	if err != nil || cached.ETag != `"original"` || string(cached.Body) != "["+original+"]" {
		t.Fatalf("mutated exact release overwrote cache: cache=%#v err=%v", cached, err)
	}
}

func TestGitHubClientReleaseByTagUsesRetainedRecentHistory(t *testing.T) {
	repository := GitHubRepository{Owner: "brave", Name: "brave-browser"}
	tag := "v1.2.3"
	original := "[" + releaseJSON(tag, false, false, []string{"app-1.2.3.zip"}) + "]"
	originalReleases, err := decodeAndValidateReleases([]byte(original), repository)
	if err != nil {
		t.Fatal(err)
	}
	absent := "[" + releaseJSON("v2.0.0", false, false, []string{"app-2.0.0.zip"}) + "]"
	client := &GitHubClient{BaseURL: "https://api.github.test", CacheDir: prepareGitHubCacheDir(t)}
	listPath := client.cachePath("https://api.github.test/repos/brave/brave-browser/releases?per_page=20")
	if err := writeGitHubCache(listPath, githubCacheRecord{Body: json.RawMessage(absent), History: []releaseEvidence{evidenceForRelease(originalReleases[0])}}); err != nil {
		t.Fatal(err)
	}
	mutated := strings.Replace(releaseJSON(tag, false, false, []string{"app-1.2.3.zip"}), `"size":100`, `"size":101`, 1)
	client.HTTP = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return testHTTPResponse(http.StatusOK, mutated), nil
	})}
	if _, err := client.ReleaseByTag(context.Background(), repository, tag); err == nil || !strings.Contains(err.Error(), "mutated") {
		t.Fatalf("exact lookup reset retained recent-page history: %v", err)
	}
}

func TestGitHubClientAcceptsAppendOnlyAssetUploads(t *testing.T) {
	tag := "v1.2.3"
	original := "[" + releaseJSON(tag, false, false, []string{"app-1.2.3.zip"}) + "]"
	expanded := "[" + releaseJSON(tag, false, false, []string{"app-1.2.3.zip", "app-1.2.3.zip.sha256", "app-1.2.3.zip.sha256.asc"}) + "]"
	expandedAgain := "[" + releaseJSON(tag, false, false, []string{"app-1.2.3.zip", "app-1.2.3.zip.sha256", "app-1.2.3.zip.sha256.asc", "app-1.2.3.zip.asc"}) + "]"
	mutated := strings.Replace(expandedAgain, `"size":100`, `"size":101`, 1)
	responses := []string{original, expanded, expandedAgain, mutated}
	calls := 0
	client := &GitHubClient{BaseURL: "https://api.github.test", CacheDir: prepareGitHubCacheDir(t), HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		response := testHTTPResponse(http.StatusOK, responses[calls])
		calls++
		response.Header.Set("ETag", fmt.Sprintf(`"etag-%d"`, calls))
		return response, nil
	})}}
	repository := GitHubRepository{Owner: "brave", Name: "brave-browser"}
	if _, err := client.Releases(context.Background(), repository); err != nil {
		t.Fatal(err)
	}
	releases, err := client.Releases(context.Background(), repository)
	if err != nil || len(releases) != 1 || releases[0].AddedAssetCount != 2 {
		t.Fatalf("first append-only update: releases=%#v err=%v", releases, err)
	}
	templates := []githubTemplate{{
		Source:        Source{Architecture: "any"},
		Kind:          "asset",
		AssetTemplate: stringTemplate{Prefix: "app-", Suffix: ".zip"},
	}}
	candidate, matched := matchGitHubRelease(Recipe{Version: "1.2.3", Release: "1"}, repository, templates, releases[0], "1.2.3")
	if !matched || !containsReason(candidate.Reasons, "2 assets were added after initial observation") {
		t.Fatalf("accepted additions missing from candidate reasons: %#v", candidate)
	}
	releases, err = client.Releases(context.Background(), repository)
	if err != nil || len(releases) != 1 || releases[0].AddedAssetCount != 1 {
		t.Fatalf("successive append-only update: releases=%#v err=%v", releases, err)
	}
	if _, err := client.Releases(context.Background(), repository); err == nil || !strings.Contains(err.Error(), "mutated") {
		t.Fatalf("later asset mutation was accepted: %v", err)
	}

	cachePath := client.cachePath("https://api.github.test/repos/brave/brave-browser/releases?per_page=20")
	cached, err := readGitHubCache(cachePath)
	if err != nil || string(cached.Body) != expandedAgain || cached.ETag != `"etag-3"` {
		t.Fatalf("latest proven snapshot was not retained: cache=%#v err=%v", cached, err)
	}
	wantReleases, err := decodeAndValidateReleases([]byte(expandedAgain), repository)
	if err != nil {
		t.Fatal(err)
	}
	if len(cached.History) != 1 || cached.History[0] != evidenceForRelease(wantReleases[0]) {
		t.Fatalf("history did not advance to the expanded snapshot: %#v", cached.History)
	}
}

func TestGitHubClientRejectsCachedBodyHistoryConflictBeforeAppend(t *testing.T) {
	repository := GitHubRepository{Owner: "brave", Name: "brave-browser"}
	original := "[" + releaseJSON("v1.2.3", false, false, []string{"app-1.2.3.zip"}) + "]"
	expanded := "[" + releaseJSON("v1.2.3", false, false, []string{"app-1.2.3.zip", "app-1.2.3.zip.sha256"}) + "]"
	releases, err := decodeAndValidateReleases([]byte(original), repository)
	if err != nil {
		t.Fatal(err)
	}
	conflicting := evidenceForRelease(releases[0])
	conflicting.Fingerprint = strings.Repeat("0", 64)
	cached := githubCacheRecord{Body: json.RawMessage(original), History: []releaseEvidence{conflicting}}
	if _, err := reconcileGitHubCache("", http.StatusOK, `"expanded"`, []byte(expanded), cached, repository, "github.com"); err == nil || !strings.Contains(err.Error(), "conflicts with retained history") {
		t.Fatalf("append-only update advanced an inconsistent cache: %v", err)
	}
}

func containsReason(reasons []string, fragment string) bool {
	for _, reason := range reasons {
		if strings.Contains(reason, fragment) {
			return true
		}
	}
	return false
}

func TestGitHubClientRateLimitAndMalformedData(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "rate limit", status: http.StatusForbidden, body: `{}`},
		{name: "malformed JSON", status: http.StatusOK, body: `{`},
		{name: "missing release id", status: http.StatusOK, body: `[{"tag_name":"v1"}]`},
		{name: "inconsistent asset URL", status: http.StatusOK, body: `[{"id":1,"tag_name":"v1","assets":[{"id":2,"name":"x","size":1,"browser_download_url":"https://github.com/other/repo/releases/download/v1/x"}]}]`},
		{name: "malformed digest", status: http.StatusOK, body: `[{"id":1,"tag_name":"v1","assets":[{"id":2,"name":"x","size":1,"state":"uploaded","digest":"sha256:nope","browser_download_url":"https://github.com/acme/app/releases/download/v1/x"}]}]`},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &GitHubClient{BaseURL: "https://api.github.test", HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return testHTTPResponse(test.status, test.body), nil
			})}}
			if _, err := client.Releases(context.Background(), GitHubRepository{Owner: "acme", Name: "app"}); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestGitHubClientBoundsCacheAndRejectsCachedReleaseMutation(t *testing.T) {
	t.Run("bounded cache read", func(t *testing.T) {
		path := t.TempDir() + "/cache.json"
		if err := os.WriteFile(path, bytes.Repeat([]byte("x"), maxGitHubCache+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readGitHubCache(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("expected bounded cache error, got %v", err)
		}
	})

	mutations := []struct {
		name   string
		mutate func(string) string
		want   string
	}{
		{name: "size", mutate: func(body string) string { return strings.Replace(body, `"size":100`, `"size":101`, 1) }, want: "mutat"},
		{name: "digest", mutate: func(body string) string {
			return strings.Replace(body, strings.Repeat("a", 64), strings.Repeat("b", 64), 1)
		}, want: "mutat"},
		{name: "state", mutate: func(body string) string {
			return strings.Replace(body, `"state":"uploaded"`, `"state":"starter"`, 1)
		}, want: "mutat"},
		{name: "removed asset", mutate: func(string) string {
			return "[" + releaseJSON("v1.2.3", false, false, nil) + "]"
		}, want: "removed"},
		{name: "asset identity", mutate: func(body string) string {
			return strings.Replace(body, `"id":`+strconv.Itoa(assetIDForTag("v1.2.3", 0)), `"id":99`, 1)
		}, want: "mutat"},
		{name: "download URL", mutate: func(body string) string {
			return strings.Replace(body, "https://github.com/", "https://GITHUB.COM/", 1)
		}, want: "inconsistent"},
		{name: "release identity", mutate: func(body string) string {
			marker := `"id":` + strconv.Itoa(releaseIDForTag("v1.2.3"))
			return strings.Replace(body, marker, `"id":999`, 1)
		}, want: "mutat"},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			original := "[" + releaseJSON("v1.2.3", false, false, []string{"app-1.2.3.zip"}) + "]"
			calls := 0
			client := &GitHubClient{BaseURL: "https://api.github.test", CacheDir: prepareGitHubCacheDir(t), HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				body := original
				if calls == 2 {
					body = test.mutate(body)
				}
				response := testHTTPResponse(http.StatusOK, body)
				response.Header.Set("ETag", fmt.Sprintf(`"etag-%d"`, calls))
				return response, nil
			})}}
			repository := GitHubRepository{Owner: "brave", Name: "brave-browser"}
			if _, err := client.Releases(context.Background(), repository); err != nil {
				t.Fatal(err)
			}
			if _, err := client.Releases(context.Background(), repository); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected mutation error, got %v", err)
			}
			cached, err := readGitHubCache(client.cachePath("https://api.github.test/repos/brave/brave-browser/releases?per_page=20"))
			if err != nil || string(cached.Body) != original {
				t.Fatalf("mutated response overwrote cache: err=%v body=%s", err, cached.Body)
			}
		})
	}
}

func TestGitHubClientSerializesConflictingCacheUpdates(t *testing.T) {
	cacheDir := prepareGitHubCacheDir(t)
	repository := GitHubRepository{Owner: "brave", Name: "brave-browser"}
	original := "[" + releaseJSON("v1.2.3", false, false, []string{"app-1.2.3.zip"}) + "]"
	mutated := strings.Replace(original, `"id":`+strconv.Itoa(releaseIDForTag("v1.2.3")), `"id":999`, 1)
	arrived := make(chan struct{}, 2)
	releaseResponses := make(chan struct{})

	type outcome struct {
		etag     string
		releases []githubRelease
		err      error
	}
	results := make(chan outcome, 2)
	start := func(body, etag string) {
		client := &GitHubClient{BaseURL: "https://api.github.test", CacheDir: cacheDir, HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			arrived <- struct{}{}
			<-releaseResponses
			response := testHTTPResponse(http.StatusOK, body)
			response.Header.Set("ETag", etag)
			return response, nil
		})}}
		go func() {
			releases, err := client.Releases(context.Background(), repository)
			results <- outcome{etag: etag, releases: releases, err: err}
		}()
	}
	start(original, `"original"`)
	start(mutated, `"mutated"`)
	<-arrived
	<-arrived
	close(releaseResponses)

	var successful outcome
	successes, mutations := 0, 0
	for range 2 {
		result := <-results
		switch {
		case result.err == nil:
			successes++
			successful = result
		case strings.Contains(result.err.Error(), "mutated"):
			mutations++
		default:
			t.Fatalf("unexpected conflicting update result: %v", result.err)
		}
	}
	if successes != 1 || mutations != 1 {
		t.Fatalf("successes=%d mutations=%d, want one of each", successes, mutations)
	}

	key := "https://api.github.test/repos/brave/brave-browser/releases?per_page=20"
	cached, err := readGitHubCache((&GitHubClient{CacheDir: cacheDir}).cachePath(key))
	if err != nil {
		t.Fatal(err)
	}
	if len(successful.releases) != 1 || cached.ETag != successful.etag {
		t.Fatalf("successful update not retained: success=%#v cache=%#v", successful, cached)
	}
	cachedReleases, err := decodeAndValidateReleases(cached.Body, repository)
	if err != nil || len(cachedReleases) != 1 || cachedReleases[0].ID != successful.releases[0].ID {
		t.Fatalf("cached identity does not match successful update: releases=%#v err=%v", cachedReleases, err)
	}
	wantEvidence := evidenceForRelease(successful.releases[0])
	if len(cached.History) != 1 || cached.History[0] != wantEvidence {
		t.Fatalf("successful identity missing from history: got=%#v want=%#v", cached.History, wantEvidence)
	}
}

func TestGitHubClientSerializesIncomparableAppendOnlyUpdates(t *testing.T) {
	cacheDir := prepareGitHubCacheDir(t)
	repository := GitHubRepository{Owner: "brave", Name: "brave-browser"}
	original := "[" + releaseJSON("v1.2.3", false, false, []string{"app-1.2.3.zip"}) + "]"
	seed := &GitHubClient{BaseURL: "https://api.github.test", CacheDir: cacheDir, HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		response := testHTTPResponse(http.StatusOK, original)
		response.Header.Set("ETag", `"original"`)
		return response, nil
	})}}
	if _, err := seed.Releases(context.Background(), repository); err != nil {
		t.Fatal(err)
	}

	expandedA := "[" + releaseJSON("v1.2.3", false, false, []string{"app-1.2.3.zip", "app-1.2.3.zip.sha256"}) + "]"
	expandedB := "[" + releaseJSON("v1.2.3", false, false, []string{"app-1.2.3.zip", "app-1.2.3.zip.asc"}) + "]"
	arrived := make(chan struct{}, 2)
	releaseResponses := make(chan struct{})
	type outcome struct {
		body string
		err  error
	}
	results := make(chan outcome, 2)
	start := func(body, etag string) {
		client := &GitHubClient{BaseURL: "https://api.github.test", CacheDir: cacheDir, HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			arrived <- struct{}{}
			<-releaseResponses
			response := testHTTPResponse(http.StatusOK, body)
			response.Header.Set("ETag", etag)
			return response, nil
		})}}
		go func() {
			_, err := client.Releases(context.Background(), repository)
			results <- outcome{body: body, err: err}
		}()
	}
	start(expandedA, `"expanded-a"`)
	start(expandedB, `"expanded-b"`)
	<-arrived
	<-arrived
	close(releaseResponses)

	var accepted string
	successes, mutations := 0, 0
	for range 2 {
		result := <-results
		switch {
		case result.err == nil:
			successes++
			accepted = result.body
		case strings.Contains(result.err.Error(), "mutated"):
			mutations++
		default:
			t.Fatalf("unexpected append-only reconciliation result: %v", result.err)
		}
	}
	if successes != 1 || mutations != 1 {
		t.Fatalf("successes=%d mutations=%d, want one of each", successes, mutations)
	}
	key := "https://api.github.test/repos/brave/brave-browser/releases?per_page=20"
	cached, err := readGitHubCache((&GitHubClient{CacheDir: cacheDir}).cachePath(key))
	if err != nil || string(cached.Body) != accepted {
		t.Fatalf("cache did not retain the monotonic winning snapshot: cache=%#v err=%v", cached, err)
	}
}

func TestGitHubCacheLockRejectsSymlink(t *testing.T) {
	dir := prepareGitHubCacheDir(t)
	cachePath := filepath.Join(dir, "endpoint.json")
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, cachePath+".lock"); err != nil {
		t.Fatal(err)
	}
	if lock, err := acquireGitHubCacheLock(cachePath); err == nil {
		releaseEvidenceLock(lock)
		t.Fatal("accepted symlink cache lock")
	}
}

func TestGitHubClientResponseLimitAndTokenScope(t *testing.T) {
	t.Run("response limit", func(t *testing.T) {
		client := &GitHubClient{BaseURL: "https://api.github.test", HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return testHTTPResponse(http.StatusOK, strings.Repeat("x", maxGitHubBody+1)), nil
		})}}
		if _, err := client.Releases(context.Background(), GitHubRepository{Owner: "brave", Name: "brave-browser"}); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("expected response limit error, got %v", err)
		}
	})

	for _, test := range []struct {
		name       string
		baseURL    string
		wantHeader string
	}{
		{name: "official API receives token", baseURL: defaultGitHubAPI, wantHeader: "Bearer secret"},
		{name: "custom API does not receive token", baseURL: "https://api.github.test"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &GitHubClient{BaseURL: test.baseURL, Token: "secret", HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if got := request.Header.Get("Authorization"); got != test.wantHeader {
					t.Fatalf("Authorization = %q, want %q", got, test.wantHeader)
				}
				return testHTTPResponse(http.StatusOK, "["+releaseJSON("v1.2.3", false, false, []string{"app-1.2.3.zip"})+"]"), nil
			})}}
			if _, err := client.Releases(context.Background(), GitHubRepository{Owner: "brave", Name: "brave-browser"}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGitHubProviderSelectsStableCompleteReleaseAndSidecars(t *testing.T) {
	releases := "[" + strings.Join([]string{
		releaseJSON("v1.2.3", false, false, []string{"brave-1.2.3-x86_64.zip", "brave-1.2.3-aarch64.zip"}),
		releaseJSON("v1.4.0-beta.1", false, true, []string{"brave-1.4.0-beta.1-x86_64.zip", "brave-1.4.0-beta.1-aarch64.zip"}),
		releaseJSON("v1.3.0", false, false, []string{"brave-1.3.0-x86_64.zip"}),
		releaseJSON("v1.2.5", false, false, []string{
			"brave-1.2.5-x86_64.zip", "brave-1.2.5-aarch64.zip",
			"brave-1.2.5-x86_64.zip.sha256", "brave-1.2.5-x86_64.zip.asc", "brave-1.2.5-x86_64.zip.sha256.asc",
		}),
	}, ",") + "]"
	provider, closeServer := testProvider(t, releases)
	defer closeServer()
	recipe := Recipe{PackageBase: "brave-bin", Version: "1.2.3", Release: "2", Epoch: "3", Architectures: []string{"x86_64", "aarch64"}, Sources: []Source{
		{Architecture: "x86_64", URL: githubAssetURL("v1.2.3", "brave-1.2.3-x86_64.zip")},
		{Architecture: "aarch64", URL: githubAssetURL("v1.2.3", "brave-1.2.3-aarch64.zip")},
	}}
	candidate, found, err := provider.Detect(context.Background(), recipe, "3:1.2.3-2", numericCompare)
	if err != nil || !found {
		t.Fatalf("detect: candidate=%#v found=%v err=%v", candidate, found, err)
	}
	if candidate.Tag != "v1.2.5" || candidate.FullVersion != "3:1.2.5-1" || !candidate.NewerThanAUR {
		t.Fatalf("wrong candidate: %#v", candidate)
	}
	if len(candidate.Assets) != 2 || !candidate.Assets[0].Sidecars.SHA256 || !candidate.Assets[0].Sidecars.Signature || !candidate.Assets[0].Sidecars.SHA256Signed {
		t.Fatalf("sidecars not detected exactly: %#v", candidate.Assets)
	}
}

func TestGitHubProviderKeepsAURPkgrelNewerAtSamePkgver(t *testing.T) {
	provider, closeServer := testProvider(t, "["+releaseJSON("v1.2.3", false, false, []string{"origin-1.2.3.zip", "brave-1.2.3.zip"})+"]")
	defer closeServer()
	recipe := Recipe{PackageBase: "brave-origin-bin", Version: "1.2.3", Release: "7", Epoch: "2", Sources: []Source{{Architecture: "any", URL: githubAssetURL("v1.2.3", "origin-1.2.3.zip")}}}
	candidate, found, err := provider.Detect(context.Background(), recipe, "2:1.2.3-7", numericCompare)
	if err != nil || !found {
		t.Fatalf("detect: found=%v err=%v", found, err)
	}
	if candidate.NewerThanAUR || candidate.FullVersion != "2:1.2.3-1" || candidate.Assets[0].Name != "origin-1.2.3.zip" {
		t.Fatalf("pkgrel or product match wrong: %#v", candidate)
	}
}

func TestGitHubProviderRejectsArchitectureGapAndAmbiguity(t *testing.T) {
	provider := GitHubProvider{Client: &GitHubClient{}}
	recipe := Recipe{Version: "1.0", Architectures: []string{"x86_64", "aarch64"}, Sources: []Source{{Architecture: "x86_64", URL: githubAssetURL("v1.0", "app-1.0-x86_64.zip")}}}
	if _, _, err := provider.Detect(context.Background(), recipe, "1.0-1", numericCompare); err == nil || !strings.Contains(err.Error(), "aarch64") {
		t.Fatalf("expected architecture gap, got %v", err)
	}
	recipe = Recipe{Version: "1.0", Sources: []Source{
		{Architecture: "any", URL: githubAssetURL("v1.0", "app-1.0.zip")},
		{Architecture: "any", URL: "https://github.com/other/repo/releases/download/v1.0/app-1.0.zip"},
	}}
	if _, _, err := provider.Detect(context.Background(), recipe, "1.0-1", numericCompare); err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("expected repository ambiguity, got %v", err)
	}
}

func TestGitHubProviderIgnoresVersionedNonGitHubSources(t *testing.T) {
	provider := GitHubProvider{}
	recipe := Recipe{
		Version:       "2.24.33",
		Architectures: []string{"any"},
		Sources: []Source{{
			Architecture: "any",
			URL:          "git+https://gitlab.gnome.org/GNOME/gtk.git#tag=2.24.33",
		}},
	}

	candidate, found, err := provider.Detect(context.Background(), recipe, "2.24.33-5", numericCompare)
	if err != nil || found {
		t.Fatalf("non-GitHub recipe was not ignored: candidate=%#v found=%v err=%v", candidate, found, err)
	}
}

func TestGitHubProviderRequiresEstablishedTagTemplate(t *testing.T) {
	provider, closeServer := testProvider(t, "["+releaseJSON("v1.2.3", false, false, []string{"app-1.2.3.zip"})+","+releaseJSON("1.2.4", false, false, []string{"app-1.2.4.zip"})+"]")
	defer closeServer()
	recipe := Recipe{Version: "1.2.3", Architectures: []string{"any"}, Sources: []Source{{Architecture: "any", URL: githubAssetURL("v1.2.3", "app-1.2.3.zip")}}}
	candidate, found, err := provider.Detect(context.Background(), recipe, "1.2.3-1", numericCompare)
	if err != nil || !found || candidate.Tag != "v1.2.3" {
		t.Fatalf("tag channel drift accepted: candidate=%#v found=%v err=%v", candidate, found, err)
	}
}

func TestGitHubProviderRequiresCurrentReleaseBaseline(t *testing.T) {
	provider := GitHubProvider{Client: &GitHubClient{BaseURL: "https://api.github.test", HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if strings.Contains(request.URL.Path, "/releases/tags/") {
			return testHTTPResponse(http.StatusNotFound, ""), nil
		}
		return testHTTPResponse(http.StatusOK, "["+releaseJSON("v1.2.4", false, false, []string{"app-1.2.4.zip"})+"]"), nil
	})}}}
	recipe := Recipe{Version: "1.2.3", Architectures: []string{"any"}, Sources: []Source{{Architecture: "any", URL: githubAssetURL("v1.2.3", "app-1.2.3.zip")}}}
	if _, _, err := provider.Detect(context.Background(), recipe, "1.2.3-1", numericCompare); err == nil || !strings.Contains(err.Error(), "release-by-tag API HTTP 404") {
		t.Fatalf("missing baseline accepted: %v", err)
	}
}

func TestGitHubProviderFetchesOlderCurrentReleaseByExactTag(t *testing.T) {
	listCalls, exactCalls := 0, 0
	recent := "[" + strings.Join([]string{
		releaseJSON("v1.2.5", false, false, []string{"app-1.2.5.zip"}),
		releaseJSON("v1.2.4", false, false, []string{"app-1.2.4.zip"}),
	}, ",") + "]"
	client := &GitHubClient{BaseURL: "https://api.github.test", HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if strings.Contains(request.URL.Path, "/releases/tags/") {
			exactCalls++
			return testHTTPResponse(http.StatusOK, releaseJSON("v1.2.3", false, false, []string{"app-1.2.3.zip"})), nil
		}
		listCalls++
		return testHTTPResponse(http.StatusOK, recent), nil
	})}}
	provider := GitHubProvider{Client: client}
	recipe := Recipe{Version: "1.2.3", Release: "1", Architectures: []string{"any"}, Sources: []Source{{Architecture: "any", URL: githubAssetURL("v1.2.3", "app-1.2.3.zip")}}}
	candidate, found, err := provider.Detect(context.Background(), recipe, "1.2.3-1", numericCompare)
	if err != nil || !found || candidate.Tag != "v1.2.5" {
		t.Fatalf("exact baseline fallback: candidate=%#v found=%v err=%v", candidate, found, err)
	}
	if listCalls != 1 || exactCalls != 1 {
		t.Fatalf("list calls=%d exact calls=%d, want one each", listCalls, exactCalls)
	}
}

func TestGitHubProviderSkipsExactLookupWhenBaselineIsRecent(t *testing.T) {
	calls := 0
	body := "[" + releaseJSON("v1.2.3", false, false, []string{"app-1.2.3.zip"}) + "]"
	client := &GitHubClient{BaseURL: "https://api.github.test", HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if strings.Contains(request.URL.Path, "/releases/tags/") {
			t.Fatal("unexpected exact baseline request")
		}
		return testHTTPResponse(http.StatusOK, body), nil
	})}}
	provider := GitHubProvider{Client: client}
	recipe := Recipe{Version: "1.2.3", Release: "1", Architectures: []string{"any"}, Sources: []Source{{Architecture: "any", URL: githubAssetURL("v1.2.3", "app-1.2.3.zip")}}}
	if _, found, err := provider.Detect(context.Background(), recipe, "1.2.3-1", numericCompare); err != nil || !found {
		t.Fatalf("recent baseline detection: found=%v err=%v", found, err)
	}
	if calls != 1 {
		t.Fatalf("requests=%d, want one recent-page request", calls)
	}
}

func TestGitHubProviderRejectsUnsafeTemplatesAndSecondHost(t *testing.T) {
	tests := []struct {
		name    string
		version string
		source  string
		extra   string
		want    string
	}{
		{name: "repeated version", source: githubAssetURL("v1.2.3", "app-1.2.3-copy-1.2.3.zip"), want: "exactly once"},
		{name: "coincidental version", source: githubAssetURL("v1.2.3", "appx1.2.3y.zip"), want: "distinct token"},
		{name: "embedded shorter version", version: "1.2", source: githubAssetURL("v1.2", "app-1.2.3.zip"), want: "embedded in another version"},
		{name: "second host", source: githubAssetURL("v1.2.3", "app-1.2.3.zip"), extra: "https://downloads.example.test/app-1.2.3.zip", want: "outside the selected GitHub release"},
		{name: "GitLab Git tag", source: githubAssetURL("v1.2.3", "app-1.2.3.zip"), extra: "git+https://gitlab.gnome.org/example/app.git#tag=1.2.3", want: "outside the selected GitHub release"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sources := []Source{{Architecture: "any", URL: test.source}}
			if test.extra != "" {
				sources = append(sources, Source{Architecture: "any", URL: test.extra})
			}
			version := test.version
			if version == "" {
				version = "1.2.3"
			}
			recipe := Recipe{Version: version, Architectures: []string{"any"}, Sources: sources}
			provider := GitHubProvider{Client: &GitHubClient{}}
			if _, _, err := provider.Detect(context.Background(), recipe, "1.2.3-1", numericCompare); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unsafe template accepted: %v", err)
			}
		})
	}
}

func TestGitHubProviderUsesFixedTagPrefixAndRejectsUnflaggedPrerelease(t *testing.T) {
	releases := "[" + strings.Join([]string{
		releaseJSON("release-v1.2.3-stable", false, false, []string{"app-1.2.3.zip"}),
		releaseJSON("release-v1.2.4-stable", false, false, []string{"app-1.2.4.zip"}),
		releaseJSON("release-v1.3.0rc1-stable", false, false, []string{"app-1.3.0rc1.zip"}),
	}, ",") + "]"
	provider, closeServer := testProvider(t, releases)
	defer closeServer()
	recipe := Recipe{Version: "1.2.3", Architectures: []string{"any"}, Sources: []Source{{Architecture: "any", URL: githubAssetURL("release-v1.2.3-stable", "app-1.2.3.zip")}}}
	candidate, found, err := provider.Detect(context.Background(), recipe, "1.2.3-1", numericCompare)
	if err != nil || !found || candidate.Version != "1.2.4" || candidate.Tag != "release-v1.2.4-stable" {
		t.Fatalf("fixed tag template selection failed: candidate=%#v found=%v err=%v", candidate, found, err)
	}
}

func TestGitHubProviderRequiresUploadedAssetsAndSidecars(t *testing.T) {
	baseline := releaseJSON("v1.2.3", false, false, []string{"app-1.2.3.zip"})
	starterBaseline := strings.Replace(baseline, `"state":"uploaded"`, `"state":"starter"`, 1)
	recipe := Recipe{Version: "1.2.3", Architectures: []string{"any"}, Sources: []Source{{Architecture: "any", URL: githubAssetURL("v1.2.3", "app-1.2.3.zip")}}}
	provider, closeServer := testProvider(t, "["+starterBaseline+"]")
	if _, _, err := provider.Detect(context.Background(), recipe, "1.2.3-1", numericCompare); err == nil || !strings.Contains(err.Error(), "not uploaded") {
		t.Fatalf("starter baseline accepted: %v", err)
	}
	closeServer()

	newRelease := releaseJSON("v1.2.4", false, false, []string{"app-1.2.4.zip", "app-1.2.4.zip.sha256"})
	newRelease = strings.Replace(newRelease, `"name":"app-1.2.4.zip.sha256","size":100,"state":"uploaded"`, `"name":"app-1.2.4.zip.sha256","size":100,"state":"starter"`, 1)
	provider, closeServer = testProvider(t, "["+baseline+","+newRelease+"]")
	defer closeServer()
	candidate, found, err := provider.Detect(context.Background(), recipe, "1.2.3-1", numericCompare)
	if err != nil || !found || candidate.Assets[0].Sidecars.SHA256 {
		t.Fatalf("starter sidecar reported: candidate=%#v found=%v err=%v", candidate, found, err)
	}
}

func prepareGitHubCacheDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	useOwnerOf(t, dir)
	return dir
}

func testProvider(t *testing.T, body string) (GitHubProvider, func()) {
	t.Helper()
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return testHTTPResponse(http.StatusOK, body), nil
	})}
	return GitHubProvider{Client: &GitHubClient{BaseURL: "https://api.github.test", HTTP: client}}, func() {}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func testHTTPResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString(body))}
}

func releaseJSON(tag string, draft, prerelease bool, names []string) string {
	assets := make([]string, 0, len(names))
	releaseID := releaseIDForTag(tag)
	for i, name := range names {
		assets = append(assets, fmt.Sprintf(`{"id":%d,"name":%q,"size":100,"state":"uploaded","browser_download_url":%q,"digest":"sha256:%s"}`, assetIDForTag(tag, i), name, githubAssetURL(tag, name), strings.Repeat("a", 64)))
	}
	return fmt.Sprintf(`{"id":%d,"tag_name":%q,"draft":%t,"prerelease":%t,"assets":[%s]}`, releaseID, tag, draft, prerelease, strings.Join(assets, ","))
}

func assetIDForTag(tag string, index int) int {
	return releaseIDForTag(tag)*100 + index + 10
}

func releaseIDForTag(tag string) int {
	id := 1
	for _, r := range tag {
		id = (id*31 + int(r)) % 1_000_000_007
	}
	return id
}

func githubAssetURL(tag, name string) string {
	return "https://github.com/brave/brave-browser/releases/download/" + tag + "/" + name
}

var numberPattern = regexp.MustCompile(`[0-9]+`)

func numericCompare(a, b string) (int, error) {
	aa, bb := numberPattern.FindAllString(a, -1), numberPattern.FindAllString(b, -1)
	for i := 0; i < len(aa) || i < len(bb); i++ {
		av, bv := 0, 0
		if i < len(aa) {
			av, _ = strconv.Atoi(aa[i])
		}
		if i < len(bb) {
			bv, _ = strconv.Atoi(bb[i])
		}
		if av < bv {
			return -1, nil
		}
		if av > bv {
			return 1, nil
		}
	}
	return 0, nil
}
