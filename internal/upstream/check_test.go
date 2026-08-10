package upstream

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

type providerFunc func(context.Context, Recipe, string, VersionComparator) (Candidate, bool, error)

func (f providerFunc) Detect(ctx context.Context, recipe Recipe, aurVersion string, compare VersionComparator) (Candidate, bool, error) {
	return f(ctx, recipe, aurVersion, compare)
}

func TestCheckerKeepsPackageFailuresNonfatal(t *testing.T) {
	checker := Checker{
		Compare: numericCompare,
		RecipeFetcher: func(_ context.Context, packageBase string) (Recipe, error) {
			if packageBase == "broken" {
				return Recipe{}, errors.New("rate limited")
			}
			return Recipe{PackageBase: packageBase, Version: "1.0", Release: "1"}, nil
		},
		Provider: providerFunc(func(_ context.Context, recipe Recipe, _ string, _ VersionComparator) (Candidate, bool, error) {
			return Candidate{Provider: "github", Repository: "acme/" + recipe.PackageBase, FullVersion: "2.0-1", NewerThanAUR: true}, true, nil
		}),
	}
	reports := checker.Check(context.Background(), []Request{
		{Name: "good", PackageBase: "good", LocalVersion: "1.0-1", AURVersion: "1.0-1"},
		{Name: "broken", PackageBase: "broken", LocalVersion: "1.0-1", AURVersion: "1.0-1"},
	})
	if len(reports) != 2 || reports[0].Candidate == nil || !reports[0].Candidate.NewerThanLocal {
		t.Fatalf("good report missing: %#v", reports)
	}
	if !strings.Contains(reports[1].UnknownReason, "rate limited") {
		t.Fatalf("failure did not remain isolated: %#v", reports)
	}
}

func TestCheckerComparesLocalVersionToCandidate(t *testing.T) {
	checker := Checker{
		Compare: numericCompare,
		RecipeFetcher: func(_ context.Context, packageBase string) (Recipe, error) {
			return Recipe{PackageBase: packageBase, Version: "1.0", Release: "1"}, nil
		},
		Provider: providerFunc(func(context.Context, Recipe, string, VersionComparator) (Candidate, bool, error) {
			return Candidate{Provider: "github", Repository: "acme/app", FullVersion: "2.0-1"}, true, nil
		}),
	}
	requests := []Request{
		{Name: "behind", PackageBase: "behind", LocalVersion: "1.0-1", AURVersion: "1.0-1"},
		{Name: "equal", PackageBase: "equal", LocalVersion: "2.0-1", AURVersion: "1.0-1"},
		{Name: "ahead", PackageBase: "ahead", LocalVersion: "3.0-1", AURVersion: "1.0-1"},
	}
	reports := checker.Check(context.Background(), requests)
	if len(reports) != 3 || !reports[0].Candidate.NewerThanLocal || reports[0].LocalCompare != -1 {
		t.Fatalf("behind comparison: %#v", reports)
	}
	if reports[1].Candidate.NewerThanLocal || reports[1].LocalCompare != 0 {
		t.Fatalf("equal comparison: %#v", reports[1])
	}
	if reports[2].Candidate.NewerThanLocal || reports[2].LocalCompare != 1 {
		t.Fatalf("ahead comparison: %#v", reports[2])
	}
}

func TestCheckerRejectsRecipeSnapshotVersionRace(t *testing.T) {
	providerCalled := false
	checker := Checker{
		Compare: numericCompare,
		RecipeFetcher: func(context.Context, string) (Recipe, error) {
			return Recipe{PackageBase: "app", Version: "2.0", Release: "1"}, nil
		},
		Provider: providerFunc(func(context.Context, Recipe, string, VersionComparator) (Candidate, bool, error) {
			providerCalled = true
			return Candidate{}, false, nil
		}),
	}
	reports := checker.Check(context.Background(), []Request{{Name: "app", PackageBase: "app", LocalVersion: "1.0-1", AURVersion: "1.0-1"}})
	if providerCalled || len(reports) != 1 || !strings.Contains(reports[0].UnknownReason, "does not match RPC") {
		t.Fatalf("snapshot race was not rejected before provider call: %#v called=%v", reports, providerCalled)
	}
}

func TestCheckerRejectsRecipeSnapshotPackageBaseMismatch(t *testing.T) {
	providerCalled := false
	checker := Checker{
		Compare: numericCompare,
		RecipeFetcher: func(context.Context, string) (Recipe, error) {
			return Recipe{PackageBase: "other", Version: "1.0", Release: "1"}, nil
		},
		Provider: providerFunc(func(context.Context, Recipe, string, VersionComparator) (Candidate, bool, error) {
			providerCalled = true
			return Candidate{}, false, nil
		}),
	}
	reports := checker.Check(context.Background(), []Request{{Name: "app", PackageBase: "app", LocalVersion: "1.0-1", AURVersion: "1.0-1"}})
	if providerCalled || len(reports) != 1 || !strings.Contains(reports[0].UnknownReason, "does not match requested") {
		t.Fatalf("package base mismatch reached provider: %#v called=%v", reports, providerCalled)
	}
}

func TestFetchRecipeUsesStrictBoundedCgitRequest(t *testing.T) {
	requests := 0
	checker := Checker{
		AURBaseURL: "https://aur.test",
		HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			requests++
			if request.URL.Path != "/cgit/aur.git/plain/.SRCINFO" || request.URL.Query().Get("h") != "brave-bin" {
				t.Fatalf("unexpected cgit request: %s", request.URL.String())
			}
			return testHTTPResponse(http.StatusOK, "pkgbase = brave-bin\npkgver = 1.2.3\npkgrel = 1\narch = x86_64\nsource_x86_64 = "+githubAssetURL("v1.2.3", "brave-1.2.3.zip")+"\n"), nil
		})},
	}
	recipe, err := checker.fetchRecipe(context.Background(), "brave-bin")
	if err != nil || recipe.FullVersion() != "1.2.3-1" || requests != 1 {
		t.Fatalf("recipe=%#v requests=%d err=%v", recipe, requests, err)
	}
	if _, err := checker.fetchRecipe(context.Background(), "../../other"); err == nil || requests != 1 {
		t.Fatalf("unsafe package base was requested: requests=%d err=%v", requests, err)
	}
}

func TestFetchRecipeRejectsOversizedResponse(t *testing.T) {
	checker := Checker{
		AURBaseURL: "https://aur.test",
		HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return testHTTPResponse(http.StatusOK, strings.Repeat("x", maxRecipeBody+1)), nil
		})},
	}
	if _, err := checker.fetchRecipe(context.Background(), "app"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected bounded response error, got %v", err)
	}
}

func TestFetchRecipeRejectsConfusingBaseURLs(t *testing.T) {
	values := []string{
		"http://aur.archlinux.org",
		"https://user@aur.archlinux.org",
		"https://aur.archlinux.org/cgit",
		"https://aur.archlinux.org?x=1",
		"https://aur.archlinux.org#x",
		"https://aur.archlinux.org.evil.test",
		"https://AUR.ARCHLINUX.ORG",
		"https://aur.archlinux.org:443",
	}
	for _, value := range values {
		checker := Checker{AURBaseURL: value}
		if _, err := checker.fetchRecipe(context.Background(), "app"); err == nil {
			t.Errorf("accepted confusing AUR base URL %q", value)
		}
	}
}

func TestFetchRecipeRefusesRedirects(t *testing.T) {
	checker := Checker{
		AURBaseURL: "https://aur.test",
		HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			response := testHTTPResponse(http.StatusFound, "")
			response.Header.Set("Location", "https://evil.test/PKGBUILD")
			return response, nil
		})},
	}
	if _, err := checker.fetchRecipe(context.Background(), "app"); err == nil || !strings.Contains(err.Error(), "redirect refused") {
		t.Fatalf("expected redirect refusal, got %v", err)
	}
}

func TestFetchRecipeRejectsResponseOriginConfusion(t *testing.T) {
	checker := Checker{
		AURBaseURL: "https://aur.test",
		HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			response := testHTTPResponse(http.StatusOK, "pkgbase = app\npkgver = 1.0\npkgrel = 1\n")
			response.Request, _ = http.NewRequest(http.MethodGet, "https://evil.test/cgit/aur.git/plain/.SRCINFO?h=app", nil)
			return response, nil
		})},
	}
	if _, err := checker.fetchRecipe(context.Background(), "app"); err == nil || !strings.Contains(err.Error(), "origin or path changed") {
		t.Fatalf("expected response origin rejection, got %v", err)
	}
}

func TestFetchRecipeRejectsPackageBaseMismatch(t *testing.T) {
	checker := Checker{
		AURBaseURL: "https://aur.test",
		HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return testHTTPResponse(http.StatusOK, "pkgbase = other\npkgver = 1.0\npkgrel = 1\n"), nil
		})},
	}
	if _, err := checker.fetchRecipe(context.Background(), "app"); err == nil || !strings.Contains(err.Error(), "does not match requested") {
		t.Fatalf("expected package base mismatch, got %v", err)
	}
}

func TestFetchRecipeDoesNotFallBackToPKGBUILD(t *testing.T) {
	for _, unsupported := range []string{"tab-delimited conditional", "subshell group", "heredoc content"} {
		t.Run(unsupported, func(t *testing.T) {
			requests := 0
			checker := Checker{
				AURBaseURL: "https://aur.test",
				HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
					requests++
					if request.URL.Path != "/cgit/aur.git/plain/.SRCINFO" {
						t.Fatalf("unexpected PKGBUILD fallback for %s: %s", unsupported, request.URL.Path)
					}
					return testHTTPResponse(http.StatusOK, "malformed metadata"), nil
				})},
			}
			if _, err := checker.fetchRecipe(context.Background(), "app"); err == nil || requests != 1 {
				t.Fatalf("fallback behavior for %s: requests=%d err=%v", unsupported, requests, err)
			}
		})
	}
}
