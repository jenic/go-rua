package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-rua/internal/aur"
	"go-rua/internal/pacman"
	"go-rua/internal/paths"
	"go-rua/internal/review"
	"go-rua/internal/reviewstate"
)

func sourceRedirect(name, from, to string) review.Finding {
	return review.Finding{Rule: "source-redirect", Action: review.Review, Location: name, Evidence: "download redirected from " + from + " to " + to}
}

func TestRememberedSourceReport(t *testing.T) {
	accepted := sourceRedirect("app-1.zip", "github.com", "release-assets.githubusercontent.com")
	next := sourceRedirect("app-2.zip", "github.com", "release-assets.githubusercontent.com")
	for _, tc := range []struct {
		name     string
		baseline *reviewstate.Record
		finding  review.Finding
		want     review.Action
	}{
		{"renamed archive", &reviewstate.Record{Base: "app", Accepted: []review.Finding{accepted}}, next, review.Info},
		{"case insensitive hosts", &reviewstate.Record{Base: "app", Accepted: []review.Finding{accepted}}, sourceRedirect("app-2.zip", "GitHub.COM", "RELEASE-ASSETS.githubusercontent.com"), review.Info},
		{"new origin", &reviewstate.Record{Base: "app", Accepted: []review.Finding{accepted}}, sourceRedirect("app-2.zip", "other.test", "release-assets.githubusercontent.com"), review.Review},
		{"new destination", &reviewstate.Record{Base: "app", Accepted: []review.Finding{accepted}}, sourceRedirect("app-2.zip", "github.com", "other.test"), review.Review},
		{"new port", &reviewstate.Record{Base: "app", Accepted: []review.Finding{accepted}}, sourceRedirect("app-2.zip", "github.com", "release-assets.githubusercontent.com:8443"), review.Review},
		{"another package", &reviewstate.Record{Base: "other", Accepted: []review.Finding{accepted}}, next, review.Review},
		{"missing baseline", nil, next, review.Review},
		{"not accepted", &reviewstate.Record{Base: "app"}, next, review.Review},
		{"runtime fetch", &reviewstate.Record{Base: "app", Accepted: []review.Finding{{Rule: "runtime-fetch", Action: review.Review, Location: "sources", Evidence: "unresolved"}}}, review.Finding{Rule: "runtime-fetch", Action: review.Review, Location: "sources", Evidence: "unresolved"}, review.Review},
		{"dynamic fetch", &reviewstate.Record{Base: "app", Accepted: []review.Finding{{Rule: "dynamic-fetch", Action: review.Review, Location: "sources", Evidence: "unresolved"}}}, review.Finding{Rule: "dynamic-fetch", Action: review.Review, Location: "sources", Evidence: "unresolved"}, review.Review},
		{"blocked", &reviewstate.Record{Base: "app", Accepted: []review.Finding{accepted}}, review.Finding{Rule: next.Rule, Action: review.Block, Location: next.Location, Evidence: next.Evidence}, review.Block},
		{"malformed redirect", &reviewstate.Record{Base: "app", Accepted: []review.Finding{{Rule: "source-redirect", Action: review.Review, Evidence: "unresolved"}}}, review.Finding{Rule: "source-redirect", Action: review.Review, Evidence: "unresolved"}, review.Review},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fetched := review.Report{Findings: []review.Finding{tc.finding}}
			displayed := rememberedSourceReport("app", fetched, tc.baseline)
			if got := displayed.Findings[0]; got.Action != tc.want || got.Location != tc.finding.Location {
				t.Fatalf("finding = %+v, want action %s", got, tc.want)
			}
			if fetched.Findings[0] != tc.finding {
				t.Fatal("display changes mutated the findings saved as accepted")
			}
			if tc.want == review.Info && !strings.Contains(displayed.Findings[0].Evidence, "(previously accepted)") {
				t.Fatal("remembered approval was not identified")
			}
		})
	}
	// Every hop must have been accepted; one remembered hop cannot approve a chain.
	displayed := rememberedSourceReport("app", review.Report{Findings: []review.Finding{next, sourceRedirect("app-2.zip", "release-assets.githubusercontent.com", "new.test")}}, &reviewstate.Record{Base: "app", Accepted: []review.Finding{accepted}})
	if displayed.Findings[0].Action != review.Info || !displayed.Has(review.Review) {
		t.Fatal("new redirect hop did not require review")
	}
}

func TestGuidedRedirectApprovalSurvivesUpgrades(t *testing.T) {
	t.Setenv("RUA_COLOR", "never")
	p, opt, output, events := guidedFixture(t, "a\naccept sources\n")
	redirect := sourceRedirect("app-2.zip", "github.com", "release-assets.githubusercontent.com")
	fetchReviewedSourcesFn = func(string) (review.Report, error) {
		*events = append(*events, "fetch")
		return review.Report{Findings: []review.Finding{redirect}}, nil
	}
	if err := GuidedUpgrade([]string{"app"}, p, opt); err != nil {
		t.Fatal(err, output.String())
	}
	if !strings.Contains(output.String(), "Type 'accept sources'") {
		t.Fatal("first redirect did not require approval")
	}
	assertSaved := func() {
		t.Helper()
		store, err := reviewstate.Open(p.ReviewStateDir())
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		r, err := store.Load("app", false)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range r.Accepted {
			if f == redirect {
				return
			}
		}
		t.Fatalf("accepted redirect was not preserved: %+v", r.Accepted)
	}
	assertSaved()
	version, installed := "3", "2-1"
	t.Cleanup(aur.SetHTTPClientForTests(&http.Client{Transport: rtIFunc(func(r *http.Request) (*http.Response, error) {
		b, _ := json.Marshal(map[string]any{"version": 5, "type": "multiinfo", "results": []aur.Package{{Name: "app", PackageBase: "app", Version: version + "-1"}}})
		return resp(200, string(b)), nil
	})}))
	prepare := prepareCandidateFn
	prepareCandidateFn = func(dir, base string) (candidate, error) {
		c, err := prepare(dir, base)
		for i := range c.recipe {
			c.recipe[i].Data = bytes.ReplaceAll(c.recipe[i].Data, []byte("2"), []byte(version))
		}
		return c, err
	}
	installedSnapshotFn = func() (pacman.Snapshot, error) {
		return pacman.Snapshot{Versions: map[string]string{"app": installed}}, nil
	}
	buildVerifiedFn = func(dir string, _ paths.Paths, _, _, _ bool) error {
		*events = append(*events, "build")
		return writeGuidedArtifact(dir, "app", version+"-1")
	}
	pacmanInstallLocalWithMode = func([]string, bool) error {
		*events = append(*events, "install")
		installed = version + "-1"
		return nil
	}
	for _, v := range []string{"3", "4"} {
		version = v
		redirect.Location = "app-" + v + ".zip"
		opt.Input = strings.NewReader("a\n")
		output.Reset()
		*events = nil
		if err := GuidedUpgrade([]string{"app"}, p, opt); err != nil {
			t.Fatal(err, output.String())
		}
		if strings.Contains(output.String(), "Type 'accept sources'") || !strings.Contains(output.String(), "INFO  "+redirect.Location+": "+redirect.Evidence+" (previously accepted)") {
			t.Fatalf("remembered redirect prompted or was hidden:\n%s", output.String())
		}
		if got := strings.Join(*events, ","); got != "candidate,merge,fetch,verify,build,install" {
			t.Fatalf("remembered approval bypassed a build stage: %s", got)
		}
		assertSaved()
	}
	version = "5"
	redirect = sourceRedirect("app-5.zip", "github.com", "different.test")
	opt.Input = strings.NewReader("a\nskip\n")
	output.Reset()
	*events = nil
	if err := GuidedUpgrade([]string{"app"}, p, opt); err != nil {
		t.Fatal(err, output.String())
	}
	if !strings.Contains(output.String(), "Type 'accept sources'") || strings.Contains(strings.Join(*events, ","), "verify") {
		t.Fatalf("new destination did not require approval:\n%s", output.String())
	}
	redirect = sourceRedirect("app-5.zip", "github.com", "release-assets.githubusercontent.com")
	for _, invalid := range []string{"installed version drift", "pending transaction"} {
		t.Run(invalid, func(t *testing.T) {
			installed = "3-1"
			if invalid == "pending transaction" {
				installed = "4-1"
				store, err := reviewstate.Open(p.ReviewStateDir())
				if err != nil {
					t.Fatal(err)
				}
				r, err := store.Load("app", false)
				if err == nil {
					err = store.Save(*r, true)
				}
				store.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			opt.Input = strings.NewReader("a\nskip\n")
			output.Reset()
			*events = nil
			if err := GuidedUpgrade([]string{"app"}, p, opt); err != nil {
				t.Fatal(err, output.String())
			}
			if !strings.Contains(output.String(), "Type 'accept sources'") || strings.Contains(output.String(), "(previously accepted)") || strings.Contains(strings.Join(*events, ","), "verify") {
				t.Fatalf("invalid baseline reused approval:\n%s", output.String())
			}
		})
	}
}

func TestGuidedRedirectApprovalNotSavedAfterFailure(t *testing.T) {
	for _, failure := range []string{"skip", "verify", "install"} {
		t.Run(failure, func(t *testing.T) {
			input := "a\naccept sources\n"
			if failure == "skip" {
				input = "a\nskip\n"
			}
			p, opt, output, _ := guidedFixture(t, input)
			fetchReviewedSourcesFn = func(string) (review.Report, error) {
				return review.Report{Findings: []review.Finding{sourceRedirect("app.zip", "github.com", "release-assets.githubusercontent.com")}}, nil
			}
			if failure == "verify" {
				verifySourcesFn = func(string, bool) (review.Report, error) { return review.Report{}, errors.New("checksum mismatch") }
			} else if failure == "install" {
				pacmanInstallLocalWithMode = func([]string, bool) error { return errors.New("installation declined") }
			}
			err := GuidedUpgrade([]string{"app"}, p, opt)
			if (err != nil) != (failure != "skip") {
				t.Fatalf("err=%v output=%s", err, output.String())
			}
			if _, err := os.Stat(filepath.Join(p.ReviewStateDir(), "app.json")); !os.IsNotExist(err) {
				t.Fatalf("failed upgrade saved reusable approval: %v", err)
			}
		})
	}
}
