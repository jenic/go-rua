package install

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go-rua/internal/aur"
	"go-rua/internal/pacman"
	"go-rua/internal/paths"
	"go-rua/internal/review"
	"go-rua/internal/reviewstate"
	"go-rua/internal/tarcheck"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func guidedFixture(t *testing.T, input string) (paths.Paths, Options, *bytes.Buffer, *[]string) {
	t.Helper()
	restoreInstallSeams(t)
	oldState, oldVerify, oldBuild := installedSnapshotFn, verifySourcesFn, buildVerifiedFn
	oldCompare, oldDeps := guidedCompareFn, guidedDepsFn
	oldPrepare, oldMerge, oldLint := prepareCandidateFn, mergeCandidateFn, guidedLintFn
	oldFetch := fetchReviewedSourcesFn
	t.Cleanup(func() {
		installedSnapshotFn = oldState
		verifySourcesFn = oldVerify
		buildVerifiedFn = oldBuild
		guidedCompareFn = oldCompare
		guidedDepsFn = oldDeps
		prepareCandidateFn = oldPrepare
		mergeCandidateFn = oldMerge
		guidedLintFn = oldLint
		fetchReviewedSourcesFn = oldFetch
	})
	t.Cleanup(aur.SetHTTPClientForTests(&http.Client{Transport: rtIFunc(func(r *http.Request) (*http.Response, error) {
		b, _ := json.Marshal(map[string]any{"version": 5, "type": "multiinfo", "results": []aur.Package{{Name: "app", PackageBase: "app", Version: "2-1"}}})
		return resp(200, string(b)), nil
	})}))
	root := t.TempDir()
	p := paths.Paths{ConfigDir: filepath.Join(root, "config"), CacheBuildDir: filepath.Join(root, "build"), DataCheckedTars: filepath.Join(root, "data", "checked_tars")}
	for _, d := range []string{p.ConfigDir, p.CacheBuildDir, p.DataCheckedTars} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	events := []string{}
	installed := "1-1"
	installedSnapshotFn = func() (pacman.Snapshot, error) {
		return pacman.Snapshot{Versions: map[string]string{"app": installed}, Files: map[string]map[string]bool{}, Owners: map[string][]string{}}, nil
	}
	guidedCompareFn = func(a, b string) (int, error) { return strings.Compare(a, b), nil }
	guidedDepsFn = func([]string) ([]string, error) { return nil, nil }
	prepareCandidateFn = func(dir, base string) (candidate, error) {
		events = append(events, "candidate")
		return candidate{commit: strings.Repeat("a", 40), recipe: reviewstate.Snapshot{
			{Path: ".SRCINFO", Mode: 0644, Data: []byte("pkgbase = app\n pkgver = 2\n pkgrel = 1\n arch = any\npkgname = app\n")},
			{Path: "PKGBUILD", Mode: 0644, Data: []byte("pkgname=app\npkgver=2\npkgrel=1\narch=('any')\n")},
		}}, nil
	}
	mergeCandidateFn = func(string, candidate) error { events = append(events, "merge"); return nil }
	guidedLintFn = func(string, bool) review.Report { return review.Report{} }
	fetchReviewedSourcesFn = func(string) (review.Report, error) { events = append(events, "fetch"); return review.Report{}, nil }
	verifySourcesFn = func(string, bool) (review.Report, error) {
		events = append(events, "verify")
		return review.Report{}, nil
	}
	buildVerifiedFn = func(dir string, _ paths.Paths, _, _, _ bool) error {
		events = append(events, "build")
		return writeGuidedArtifact(dir, "app", "2-1")
	}
	pacmanInstallLocalWithMode = func(files []string, asdeps bool) error {
		events = append(events, "install")
		if len(files) != 1 || asdeps {
			t.Errorf("wrong transaction: %v %v", files, asdeps)
		}
		installed = "2-1"
		return nil
	}
	opt := Options{Guided: true, InstallBuilt: true, Offline: true, Input: strings.NewReader(input), Output: &output, Plan: &Plan{Targets: []string{"app"}, BuildOrder: []string{"app"}}}
	return p, opt, &output, &events
}
func writeGuidedArtifact(dir, name, version string) error {
	f, err := os.Create(filepath.Join(dir, name+".pkg.tar"))
	if err != nil {
		return err
	}
	defer f.Close()
	w := tar.NewWriter(f)
	for _, item := range []struct{ name, data string }{{".PKGINFO", fmt.Sprintf("pkgname = %s\npkgbase = %s\npkgver = %s\narch = any\n", name, name, version)}, {"usr/share/go-rua-test-absent/data", "data"}} {
		if err := w.WriteHeader(&tar.Header{Name: item.name, Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(item.data))}); err != nil {
			return err
		}
		if _, err := w.Write([]byte(item.data)); err != nil {
			return err
		}
	}
	return w.Close()
}
func TestGuidedUpgradeRecordsOnlySuccessfulInstall(t *testing.T) {
	p, opt, out, events := guidedFixture(t, "a\n")
	if err := Install([]string{"app"}, p, opt); err != nil {
		t.Fatal(err, out.String())
	}
	if got := strings.Join(*events, ","); got != "candidate,merge,fetch,verify,build,install" {
		t.Fatal(got)
	}
	store, err := reviewstate.Open(p.ReviewStateDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	r, err := store.Load("app", false)
	if err != nil {
		t.Fatal(err)
	}
	if r.Artifacts[0].Version != "2-1" {
		t.Fatal(r)
	}
	if _, err := store.Load("app", true); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "full") && !strings.Contains(out.String(), "review every file") {
		t.Fatal("first-run review missing")
	}
}
func TestGuidedUpgradeFailuresStopLaterStages(t *testing.T) {
	for _, kind := range []string{"eof", "skip", "checkout", "verify", "missing artifact", "wrong version", "install"} {
		t.Run(kind, func(t *testing.T) {
			input := "a\n"
			if kind == "eof" {
				input = ""
			}
			if kind == "skip" {
				input = "s\n"
			}
			p, opt, out, events := guidedFixture(t, input)
			switch kind {
			case "checkout":
				prepareCandidateFn = func(string, string) (candidate, error) { return candidate{}, errors.New("dirty checkout") }
			case "verify":
				verifySourcesFn = func(string, bool) (review.Report, error) { return review.Report{}, errors.New("checksum mismatch") }
			case "missing artifact":
				buildVerifiedFn = func(string, paths.Paths, bool, bool, bool) error { return nil }
			case "wrong version":
				buildVerifiedFn = func(d string, _ paths.Paths, _, _, _ bool) error { return writeGuidedArtifact(d, "app", "9-1") }
			case "install":
				pacmanInstallLocalWithMode = func([]string, bool) error { return errors.New("declined transaction") }
			}
			err := Install([]string{"app"}, p, opt)
			if (err != nil) != (kind != "skip") {
				t.Fatalf("error=%v output=%s", err, out.String())
			}
			if _, err := os.Stat(filepath.Join(p.ReviewStateDir(), "app.json")); !os.IsNotExist(err) {
				t.Fatal("failed flow advanced baseline")
			}
			if kind != "install" && strings.Contains(strings.Join(*events, ","), "install") {
				t.Fatal("installed after failure")
			}
			if kind == "install" {
				if _, err := os.Stat(filepath.Join(p.ReviewStateDir(), "app.pending.json")); err != nil {
					t.Fatal("pending evidence lost", err)
				}
			}
		})
	}
}
func TestGuidedArtifactMutationBlocksInstallation(t *testing.T) {
	p, opt, out, _ := guidedFixture(t, "a\n")
	installed := false
	pacmanInstallLocalWithMode = func([]string, bool) error { installed = true; return nil }
	guidedLintFn = func(target string, artifact bool) review.Report {
		if artifact {
			os.WriteFile(target, []byte("changed after inspection"), 0600)
		}
		return review.Report{}
	}
	if err := Install([]string{"app"}, p, opt); err == nil || installed || !strings.Contains(out.String(), "artifact changed") {
		t.Fatal(err, installed, out.String())
	}
}

func TestGuidedUpgradeRejectsLinkedInstallBeforeTransaction(t *testing.T) {
	for _, typeflag := range []byte{tar.TypeLink, tar.TypeSymlink} {
		t.Run(string(typeflag), func(t *testing.T) {
			p, opt, out, events := guidedFixture(t, "a\na\n")
			input := strings.NewReader("a\na\n")
			opt.Input = input
			// Use the real archive reader; only builds and pacman are simulated.
			oldInspect := inspectArtifactFn
			inspectArtifactFn = tarcheck.Inspect
			t.Cleanup(func() { inspectArtifactFn = oldInspect })
			buildVerifiedFn = func(dir string, _ paths.Paths, _, _, _ bool) error {
				*events = append(*events, "build")
				f, err := os.Create(filepath.Join(dir, "app.pkg.tar"))
				if err != nil {
					return err
				}
				defer f.Close()
				w := tar.NewWriter(f)
				defer w.Close()
				for _, item := range []struct{ name, body string }{
					{".PKGINFO", "pkgname = app\npkgbase = app\npkgver = 2-1\narch = any\n"},
					{"usr/share/go-rua-test-absent/script", "post_install() { :; }\n"},
				} {
					if err := w.WriteHeader(&tar.Header{Name: item.name, Mode: 0644, Typeflag: tar.TypeReg, Size: int64(len(item.body))}); err != nil {
						return err
					}
					if _, err := w.Write([]byte(item.body)); err != nil {
						return err
					}
				}
				if err := w.WriteHeader(&tar.Header{Name: "./.INSTALL", Mode: 0644, Typeflag: typeflag, Linkname: "usr/share/go-rua-test-absent/script"}); err != nil {
					return err
				}
				return w.Close()
			}
			err := Install([]string{"app"}, p, opt)
			if err == nil || !strings.Contains(out.String(), "package metadata \".INSTALL\" must be a regular file") {
				t.Fatalf("wrong rejection: %v output=%s", err, out.String())
			}
			if got := strings.Join(*events, ","); got != "candidate,merge,fetch,verify,build" {
				t.Fatalf("malformed metadata reached pacman or failed before inspection: %s", got)
			}
			if input.Len() != len("a\n") {
				t.Fatal("malformed metadata reached artifact approval")
			}
			for _, name := range []string{"app.json", "app.pending.json"} {
				if _, err := os.Stat(filepath.Join(p.ReviewStateDir(), name)); !os.IsNotExist(err) {
					t.Fatalf("rejected archive saved installation evidence %s: %v", name, err)
				}
			}
		})
	}
}

func TestGuidedArtifactFindingsRequireExplicitAcceptance(t *testing.T) {
	for _, tt := range []struct {
		name, answer       string
		installed, wantErr bool
	}{
		{"uppercase", "A\n", true, false},
		{"lowercase", "a\n", true, false},
		{"list then accept", "F\nA\n", true, false},
		{"skip", "S\n", false, false},
		{"quit", "Q\n", false, true},
		{"empty then EOF", "\n", false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, opt, out, events := guidedFixture(t, "a\n"+tt.answer)
			guidedLintFn = func(_ string, artifact bool) review.Report {
				var r review.Report
				if artifact {
					r.Add("tool-diagnostics", review.Review, "namcap", "fixture finding requiring approval")
				}
				return r
			}
			err := Install([]string{"app"}, p, opt)
			installed := false
			for _, event := range *events {
				if event == "install" {
					installed = true
				}
			}
			if (err != nil) != tt.wantErr || installed != tt.installed {
				t.Fatalf("err=%v installed=%v output=%s", err, installed, out.String())
			}
		})
	}
}
func TestBaseOrderDeduplicatesSharedAndSplitPackages(t *testing.T) {
	infos := []aur.Package{{Name: "root", PackageBase: "root", Depends: []string{"a", "b"}}, {Name: "a", PackageBase: "split", Depends: []string{"dep"}}, {Name: "b", PackageBase: "split", Depends: []string{"other"}}, {Name: "dep", PackageBase: "dep"}, {Name: "other", PackageBase: "other", Depends: []string{"dep"}}}
	plan := Plan{BuildOrder: []string{"dep", "a", "other", "b", "root"}}
	order, groups, err := baseOrder(plan, infos)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "dep,other,split,root" || len(groups["split"]) != 2 {
		t.Fatal(order, groups)
	}
}

func TestGuidedUpstreamOverrideReviewsInstalledAURRecipe(t *testing.T) {
	p, opt, out, _ := guidedFixture(t, "a\n")
	version := "2-1"
	installedSnapshotFn = func() (pacman.Snapshot, error) {
		return pacman.Snapshot{Versions: map[string]string{"app": version}, Files: map[string]map[string]bool{}, Owners: map[string][]string{}}, nil
	}
	opt.UpstreamBases = map[string]bool{"app": true}
	opt.PrepareBuildCopy = func(base, reviewDir, buildDir string) error {
		for _, name := range []string{"PKGBUILD", ".SRCINFO"} {
			p := filepath.Join(buildDir, name)
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if err := os.WriteFile(p, []byte(strings.ReplaceAll(string(b), "2", "3")), 0644); err != nil {
				return err
			}
		}
		return nil
	}
	buildVerifiedFn = func(dir string, _ paths.Paths, _, _, _ bool) error { return writeGuidedArtifact(dir, "app", "3-1") }
	pacmanInstallLocalWithMode = func([]string, bool) error { version = "3-1"; return nil }
	if err := Install([]string{"app"}, p, opt); err != nil {
		t.Fatal(err, out.String())
	}
	store, err := reviewstate.Open(p.ReviewStateDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	r, err := store.Load("app", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(r.Recipe.Get("PKGBUILD")), "pkgver=2") || !strings.Contains(string(r.EffectiveRecipe.Get("PKGBUILD")), "pkgver=3") {
		t.Fatal("effective recipe evidence lost")
	}
}
func TestGuidedRecipeChangedDuringVerificationStopsBuild(t *testing.T) {
	p, opt, out, events := guidedFixture(t, "a\n")
	verifySourcesFn = func(dir string, _ bool) (review.Report, error) {
		os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("changed"), 0644)
		return review.Report{}, nil
	}
	if err := Install([]string{"app"}, p, opt); err == nil || strings.Contains(strings.Join(*events, ","), "build") || !strings.Contains(out.String(), "recipe changed") {
		t.Fatal(err, *events, out.String())
	}
}
func TestGuidedReuseDependencyAndBlockMissingDependency(t *testing.T) {
	p, opt, out, events := guidedFixture(t, "a\n")
	// A dependency already at the candidate version does not require another build.
	installedSnapshotFn = func() (pacman.Snapshot, error) {
		return pacman.Snapshot{Versions: map[string]string{"app": "2-1"}}, nil
	}
	if err := Install([]string{"root"}, p, opt); err != nil || len(*events) != 0 {
		t.Fatal(err, *events, out.String())
	}
	// An unavailable dependency stops before candidate execution.
	installedSnapshotFn = func() (pacman.Snapshot, error) {
		return pacman.Snapshot{Versions: map[string]string{"app": "1-1"}}, nil
	}
	guidedDepsFn = func([]string) ([]string, error) { return []string{"skipped-dependency>=2"}, nil }
	if err := Install([]string{"app"}, p, opt); err == nil || len(*events) != 0 {
		t.Fatal(err, *events)
	}
}
