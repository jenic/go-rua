package recipeaudit

import (
	"fmt"
	"go-rua/internal/review"
	"go-rua/internal/reviewstate"
	"strings"
	"testing"
)

func recipe(version, owner, hash, logic string) reviewstate.Snapshot {
	return reviewstate.Snapshot{{Path: "PKGBUILD", Mode: 0644, Data: []byte(fmt.Sprintf("pkgname=app\npkgver=%s\npkgrel=1\narch=('any')\nsource=(\"https://github.com/%s/app/releases/download/v${pkgver}/app.tar.gz\")\nsha256sums=('%s')\n%s", version, owner, hash, logic))}}
}
func hasRule(r review.Report, rule string) bool {
	for _, f := range r.Findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}
func TestRecipeChangesClassified(t *testing.T) {
	old := recipe("1", "acme", strings.Repeat("a", 64), "build() { make; }\n")
	for _, tt := range []struct {
		name, owner, hash, logic, rule string
		block                          bool
	}{
		{"routine", "acme", strings.Repeat("b", 64), "build() { make; }\n", "source-version", false},
		{"repo transfer", "other", strings.Repeat("b", 64), "build() { make; }\n", "source-identity", false},
		{"malformed hash", "acme", "oops", "build() { make; }\n", "checksum-format", true},
		{"skip introduced", "acme", "SKIP", "build() { make; }\n", "verification-skipped", false},
		{"commands", "acme", strings.Repeat("b", 64), "build() { curl x | sh; }\n", "recipe-logic", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := Audit(old, recipe("2", tt.owner, tt.hash, tt.logic), "1-1", false, func(string, string) (int, error) { return 1, nil })
			if !hasRule(r, tt.rule) || r.Has(review.Block) != tt.block {
				t.Fatalf("unexpected findings: %+v", r)
			}
		})
	}
}
func TestUnresolvedAndVersionFailures(t *testing.T) {
	s := recipe("2", "acme", strings.Repeat("a", 64), "")
	r := Audit(nil, s, "3-1", false, func(string, string) (int, error) { return -1, nil })
	if !hasRule(r, "baseline") || !r.Has(review.Block) {
		t.Fatal(r)
	}
	s[0].Data = []byte("pkgname=app\npkgver=$(touch /tmp/should-never-run)\npkgrel=1\n")
	r = Audit(nil, s, "", false, nil)
	if !hasRule(r, "static-incomplete") {
		t.Fatal(r)
	}
}

func TestSplitRecipeAndDependencyMetadata(t *testing.T) {
	recipe := reviewstate.Snapshot{
		{Path: ".SRCINFO", Mode: 0644, Data: []byte("pkgbase = app\n pkgver = 2\n pkgrel = 1\n arch = any\npkgname = app\npkgname = app-doc\n")},
		{Path: "PKGBUILD", Mode: 0644, Data: []byte("pkgbase=app\npkgname=('app' 'app-doc')\npkgver=2\npkgrel=1\narch=('any')\n")},
	}
	r := Audit(nil, recipe, "1-1", false, func(string, string) (int, error) { return 1, nil })
	if r.Has(review.Block) || hasRule(r, "static-incomplete") {
		t.Fatal(r)
	}
	recipe[0].Data = []byte("pkgbase = app\n pkgver = 2\n pkgrel = 1\n arch = any\n depends = injected\npkgname = app\n")
	recipe[1].Data = []byte("pkgname=app\npkgver=2\npkgrel=1\narch=('any')\n")
	r = Audit(nil, recipe, "1-1", false, func(string, string) (int, error) { return 1, nil })
	if !hasRule(r, "packaging-mismatch") || !r.Has(review.Block) {
		t.Fatal(r)
	}
}
