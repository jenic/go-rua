package upstream

import "testing"

func TestParseSRCINFOSortsStaticSourcesAndArchitectures(t *testing.T) {
	data := []byte(`pkgbase = brave-bin
	pkgver = 1.2.3
	pkgrel = 4
	epoch = 2
	arch = x86_64
	arch = aarch64
	source_x86_64 = brave-browser-1.2.3-x86_64.pkg.tar.zst::https://github.com/brave/brave-browser/releases/download/v1.2.3/brave-browser-1.2.3-x86_64.pkg.tar.zst
	source_aarch64 = https://github.com/brave/brave-browser/releases/download/v1.2.3/brave-browser-1.2.3-aarch64.pkg.tar.zst
	source = brave-launcher.sh
`)
	recipe, err := ParseSRCINFO(data)
	if err != nil {
		t.Fatal(err)
	}
	if recipe.PackageBase != "brave-bin" || recipe.FullVersion() != "2:1.2.3-4" {
		t.Fatalf("unexpected recipe: %#v", recipe)
	}
	if got := recipe.Architectures; len(got) != 2 || got[0] != "aarch64" || got[1] != "x86_64" {
		t.Fatalf("architectures not sorted: %#v", got)
	}
	if got := recipe.Sources; len(got) != 3 || got[0].Architecture != "aarch64" || got[1].Architecture != "any" || got[2].Architecture != "x86_64" {
		t.Fatalf("sources not sorted: %#v", got)
	}
}

func TestParseSRCINFOPreservesGitSourceIdentityAndTrustMetadata(t *testing.T) {
	recipe, err := ParseSRCINFO([]byte(`pkgbase = app
pkgver = 1.2.3
pkgrel = 2
arch = x86_64
source = checkout::git+https://github.com/acme/app.git?signed#tag=v1.2.3
sha256sums = SKIP
validpgpkeys = 0123456789abcdef0123456789abcdef01234567
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(recipe.Sources) != 1 {
		t.Fatalf("sources = %#v", recipe.Sources)
	}
	source := recipe.Sources[0]
	if source.Key != "source" || source.Index != 0 || source.Name != "checkout" || source.Alias != "checkout" {
		t.Fatalf("source identity = %#v", source)
	}
	if got := recipe.Checksums["sha256sums"]; len(got) != 1 || got[0] != "SKIP" {
		t.Fatalf("checksums = %#v", recipe.Checksums)
	}
	if len(recipe.ValidPGPKeys) != 1 || recipe.ValidPGPKeys[0] != "0123456789ABCDEF0123456789ABCDEF01234567" {
		t.Fatalf("validpgpkeys = %#v", recipe.ValidPGPKeys)
	}
}

func TestParseSRCINFORejectsMalformedOrDuplicateIdentity(t *testing.T) {
	tests := []string{
		"pkgbase = x\npkgver=1\npkgrel = 1\n",
		"pkgbase = x\npkgbase = y\npkgver = 1\npkgrel = 1\n",
		"pkgbase = x\npkgver = 1\n",
	}
	for _, input := range tests {
		if _, err := ParseSRCINFO([]byte(input)); err == nil {
			t.Fatalf("expected rejection for %q", input)
		}
	}
}
