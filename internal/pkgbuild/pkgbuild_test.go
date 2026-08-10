package pkgbuild

import (
	"bytes"
	"strings"
	"testing"
)

const fixture = `pkgname=app-bin
pkgver=1.2.3
pkgrel=4
epoch=2
arch=('x86_64')
source_x86_64=("app-${pkgver}.zip::https://github.com/acme/app/releases/download/v${pkgver}/app-${pkgver}.zip" 'launcher.sh')
sha256sums_x86_64=('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')
validpgpkeys=('0123456789ABCDEF0123456789ABCDEF01234567')
package() { install -Dm755 launcher.sh "$pkgdir/usr/bin/app"; }
`

func TestParseAndRewriteLiteralPKGBUILD(t *testing.T) {
	meta, err := Parse([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if meta.PackageBase != "app-bin" || meta.Version != "1.2.3" || meta.Epoch != "2" || len(meta.Sources["source_x86_64"]) != 2 {
		t.Fatalf("metadata: %#v", meta)
	}
	override := Override{Version: "1.2.4", Release: "1", Sources: map[string][]string{"source_x86_64": {"app-1.2.4.zip::https://github.com/acme/app/releases/download/v1.2.4/app-1.2.4.zip", "launcher.sh"}}, Checksums: map[string][]string{"sha256sums_x86_64": {"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}
	out, err := Rewrite([]byte(fixture), override)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, want := range []string{"pkgver='1.2.4'", "pkgrel='1'", "epoch=2", "package()"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q:\n%s", want, text)
		}
	}
}

func TestParseRejectsDynamicAndAmbiguousAssignments(t *testing.T) {
	tests := []string{
		"pkgname=x\npkgver=1.2\npkgrel=1\nsource=($(curl x))\nsha256sums=('SKIP')\n",
		"pkgname=x\npkgver=1.2\npkgver=1.3\npkgrel=1\n",
		"pkgname=x\npkgver=1.2\npkgrel=1\nsource=('x')\nsource+=('y')\nsha256sums=('SKIP')\n",
		"pkgname=x\npkgver=1.2\npkgrel=1\nif true; then source=('x'); fi\nsha256sums=('SKIP')\n",
		"pkgname=x\npkgver=1.2\npkgrel=1\nsource=('https://example.invalid/$pkgver/x')\nsha256sums=('SKIP')\n",
		"pkgname=x\npkgver=1.2\npkgrel=1\nsource=(https://example.invalid/\\$pkgver/x)\nsha256sums=('SKIP')\n",
		"pkgname=x\npkgver=1.2\npkgrel=1\npackage() { source=('x'); }\nsha256sums=('SKIP')\n",
		"pkgname=x\npkgver=1.2\npkgrel=1\nsource=(\"`printf x`\")\nsha256sums=('SKIP')\n",
		"pkgname=x\npkgver=1.2\npkgrel=1\nsource=(\"$pkgnameSuffix\")\nsha256sums=('SKIP')\n",
	}
	for _, input := range tests {
		if _, err := Parse([]byte(input)); err == nil {
			t.Fatalf("accepted unsupported recipe:\n%s", input)
		}
	}
}

func TestRewriteRejectsAmbiguousIndexMapping(t *testing.T) {
	override := Override{Version: "1.3", Release: "1", Sources: map[string][]string{"source_x86_64": {"only-one"}}}
	if _, err := Rewrite([]byte(fixture), override); err == nil || !strings.Contains(err.Error(), "index mapping") {
		t.Fatalf("expected index error, got %v", err)
	}
}

func TestRewriteSRCINFO(t *testing.T) {
	src := []byte("pkgbase = app-bin\npkgver = 1.2.3\npkgrel = 4\nsource_x86_64 = old.zip\nsha256sums_x86_64 = old\n")
	override := Override{Version: "1.2.4", Release: "1", Sources: map[string][]string{"source_x86_64": {"new.zip"}}, Checksums: map[string][]string{"sha256sums_x86_64": {"newhash"}}}
	out, err := RewriteSRCINFO(src, override)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "pkgver = 1.2.4\npkgrel = 1") || !strings.Contains(string(out), "source_x86_64 = new.zip") {
		t.Fatalf("unexpected SRCINFO:\n%s", out)
	}
}

func TestValidateSRCINFORejectsStaleMetadata(t *testing.T) {
	meta, err := Parse([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	src := []byte("pkgbase = app-bin\npkgver = 1.2.2\npkgrel = 4\nepoch = 2\nsource_x86_64 = app-1.2.3.zip::https://github.com/acme/app/releases/download/v1.2.3/app-1.2.3.zip\nsource_x86_64 = launcher.sh\nsha256sums_x86_64 = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nsha256sums_x86_64 = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\nvalidpgpkeys = 0123456789ABCDEF0123456789ABCDEF01234567\n")
	if err := ValidateSRCINFO(src, meta); err == nil || !strings.Contains(err.Error(), "pkgver") {
		t.Fatalf("expected stale pkgver error, got %v", err)
	}
	extra := append(src, []byte("source_aarch64 = unexpected\nsha256sums_aarch64 = SKIP\n")...)
	if err := ValidateSRCINFO(extra, meta); err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("expected extra metadata error, got %v", err)
	}
}

func TestParsePreservesDoubleQuoteBackslashSemantics(t *testing.T) {
	input := "pkgname=x\npkgver=1.2\npkgrel=1\nsource=(\"path\\\\q/${pkgver}\")\nsha256sums=('SKIP')\n"
	meta, err := Parse([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if got := meta.Sources["source"][0]; got != `path\q/1.2` {
		t.Fatalf("double-quote backslash changed: %q", got)
	}
}

func TestParseSupportsOnlyDocumentedPrimitiveExpansions(t *testing.T) {
	input := "pkgname=brave-origin-bin\npkgver=1.2\npkgrel=7\narch=('x86_64')\nsource=(\"${pkgname%-bin}-${pkgver}-${pkgrel}.zip\")\nsha256sums=('SKIP')\n"
	meta, err := Parse([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if got := meta.Sources["source"][0]; got != "brave-origin-1.2-7.zip" {
		t.Fatalf("primitive expansion = %q", got)
	}
	next, err := meta.SourcesAt("1.3", "1")
	if err != nil || next["source"][0] != "brave-origin-1.3-1.zip" {
		t.Fatalf("next sources = %#v, %v", next, err)
	}

	for _, expansion := range []string{"${pkgname%bin}", "${pkgname#brave-}", "${pkgver:-1}", "${unknown}"} {
		unsupported := strings.Replace(input, "${pkgname%-bin}-${pkgver}-${pkgrel}", expansion, 1)
		if _, err := Parse([]byte(unsupported)); err == nil {
			t.Fatalf("accepted unsupported expansion %s", expansion)
		}
	}
}

func TestParseRejectsUnsafeRawArrayWords(t *testing.T) {
	for _, word := range []string{
		"file # treated-as-a-comment",
		"*.zip",
		"file?.zip",
		"file[0].zip",
		"{one,two}.zip",
		"~/file.zip",
		"$((1+1))",
	} {
		input := "pkgname=x\npkgver=1.2\npkgrel=1\nsource=(" + word + ")\nsha256sums=('SKIP')\n"
		if _, err := Parse([]byte(input)); err == nil {
			t.Fatalf("accepted unsafe raw word %q", word)
		}
	}
}

func TestRewriteRegeneratedArrayPreservesLiteralSemantics(t *testing.T) {
	input := "pkgname=x\npkgver=1.2\npkgrel=1\nsource=(\"two words\" '' escaped\\ word \"path\\\\q\")\nsha256sums=('SKIP' 'SKIP' 'SKIP' 'SKIP')\n"
	want := []string{"two words", "", "escaped word", `path\q`}
	out, err := Rewrite([]byte(input), Override{Version: "1.3", Sources: map[string][]string{"source": want}})
	if err != nil {
		t.Fatal(err)
	}
	meta, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if !equal(meta.Sources["source"], want) {
		t.Fatalf("regenerated values = %#v, want %#v\n%s", meta.Sources["source"], want, out)
	}
}

func TestParsePreservesShellLineContinuationSemantics(t *testing.T) {
	input := "pkgname=x\npkgver=1.2\npkgrel=1\nsource=(\\\n 'one' \\\n \"two\")\nsha256sums=('SKIP' 'SKIP')\n"
	meta, err := Parse([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"one", "two"}
	if !equal(meta.Sources["source"], want) {
		t.Fatalf("line continuation values = %#v, want %#v", meta.Sources["source"], want)
	}
}

func TestValidateSRCINFORequiresExactArchKeysAndFingerprints(t *testing.T) {
	meta, err := Parse([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	valid := []byte("pkgbase = app-bin\npkgver = 1.2.3\npkgrel = 4\nepoch = 2\narch = x86_64\nsource_x86_64 = app-1.2.3.zip::https://github.com/acme/app/releases/download/v1.2.3/app-1.2.3.zip\nsource_x86_64 = launcher.sh\nsha256sums_x86_64 = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nsha256sums_x86_64 = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\nvalidpgpkeys = 0123456789ABCDEF0123456789ABCDEF01234567\n")
	if err := ValidateSRCINFO(valid, meta); err != nil {
		t.Fatal(err)
	}
	for name, mutated := range map[string][]byte{
		"missing arch":       bytes.Replace(valid, []byte("arch = x86_64\n"), nil, 1),
		"extra source key":   append(append([]byte(nil), valid...), []byte("source = stale\n")...),
		"extra checksum key": append(append([]byte(nil), valid...), []byte("b2sums_x86_64 = SKIP\n")...),
		"wrong fingerprint":  bytes.Replace(valid, []byte("0123456789ABCDEF0123456789ABCDEF01234567"), []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 1),
		"malformed line":     append(append([]byte(nil), valid...), []byte("source_x86_64=hidden\n")...),
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateSRCINFO(mutated, meta); err == nil {
				t.Fatal("accepted inconsistent .SRCINFO")
			}
		})
	}
}
