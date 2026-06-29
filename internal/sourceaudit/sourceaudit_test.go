package sourceaudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditDirSRCINFOFindsUnicodeHost(t *testing.T) {
	dir := t.TempDir()
	srcinfo := "pkgbase = demo\nsource = demo::https://exаmple.com/a.tar.gz\nsource_x86_64 = git+https://github.com/demo/repo.git\n"
	if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), []byte(srcinfo), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if len(report.Sources) != 2 {
		t.Fatalf("expected two sources, got %v", report.Sources)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected one finding, got %#v", report.Findings)
	}
	f := report.Findings[0]
	if !strings.Contains(f.ASCIIHost, "xn--") {
		t.Fatalf("expected punycode host, got %q", f.ASCIIHost)
	}
	if !strings.Contains(strings.Join(f.Codepoints, ","), "CYRILLIC") {
		t.Fatalf("expected Cyrillic codepoint details, got %v", f.Codepoints)
	}
}

func TestAuditDirPKGBUILDFallbackAndIncomplete(t *testing.T) {
	dir := t.TempDir()
	pkgbuild := `
source=(
  'https://example.com/a.tar.gz'
  "https://οexample.com/b.tar.gz"
  "https://example.com/${pkgver}.tar.gz"
)
`
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if len(report.Sources) != 3 {
		t.Fatalf("expected three parsed sources, got %#v", report.Sources)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected one Unicode finding, got %#v", report.Findings)
	}
	if len(report.Incomplete) != 1 {
		t.Fatalf("expected incomplete parsing warning, got %#v", report.Incomplete)
	}
}

func TestAuditDirDetectsInvisibleAndMixedScriptHost(t *testing.T) {
	dir := t.TempDir()
	srcinfo := "source = https://exa\u200bmple.com/a.tar.gz\nsource = https://exаmple.com/b.tar.gz\n"
	if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), []byte(srcinfo), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("expected two findings, got %#v", report.Findings)
	}
	out := FormatReport(report)
	if !strings.Contains(out, "default-ignorable") || !strings.Contains(out, "mixes Unicode scripts") {
		t.Fatalf("expected invisible and mixed-script reasons, got %q", out)
	}
}

func TestAuditDirDetectsPunycodeHost(t *testing.T) {
	dir := t.TempDir()
	srcinfo := "source = https://xn--exmple-4nf.com/a.tar.gz\n"
	if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), []byte(srcinfo), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected one finding, got %#v", report.Findings)
	}
	out := FormatReport(report)
	if !strings.Contains(out, "Punycode/IDN") || !strings.Contains(out, "Unicode form:") {
		t.Fatalf("expected punycode warning and Unicode form, got %q", out)
	}
}

func TestAuditSourcesChecksSCPLikeHosts(t *testing.T) {
	report := auditSources([]Source{{
		Key:      "source",
		Value:    "git@github.com:owner/repo.git",
		Location: ".SRCINFO:1",
	}})
	if report.HasWarnings() {
		t.Fatalf("expected no warnings for safe scp-like host, got %#v", report)
	}

	report = auditSources([]Source{{
		Key:      "source",
		Value:    "git@exаmple.com:owner/repo.git",
		Location: ".SRCINFO:2",
	}})
	if len(report.Findings) != 1 {
		t.Fatalf("expected one finding for Unicode scp-like host, got %#v", report.Findings)
	}
	if report.Findings[0].Host != "exаmple.com" {
		t.Fatalf("unexpected finding host: %q", report.Findings[0].Host)
	}
}

func TestSCPLikeHostRejectsInvalidForms(t *testing.T) {
	tests := []string{
		"git@example.com:owner repo.git",
		"https://example.com:443/owner/repo.git",
		"localhost:owner/repo.git",
		"git@example.com/owner:repo.git",
	}
	for _, raw := range tests {
		if got := scpLikeHost(raw); got != "" {
			t.Fatalf("scpLikeHost(%q) = %q, want empty", raw, got)
		}
	}
}

func TestAuditDirChecksSRCINFOAndPKGBUILDWhenBothPresent(t *testing.T) {
	dir := t.TempDir()
	srcinfo := "source = pkg::https://example.com/a.tar.gz\n"
	pkgbuild := "source=('https://example.com/a.tar.gz')\n"
	if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), []byte(srcinfo), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if len(report.Sources) != 2 {
		t.Fatalf("expected sources from both files, got %#v", report.Sources)
	}
	if report.HasWarnings() {
		t.Fatalf("expected no warnings for matching safe sources, got %#v", report)
	}
}

func TestAuditDirFindsExtraPKGBUILDSourceWhenSRCINFOExists(t *testing.T) {
	dir := t.TempDir()
	srcinfo := "source = https://example.com/a.tar.gz\n"
	pkgbuild := `
source=(
  'https://example.com/a.tar.gz'
  'https://exаmple.com/b.tar.gz'
)
`
	if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), []byte(srcinfo), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected Unicode finding for extra PKGBUILD source, got %#v", report.Findings)
	}
	out := FormatReport(report)
	if !strings.Contains(out, "PKGBUILD source not represented in .SRCINFO") {
		t.Fatalf("expected PKGBUILD extra source mismatch, got %q", out)
	}
}

func TestAuditDirReportsSRCINFOSourceMissingFromPKGBUILD(t *testing.T) {
	dir := t.TempDir()
	srcinfo := "source = https://example.com/a.tar.gz\nsource = https://example.com/b.tar.gz\n"
	pkgbuild := "source=('https://example.com/a.tar.gz')\n"
	if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), []byte(srcinfo), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	out := FormatReport(report)
	if !strings.Contains(out, ".SRCINFO source not represented in PKGBUILD literal parsing") {
		t.Fatalf("expected .SRCINFO missing-from-PKGBUILD mismatch, got %q", out)
	}
}

func TestAuditDirResolvesPrimitivePKGBUILDVariables(t *testing.T) {
	dir := t.TempDir()
	srcinfo := strings.Join([]string{
		"pkgbase = brave-origin-bin",
		"pkgname = brave-origin-bin",
		"pkgver = 1.91.172",
		"source = brave-origin-bin.sh",
		"source = brave-origin.desktop",
		"source_x86_64 = brave-origin-bin-1.91.172-x86_64.zip::https://github.com/brave/brave-browser/releases/download/v1.91.172/brave-origin-1.91.172-linux-amd64.zip",
		"source_aarch64 = brave-origin-bin-1.91.172-aarch64.zip::https://github.com/brave/brave-browser/releases/download/v1.91.172/brave-origin-1.91.172-linux-arm64.zip",
		"",
	}, "\n")
	pkgbuild := `pkgname=brave-origin-bin
pkgver=1.91.172
source=("$pkgname.sh" "${pkgname%-bin}.desktop")
source_x86_64=("${pkgname}-${pkgver}-x86_64.zip::https://github.com/brave/brave-browser/releases/download/v${pkgver}/brave-origin-${pkgver}-linux-amd64.zip")
source_aarch64=("${pkgname}-${pkgver}-aarch64.zip::https://github.com/brave/brave-browser/releases/download/v${pkgver}/brave-origin-${pkgver}-linux-arm64.zip")
`
	if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), []byte(srcinfo), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if report.HasWarnings() {
		t.Fatalf("expected primitive variable resolution to avoid warnings, got %#v", report)
	}
}

func TestAuditDirResolvesFirstElementOfSimplePKGBUILDArrayVariable(t *testing.T) {
	dir := t.TempDir()
	srcinfo := "pkgname = demo\nsource = demo.sh\n"
	pkgbuild := "pkgname=(demo demo-docs)\nsource=(\"$pkgname.sh\")\n"
	if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), []byte(srcinfo), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if report.HasWarnings() {
		t.Fatalf("expected first simple array element to resolve, got %#v", report)
	}
}

func TestAuditDirUsesSRCINFOMetadataForMissingPKGBUILDVariable(t *testing.T) {
	dir := t.TempDir()
	srcinfo := "pkgname = demo\npkgver = 1\nsource = https://example.com/demo-1.tar.gz\n"
	pkgbuild := "source=(\"https://example.com/${pkgname}-${pkgver}.tar.gz\")\n"
	if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), []byte(srcinfo), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if report.HasWarnings() {
		t.Fatalf("expected .SRCINFO metadata to seed primitive resolution, got %#v", report)
	}
}

func TestAuditDirKeepsDynamicPKGBUILDWarningWithSRCINFO(t *testing.T) {
	dir := t.TempDir()
	srcinfo := "source = https://example.com/pkg-1.tar.gz\n"
	pkgbuild := "source=(\"https://example.com/pkg-${pkgver}.tar.gz\")\n"
	if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), []byte(srcinfo), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if len(report.Incomplete) != 1 {
		t.Fatalf("expected dynamic PKGBUILD warning, got %#v", report.Incomplete)
	}
	out := FormatReport(report)
	if !strings.Contains(out, "contains shell expansion or unsupported syntax") {
		t.Fatalf("expected incomplete parsing warning, got %q", out)
	}
	if strings.Contains(out, "not represented") {
		t.Fatalf("expected unresolved dynamic source to avoid mismatch spam, got %q", out)
	}
}

func TestAuditDirDoesNotResolveVariablesFromFunctionBody(t *testing.T) {
	dir := t.TempDir()
	srcinfo := "source = https://example.com/pkg-1.tar.gz\n"
	pkgbuild := `prepare() {
  _url=https://example.com/pkg-1.tar.gz
}
source=("$_url")
`
	if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), []byte(srcinfo), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if len(report.Incomplete) != 1 {
		t.Fatalf("expected unresolved function-local variable warning, got %#v", report.Incomplete)
	}
	out := FormatReport(report)
	if strings.Contains(out, "not represented") {
		t.Fatalf("expected unresolved function-local variable not to produce mismatch spam, got %q", out)
	}
}

func TestAuditDirDoesNotResolveVariablesFromConditionalBody(t *testing.T) {
	dir := t.TempDir()
	srcinfo := "source = https://example.com/pkg-1.tar.gz\n"
	pkgbuild := `if true; then
  _url=https://example.com/pkg-1.tar.gz
fi
source=("$_url")
`
	if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), []byte(srcinfo), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if len(report.Incomplete) != 1 {
		t.Fatalf("expected unresolved conditional variable warning, got %#v", report.Incomplete)
	}
}

func TestAuditDirAuditsLiteralSourceInsideConditionalWithoutSRCINFO(t *testing.T) {
	dir := t.TempDir()
	pkgbuild := "if [[ $CARCH == x86_64 ]]; then\n  source=(\"https://exаmple.com/pkg.tar.gz\")\nfi\n"
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected Unicode finding for conditional literal source, got %#v", report.Findings)
	}
}

func TestAuditDirSuppressesMismatchSpamForUnresolvedPKGBUILDSource(t *testing.T) {
	dir := t.TempDir()
	srcinfo := "source = https://example.com/pkg-1.tar.gz\n"
	pkgbuild := "source=(\"https://example.com/pkg-${unknown}.tar.gz\")\n"
	if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), []byte(srcinfo), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if len(report.Incomplete) != 1 {
		t.Fatalf("expected one unresolved-source warning, got %#v", report.Incomplete)
	}
	out := FormatReport(report)
	if strings.Contains(out, ".SRCINFO source not represented") || strings.Contains(out, "PKGBUILD source not represented") {
		t.Fatalf("expected unresolved source not to produce mismatch spam, got %q", out)
	}
}
