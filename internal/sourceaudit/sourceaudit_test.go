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
}
