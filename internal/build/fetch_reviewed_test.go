package build

import (
	"go-rua/internal/review"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type reviewedTransport func(*http.Request) (*http.Response, error)

func (f reviewedTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestReviewedDownloadTracksRedirectsAndRejectsDowngrade(t *testing.T) {
	for _, kind := range []string{"direct", "redirect", "downgrade", "http error"} {
		t.Run(kind, func(t *testing.T) {
			old := sourceHTTPClient
			defer func() { sourceHTTPClient = old }()
			sourceHTTPClient = &http.Client{Transport: reviewedTransport(func(r *http.Request) (*http.Response, error) {
				h := make(http.Header)
				code := 200
				body := "source bytes"
				if r.URL.Host == "origin.test" && kind == "redirect" {
					code = 302
					h.Set("Location", "https://cdn.test/source.tar")
				}
				if r.URL.Host == "origin.test" && kind == "downgrade" {
					code = 302
					h.Set("Location", "http://cdn.test/source.tar")
				}
				if kind == "http error" {
					code = 404
				}
				return &http.Response{StatusCode: code, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})}
			dir := t.TempDir()
			os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=app\npkgver=1\npkgrel=1\nsource=('https://origin.test/source.tar')\n"), 0600)
			report, err := FetchReviewedSources(dir)
			if (err != nil) != (kind == "downgrade" || kind == "http error") {
				t.Fatal(err)
			}
			if kind == "redirect" && !report.Has(review.Review) {
				t.Fatal("redirect was not surfaced")
			}
			if err == nil {
				b, e := os.ReadFile(filepath.Join(dir, "source.tar"))
				if e != nil || string(b) != "source bytes" {
					t.Fatal(string(b), e)
				}
			}
		})
	}
}
func TestReviewedDownloadRejectsSymlinkDestination(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=app\npkgver=1\npkgrel=1\nsource=('https://origin.test/source.tar')\n"), 0600)
	os.Symlink("/etc/passwd", filepath.Join(dir, "source.tar"))
	if _, err := FetchReviewedSources(dir); err == nil {
		t.Fatal("symlink destination accepted")
	}
}
