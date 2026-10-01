package build

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"go-rua/internal/pkgbuild"
	"go-rua/internal/review"
)

var sourceHTTPClient = &http.Client{Timeout: 20 * time.Minute}

// FetchReviewedSources retrieves statically resolved HTTPS sources as data. It
// records the redirects of the actual downloads later consumed by makepkg.
// Dynamic and VCS recipes remain explicit review cases handled by makepkg.
func FetchReviewedSources(dir string) (review.Report, error) {
	var report review.Report
	data, err := os.ReadFile(filepath.Join(dir, "PKGBUILD"))
	if err != nil {
		return report, err
	}
	m, err := pkgbuild.ParseReview(data)
	if err != nil {
		report.Add("dynamic-fetch", review.Review, "sources", "source URLs and redirects cannot be resolved statically; approved recipe will fetch inside the sandbox")
		return report, nil
	}
	arch := HostArchitecture()
	seen := map[string]bool{}
	for _, key := range []string{"source", "source_" + arch} {
		for _, source := range m.Sources[key] {
			name, raw, alias := strings.Cut(source, "::")
			if !alias {
				raw = source
				name = ""
			}
			u, err := url.Parse(raw)
			if err != nil {
				return report, err
			}
			if u.Scheme == "" {
				continue
			}
			if u.Scheme != "https" {
				report.Add("runtime-fetch", review.Review, key, "makepkg must fetch "+source+"; redirect destinations are not assessed by the static downloader")
				continue
			}
			if u.User != nil || u.Fragment != "" {
				return report, fmt.Errorf("unsupported source URL credentials or fragment")
			}
			if name == "" {
				name = path.Base(u.Path)
			}
			if name == "" || name == "." || filepath.Base(name) != name || strings.HasPrefix(name, ".") || strings.ContainsAny(name, "\\\x00\r\n") || name == "PKGBUILD" {
				return report, fmt.Errorf("unsafe source destination %q", name)
			}
			if seen[name] {
				return report, fmt.Errorf("duplicate source destination %q", name)
			}
			seen[name] = true
			dst := filepath.Join(dir, name)
			if st, err := os.Lstat(dst); err == nil {
				if !st.Mode().IsRegular() {
					return report, fmt.Errorf("source destination is not regular: %s", name)
				}
				// Overrides may have already downloaded and verified this exact source.
				report.Add("existing-source", review.Info, name, "existing source will be reverified by makepkg")
				continue
			} else if !os.IsNotExist(err) {
				return report, err
			}
			client := *sourceHTTPClient
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many source redirects")
				}
				if req.URL.Scheme != "https" || req.URL.User != nil {
					return fmt.Errorf("source redirect downgraded HTTPS or introduced credentials")
				}
				prev := via[len(via)-1].URL
				if !strings.EqualFold(req.URL.Host, prev.Host) {
					report.Add("source-redirect", review.Review, name, "download redirected from "+prev.Host+" to "+req.URL.Host)
				}
				return nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
			if err != nil {
				cancel()
				return report, err
			}
			resp, err := client.Do(req)
			if err != nil {
				cancel()
				return report, fmt.Errorf("download %s: %w", name, err)
			}
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				cancel()
				return report, fmt.Errorf("download %s: HTTP %d", name, resp.StatusCode)
			}
			f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				resp.Body.Close()
				cancel()
				return report, err
			}
			n, copyErr := io.Copy(f, io.LimitReader(resp.Body, (4<<30)+1))
			closeErr := f.Close()
			resp.Body.Close()
			cancel()
			if copyErr != nil || closeErr != nil || n > 4<<30 {
				os.Remove(dst)
				return report, fmt.Errorf("source download incomplete or exceeds limit: %s", name)
			}
			report.Add("source-downloaded", review.Info, name, "downloaded from "+resp.Request.URL.Host)
		}
	}
	return report, nil
}

func HostArchitecture() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "386":
		return "i686"
	case "arm64":
		return "aarch64"
	case "arm":
		return "armv7h"
	default:
		return runtime.GOARCH
	}
}
