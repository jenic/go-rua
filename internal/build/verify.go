package build

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go-rua/internal/pkgbuild"
	"go-rua/internal/review"
	"go-rua/internal/sandbox"
)

// VerifySources runs the approved recipe in isolation, including dynamic sources.
// Static .SRCINFO is not substituted for the effective recipe at this stage.
func VerifySources(dir string, seccomp bool) (review.Report, error) {
	var report review.Report
	gpgHome, err := prepareSandboxGPGHomeFn(dir)
	if err != nil {
		return report, err
	}
	cfg := sandbox.Config{RO: []string{"/etc"}, ROX: []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"}, RWX: []string{dir}, WorkDir: dir, Env: makepkgEnv(dir, gpgHome), UnrestrictedNet: true, SeccompDenylist: seccomp}
	if err := sandbox.Run(cfg, []string{"makepkg", "--nosign", "--verifysource"}); err != nil {
		return report, fmt.Errorf("source verification failed: %w", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "PKGBUILD"))
	if err != nil {
		return report, err
	}
	m, err := pkgbuild.ParseReview(data)
	if err != nil {
		report.Add("source-verification", review.Info, "makepkg", "source verification command completed; dynamic source mappings are not statically assessed")
		return report, nil
	}
	keys := make([]string, 0, len(m.Sources))
	for k := range m.Sources {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key != "source" && key != "source_"+HostArchitecture() {
			report.Add("other-architecture", review.Info, key, "not selected for this host; integrity metadata was inspected statically")
			continue
		}
		for i, source := range m.Sources[key] {
			var methods []string
			for sums, values := range m.Checksums {
				algorithm, arch, hasArch := strings.Cut(sums, "_")
				suffix := ""
				if hasArch {
					suffix = "_" + arch
				}
				if "source"+suffix == key && i < len(values) && values[i] != "SKIP" {
					methods = append(methods, algorithm)
				}
			}
			sort.Strings(methods)
			message := "declared verification: " + strings.Join(methods, ", ")
			if len(methods) == 0 {
				message = "no checksum declared; consult makepkg output for signature/VCS verification"
			}
			report.Add("source-verification", review.Info, fmt.Sprintf("%s[%d]", key, i), source+": "+message)
			if err := recordGitRevision(dir, source, cfg, &report); err != nil {
				return report, err
			}
		}
	}
	report.Add("source-verification", review.Info, "makepkg", "source verification succeeded for the build architecture")
	return report, nil
}

func recordGitRevision(dir, source string, cfg sandbox.Config, report *review.Report) error {
	alias, raw, hasAlias := strings.Cut(source, "::")
	if !hasAlias {
		raw = source
		alias = ""
	}
	if !strings.HasPrefix(raw, "git+") {
		return nil
	}
	u, err := url.Parse(strings.TrimPrefix(raw, "git+"))
	if err != nil {
		return err
	}
	if alias == "" {
		alias = strings.TrimSuffix(filepath.Base(u.Path), ".git")
	}
	if alias == "" || alias == "." || filepath.Base(alias) != alias {
		return fmt.Errorf("invalid Git source destination")
	}
	ref := "HEAD"
	if u.Fragment != "" {
		kind, value, ok := strings.Cut(strings.TrimSuffix(u.Fragment, "?signed"), "=")
		if !ok {
			return fmt.Errorf("unresolved Git source reference")
		}
		switch kind {
		case "commit":
			ref = value
		case "tag":
			ref = "refs/tags/" + value
		case "branch":
			ref = "refs/heads/" + value
		default:
			return fmt.Errorf("unsupported Git reference kind %s", kind)
		}
	}
	out, _, err := sandbox.RunCapture(cfg, []string{"git", "--no-replace-objects", "-C", filepath.Join(dir, alias), "rev-parse", "--verify", "--end-of-options", ref + "^{commit}"})
	if err != nil {
		return fmt.Errorf("record fetched Git revision: %w", err)
	}
	commit := strings.TrimSpace(out)
	if _, err := hex.DecodeString(commit); err != nil || (len(commit) != 40 && len(commit) != 64) {
		return fmt.Errorf("invalid fetched Git object identity")
	}
	report.Add("git-revision", review.Info, alias, ref+" resolved to "+commit)
	return nil
}
