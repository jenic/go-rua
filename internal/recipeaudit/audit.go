// Package recipeaudit compares recipes without evaluating shell code.
package recipeaudit

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"

	"go-rua/internal/pkgbuild"
	"go-rua/internal/review"
	"go-rua/internal/reviewstate"
)

type Comparator func(string, string) (int, error)

func Audit(before, after reviewstate.Snapshot, installed string, devel bool, compare Comparator) review.Report {
	var r review.Report
	if before == nil {
		r.Add("baseline", review.Review, "recipe", "no confirmed installed recipe baseline; review every file")
	}
	old, oldErr := pkgbuild.ParseReview(before.Get("PKGBUILD"))
	next, err := pkgbuild.ParseReview(after.Get("PKGBUILD"))
	if err != nil {
		r.Add("static-incomplete", review.Review, "PKGBUILD", "static metadata could not be assessed: "+err.Error())
	} else {
		for _, reason := range next.Incomplete {
			r.Add("packaging-incomplete", review.Review, "PKGBUILD", reason)
		}
		version := Version(next)
		if installed != "" {
			cmp, err := compare(version, installed)
			if err != nil {
				r.Add("version-check", review.Block, "pkgver", err.Error())
			} else if cmp <= 0 {
				action := review.Block
				if devel {
					action = review.Review
				}
				r.Add("version-order", action, "pkgver", fmt.Sprintf("candidate %s is not newer than installed %s", version, installed))
			} else {
				r.Add("version-order", review.Info, "pkgver", installed+" -> "+version)
			}
		}
		if data := after.Get(".SRCINFO"); data != nil {
			if err := pkgbuild.ValidateSRCINFO(data, next); err != nil {
				r.Add("metadata-mismatch", review.Block, ".SRCINFO", err.Error())
			}
			if !sameValues(Fields(data, "pkgname"), next.PackageNames) {
				r.Add("package-identity", review.Block, ".SRCINFO", "package names differ from PKGBUILD")
			}
			// Split functions may override inherited metadata; mark those unresolved.
			if len(next.PackageNames) == 1 && len(next.Incomplete) == 0 {
				keys := map[string]bool{}
				for key := range next.Packaging {
					keys[key] = true
				}
				for _, line := range strings.Split(string(data), "\n") {
					key, _, ok := strings.Cut(strings.TrimSpace(line), " = ")
					if ok && packagingField(key) {
						keys[key] = true
					}
				}
				for key := range keys {
					var values []string
					for _, line := range strings.Split(string(data), "\n") {
						k, v, ok := strings.Cut(strings.TrimSpace(line), " = ")
						if ok && k == key {
							values = append(values, v)
						}
					}
					if !sameValues(values, next.Packaging[key]) {
						r.Add("packaging-mismatch", review.Block, key, ".SRCINFO packaging metadata differs from PKGBUILD")
					}
				}
			}
		} else {
			r.Add("metadata-missing", review.Review, ".SRCINFO", "metadata is missing; dependency/source assessment is incomplete")
		}
		checkIntegrity(&r, next)
		if oldErr == nil {
			if old.Epoch != next.Epoch {
				r.Add("epoch", review.Review, "epoch", old.Epoch+" -> "+next.Epoch)
			}
			if !reflect.DeepEqual(old.ValidPGPKeys, next.ValidPGPKeys) {
				r.Add("signing-keys", review.Review, "validpgpkeys", fmt.Sprintf("%v -> %v", old.ValidPGPKeys, next.ValidPGPKeys))
			}
			compareSources(&r, old, next)
			for key, values := range old.Checksums {
				newValues, ok := next.Checksums[key]
				if !ok {
					r.Add("verification-removed", review.Review, key, "checksum algorithm removed")
				}
				for i, v := range newValues {
					if i < len(values) && v == "SKIP" && values[i] != "SKIP" {
						r.Add("verification-skipped", review.Review, key, fmt.Sprintf("source %d changed to SKIP", i))
					}
				}
			}
			if logic(before.Get("PKGBUILD"), old) != logic(after.Get("PKGBUILD"), next) {
				r.Add("recipe-logic", review.Review, "PKGBUILD", "commands, functions, or other packaging metadata changed; inspect the diff")
			}
		}
	}
	for _, f := range after {
		if f.Path == "PKGBUILD" || f.Path == ".SRCINFO" {
			continue
		}
		if string(before.Get(f.Path)) != string(f.Data) || before.Get(f.Path) == nil {
			r.Add("supporting-file", review.Review, f.Path, "new or changed recipe input")
		}
	}
	for _, f := range before {
		if after.Get(f.Path) == nil {
			r.Add("removed-input", review.Review, f.Path, "recipe input removed")
		}
	}
	if a, b := before.Get(".SRCINFO"), after.Get(".SRCINFO"); a != nil && b != nil {
		for _, key := range []string{"depends", "makedepends", "checkdepends", "optdepends", "provides", "conflicts", "replaces", "install", "options", "pkgname"} {
			oldFields, newFields := Fields(a, key), Fields(b, key)
			if !reflect.DeepEqual(oldFields, newFields) {
				r.Add("package-metadata", review.Review, key, fmt.Sprintf("%v -> %v", oldFields, newFields))
			}
		}
	}
	sort.SliceStable(r.Findings, func(i, j int) bool { return r.Findings[i].Location < r.Findings[j].Location })
	return r
}

func sameValues(a, b []string) bool { return strings.Join(a, "\x00") == strings.Join(b, "\x00") }
func packagingField(key string) bool {
	for _, k := range []string{"depends", "makedepends", "checkdepends", "optdepends", "provides", "conflicts", "replaces", "install", "options", "backup"} {
		if key == k || strings.HasPrefix(key, k+"_") {
			return true
		}
	}
	return false
}
func Version(m pkgbuild.Metadata) string {
	v := m.Version + "-" + m.Release
	if m.Epoch != "" && m.Epoch != "0" {
		v = m.Epoch + ":" + v
	}
	return v
}
func Fields(data []byte, key string) []string {
	var values []string
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " = ")
		if ok && (k == key || strings.HasPrefix(k, key+"_")) {
			values = append(values, v)
		}
	}
	return values
}

func FieldsForArchitecture(data []byte, key, arch string) []string {
	var values []string
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " = ")
		if ok && (k == key || k == key+"_"+arch) {
			values = append(values, v)
		}
	}
	return values
}
func logic(src []byte, m pkgbuild.Metadata) string {
	var assignments []pkgbuild.Assignment
	for key, a := range m.Assignments {
		if key == "pkgver" || key == "pkgrel" || key == "epoch" || key == "source" || strings.HasPrefix(key, "source_") || strings.Contains(key, "sums") || key == "validpgpkeys" {
			assignments = append(assignments, a)
		}
	}
	sort.Slice(assignments, func(i, j int) bool { return assignments[i].Start > assignments[j].Start })
	out := append([]byte(nil), src...)
	for _, a := range assignments {
		out = append(out[:a.Start], out[a.End:]...)
	}
	return string(out)
}

var algorithms = map[string]int{"cksums": 0, "md5sums": 16, "sha1sums": 20, "sha224sums": 28, "sha256sums": 32, "sha384sums": 48, "sha512sums": 64, "b2sums": 64}

func checkIntegrity(r *review.Report, m pkgbuild.Metadata) {
	for sourceKey, sources := range m.Sources {
		suffix := strings.TrimPrefix(sourceKey, "source")
		covered := make([]bool, len(sources))
		for algorithm, size := range algorithms {
			key := algorithm + suffix
			values, ok := m.Checksums[key]
			if !ok {
				continue
			}
			if len(values) != len(sources) {
				r.Add("checksum-count", review.Block, key, "checksum count does not match source count")
				continue
			}
			for i, value := range values {
				loc := fmt.Sprintf("%s[%d]", key, i)
				if value == "SKIP" {
					r.Add("checksum-skip", review.Review, loc, "checksum skipped for "+sources[i]+"; assess signature or VCS verification")
					continue
				}
				if size == 0 {
					r.Add("checksum-weak", review.Review, loc, "CRC checksum offers weak integrity protection")
					covered[i] = true
					continue
				}
				decoded, err := hex.DecodeString(value)
				if err != nil || len(decoded) != size {
					r.Add("checksum-format", review.Block, loc, "malformed checksum")
				} else {
					covered[i] = true
				}
				if size < 28 {
					r.Add("checksum-weak", review.Review, loc, "weak checksum algorithm")
				}
			}
		}
		for i, ok := range covered {
			if !ok {
				r.Add("integrity-incomplete", review.Review, fmt.Sprintf("%s[%d]", sourceKey, i), "no usable checksum; verification requires review")
			}
		}
	}
}
func compareSources(r *review.Report, a, b pkgbuild.Metadata) {
	for key, values := range b.Sources {
		for i, next := range values {
			loc := fmt.Sprintf("%s[%d]", key, i)
			if i >= len(a.Sources[key]) {
				r.Add("source-added", review.Review, loc, next)
				continue
			}
			old := a.Sources[key][i]
			if old == next {
				continue
			}
			u, e1 := sourceURL(old)
			v, e2 := sourceURL(next)
			if e1 != nil || e2 != nil {
				r.Add("source-unresolved", review.Review, loc, old+" -> "+next)
				continue
			}
			identityChanged := u.Scheme != v.Scheme || !strings.EqualFold(u.Host, v.Host) || u.User != nil || v.User != nil
			if strings.EqualFold(u.Hostname(), "github.com") || strings.EqualFold(u.Hostname(), "gitlab.com") {
				identityChanged = identityChanged || project(u.Path) != project(v.Path)
			}
			if identityChanged {
				r.Add("source-identity", review.Review, loc, old+" -> "+next)
			} else if strings.ReplaceAll(old, a.Version, "{version}") != strings.ReplaceAll(next, b.Version, "{version}") {
				r.Add("source-path", review.Review, loc, old+" -> "+next)
			} else {
				r.Add("source-version", review.Info, loc, "source identity unchanged; release path updated")
			}
		}
	}
	for key, values := range a.Sources {
		if len(values) > len(b.Sources[key]) {
			r.Add("source-removed", review.Review, key, "source entries removed")
		}
	}
}
func sourceURL(s string) (*url.URL, error) {
	if _, v, ok := strings.Cut(s, "::"); ok {
		s = v
	}
	s = strings.TrimPrefix(s, "git+")
	u, err := url.Parse(s)
	if err == nil && (u.Host == "" || u.Scheme == "") {
		err = fmt.Errorf("not a resolved remote URL")
	}
	return u, err
}
func project(s string) string {
	parts := strings.Split(strings.Trim(s, "/"), "/")
	if len(parts) < 2 {
		return s
	}
	return parts[0] + "/" + strings.TrimSuffix(parts[1], ".git")
}
