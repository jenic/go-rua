package upstream

import (
	"bufio"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// ParseSRCINFO extracts static metadata emitted by makepkg. It does not
// evaluate PKGBUILD shell code.
func ParseSRCINFO(data []byte) (Recipe, error) {
	recipe := Recipe{Checksums: map[string][]string{}}
	seen := map[string]bool{}
	sourceIndices := map[string]int{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, " = ")
		if !ok {
			return Recipe{}, fmt.Errorf("malformed .SRCINFO line %q", line)
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch {
		case key == "pkgbase":
			if seen[key] {
				return Recipe{}, fmt.Errorf("duplicate %s", key)
			}
			seen[key], recipe.PackageBase = true, value
		case key == "pkgver":
			if seen[key] {
				return Recipe{}, fmt.Errorf("duplicate %s", key)
			}
			seen[key], recipe.Version = true, value
		case key == "pkgrel":
			if seen[key] {
				return Recipe{}, fmt.Errorf("duplicate %s", key)
			}
			seen[key], recipe.Release = true, value
		case key == "epoch":
			if seen[key] {
				return Recipe{}, fmt.Errorf("duplicate %s", key)
			}
			seen[key], recipe.Epoch = true, value
		case key == "arch":
			recipe.Architectures = appendUnique(recipe.Architectures, value)
		case key == "source" || strings.HasPrefix(key, "source_"):
			arch := "any"
			if key != "source" {
				arch = strings.TrimPrefix(key, "source_")
			}
			name, alias, sourceURL, err := splitSource(value)
			if err != nil {
				return Recipe{}, err
			}
			index := sourceIndices[key]
			sourceIndices[key]++
			recipe.Sources = append(recipe.Sources, Source{Architecture: arch, Key: key, Index: index, Name: name, Alias: alias, URL: sourceURL})
		case isRecipeChecksumKey(key):
			recipe.Checksums[key] = append(recipe.Checksums[key], value)
		case key == "validpgpkeys":
			recipe.ValidPGPKeys = appendUnique(recipe.ValidPGPKeys, strings.ToUpper(value))
		}
	}
	if err := scanner.Err(); err != nil {
		return Recipe{}, err
	}
	if recipe.PackageBase == "" || recipe.Version == "" || recipe.Release == "" {
		return Recipe{}, fmt.Errorf(".SRCINFO is missing pkgbase, pkgver, or pkgrel")
	}
	if len(recipe.Architectures) == 0 {
		recipe.Architectures = []string{"any"}
	}
	sort.Strings(recipe.Architectures)
	sort.Strings(recipe.ValidPGPKeys)
	sortSources(recipe.Sources)
	return recipe, nil
}

func splitSource(value string) (string, string, string, error) {
	name, rawURL := "", value
	alias := ""
	if left, right, ok := strings.Cut(value, "::"); ok {
		name, alias, rawURL = left, left, right
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid source URL %q", rawURL)
	}
	if u.Scheme == "" {
		if name == "" {
			name = rawURL
		}
		return name, alias, rawURL, nil
	}
	if name == "" {
		parts := strings.Split(strings.TrimSuffix(u.Path, "/"), "/")
		name = strings.TrimSuffix(parts[len(parts)-1], ".git")
	}
	return name, alias, rawURL, nil
}

func isRecipeChecksumKey(key string) bool {
	for _, family := range []string{"md5sums", "sha1sums", "sha224sums", "sha256sums", "sha384sums", "sha512sums", "b2sums"} {
		if key == family || strings.HasPrefix(key, family+"_") {
			return true
		}
	}
	return false
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func sortSources(sources []Source) {
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].Architecture != sources[j].Architecture {
			return sources[i].Architecture < sources[j].Architecture
		}
		if sources[i].Name != sources[j].Name {
			return sources[i].Name < sources[j].Name
		}
		return sources[i].URL < sources[j].URL
	})
}
