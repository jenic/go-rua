package pkgbuild

import (
	"bufio"
	"fmt"
	"strings"
)

// ValidateSRCINFO confirms that static prefetch metadata describes the same
// package, version, source indices, and checksums as the parsed PKGBUILD.
func ValidateSRCINFO(src []byte, meta Metadata) error {
	values := map[string][]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(src)))
	for scanner.Scan() {
		trimmed := strings.TrimSpace(scanner.Text())
		if trimmed == "" {
			continue
		}
		key, value, ok := strings.Cut(trimmed, " = ")
		if !ok || key == "" {
			return fmt.Errorf(".SRCINFO contains malformed metadata line %q", trimmed)
		}
		values[key] = append(values[key], value)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	expectedKeys := make(map[string]bool, len(meta.Sources)+len(meta.Checksums))
	for key := range meta.Sources {
		expectedKeys[key] = true
	}
	for key := range meta.Checksums {
		expectedKeys[key] = true
	}
	for key := range values {
		if strings.HasPrefix(key, "source") || isChecksumKey(key) {
			if !expectedKeys[key] {
				return fmt.Errorf(".SRCINFO contains unexpected %s metadata", key)
			}
		}
	}
	for key, want := range map[string]string{"pkgbase": meta.PackageBase, "pkgver": meta.Version, "pkgrel": meta.Release} {
		if len(values[key]) != 1 || values[key][0] != want {
			return fmt.Errorf(".SRCINFO %s does not match reviewed PKGBUILD", key)
		}
	}
	if meta.Epoch != "" && meta.Epoch != "0" && (len(values["epoch"]) != 1 || values["epoch"][0] != meta.Epoch) {
		return fmt.Errorf(".SRCINFO epoch does not match reviewed PKGBUILD")
	}
	if (meta.Epoch == "" || meta.Epoch == "0") && len(values["epoch"]) != 0 {
		return fmt.Errorf(".SRCINFO contains unexpected epoch metadata")
	}
	if !equal(values["arch"], meta.Architectures) {
		return fmt.Errorf(".SRCINFO arch metadata differs from reviewed PKGBUILD")
	}
	actualKeys := append([]string(nil), values["validpgpkeys"]...)
	for i := range actualKeys {
		actualKeys[i] = strings.ToUpper(strings.TrimSpace(actualKeys[i]))
	}
	if !equal(actualKeys, meta.ValidPGPKeys) {
		return fmt.Errorf(".SRCINFO validpgpkeys metadata differs from reviewed PKGBUILD")
	}
	for key, want := range meta.Sources {
		if !equal(values[key], want) {
			return fmt.Errorf(".SRCINFO %s index mapping differs from reviewed PKGBUILD", key)
		}
	}
	for key, want := range meta.Checksums {
		if !equal(values[key], want) {
			return fmt.Errorf(".SRCINFO %s index mapping differs from reviewed PKGBUILD", key)
		}
	}
	return nil
}

// RewriteSRCINFO updates static build-copy metadata using the same exact
// assignment/index mapping as the PKGBUILD override.
func RewriteSRCINFO(src []byte, override Override) ([]byte, error) {
	values := map[string][]string{"pkgver": {override.Version}, "pkgrel": {override.Release}}
	for key, entries := range override.Sources {
		values[key] = append([]string(nil), entries...)
	}
	for key, entries := range override.Checksums {
		values[key] = append([]string(nil), entries...)
	}
	seen := map[string]int{}
	var output strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(string(src)))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		key, _, ok := strings.Cut(trimmed, " = ")
		entries, replace := values[key]
		if ok && replace {
			index := seen[key]
			if index >= len(entries) {
				return nil, fmt.Errorf(".SRCINFO has too many %s entries", key)
			}
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			output.WriteString(indent + key + " = " + entries[index] + "\n")
			seen[key]++
		} else {
			output.WriteString(line + "\n")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	for key, entries := range values {
		if seen[key] != len(entries) {
			return nil, fmt.Errorf(".SRCINFO %s index mapping differs: got %d want %d", key, seen[key], len(entries))
		}
	}
	return []byte(output.String()), nil
}
