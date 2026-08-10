package upstream

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	policyVersion = 1
	maxPolicySize = 1 << 20
)

var envNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

var effectiveUID = func() uint32 { return uint32(os.Geteuid()) }

type HostPolicy struct {
	Name               string   `json:"host"`
	APIBase            string   `json:"api_base"`
	AssetRedirectHosts []string `json:"asset_redirect_hosts,omitempty"`
	TokenEnv           string   `json:"token_env,omitempty"`
	AllowPort          bool     `json:"allow_nondefault_port,omitempty"`
}

type PackagePolicy struct {
	Package             string            `json:"package"`
	Host                string            `json:"host"`
	Repository          string            `json:"repository"`
	Channel             string            `json:"channel"`
	TagTemplate         string            `json:"tag_template"`
	AssetTemplates      map[string]string `json:"asset_templates"`
	TrustedFingerprints []string          `json:"trusted_fingerprints,omitempty"`
}

type Policy struct {
	Hosts       map[string]HostPolicy
	Packages    map[string]PackagePolicy
	Diagnostics map[string]string
}

type policyDocument struct {
	Version  int               `json:"version"`
	Hosts    []json.RawMessage `json:"hosts,omitempty"`
	Packages []json.RawMessage `json:"packages,omitempty"`
}

func DefaultPolicyPath() string {
	home, _ := os.UserHomeDir()
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "rua", "github_upstream.json")
}

// LoadPolicy reads a bounded private configuration without following the final
// path component. Package validation failures remain scoped diagnostics so a
// normal status plan can continue for unrelated packages.
func LoadPolicy(path string) (Policy, error) {
	policy := Policy{Hosts: map[string]HostPolicy{}, Packages: map[string]PackagePolicy{}, Diagnostics: map[string]string{}}
	if path == "" {
		path = DefaultPolicyPath()
	}
	data, err := readPrivatePolicyFile(path)
	if os.IsNotExist(err) {
		return policy, nil
	}
	if err != nil {
		return policy, err
	}
	var document policyDocument
	if err := decodeStrict(data, &document); err != nil {
		return policy, fmt.Errorf("decode GitHub upstream policy: %w", err)
	}
	if document.Version != policyVersion {
		return policy, fmt.Errorf("unsupported GitHub upstream policy version %d", document.Version)
	}
	for index, raw := range document.Hosts {
		var host HostPolicy
		if err := decodeStrict(raw, &host); err != nil {
			return policy, fmt.Errorf("hosts[%d]: %w", index, err)
		}
		validated, err := validateHostPolicy(host)
		if err != nil {
			return policy, fmt.Errorf("hosts[%d]: %w", index, err)
		}
		if _, exists := policy.Hosts[validated.Name]; exists {
			return policy, fmt.Errorf("hosts[%d]: duplicate host %q", index, validated.Name)
		}
		policy.Hosts[validated.Name] = validated
	}
	seenPackages := map[string]int{}
	for index, raw := range document.Packages {
		var identity struct {
			Package string `json:"package"`
		}
		if err := json.Unmarshal(raw, &identity); err != nil || !validPackageBase(identity.Package) {
			return policy, fmt.Errorf("packages[%d]: package identity is missing, malformed, or invalid", index)
		}
		name := identity.Package
		if previous, exists := seenPackages[name]; exists {
			reason := fmt.Sprintf("duplicate package policy at indices %d and %d", previous, index)
			policy.Diagnostics[name] = reason
			delete(policy.Packages, name)
			continue
		}
		seenPackages[name] = index
		var packagePolicy PackagePolicy
		if err := decodeStrict(raw, &packagePolicy); err != nil {
			policy.Diagnostics[name] = err.Error()
			continue
		}
		validated, err := validatePackagePolicy(packagePolicy, policy.Hosts)
		if err != nil {
			policy.Diagnostics[name] = err.Error()
			continue
		}
		policy.Packages[validated.Package] = validated
	}
	return policy, nil
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return fmt.Errorf("trailing JSON value")
	} else if !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func readPrivatePolicyFile(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	if err := validateFDOwner(fd, "GitHub upstream policy"); err != nil {
		unix.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("open policy returned no file")
	}
	defer file.Close()
	if err := validateOpenedDirectory(filepath.Dir(path), true, "GitHub upstream policy directory"); err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("GitHub upstream policy is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("GitHub upstream policy permissions must not grant group or other access")
	}
	if info.Size() > maxPolicySize {
		return nil, fmt.Errorf("GitHub upstream policy exceeds %d bytes", maxPolicySize)
	}
	return readLimited(file, maxPolicySize)
}

func validateFDOwner(fd int, label string) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("stat %s: %w", label, err)
	}
	if stat.Uid != effectiveUID() {
		return fmt.Errorf("%s must be owned by the effective user", label)
	}
	return nil
}

func validateOpenedDirectory(path string, private bool, label string) error {
	if err := rejectSymlinkComponents(path); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if err := validateFDOwner(fd, label); err != nil {
		unix.Close(fd)
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return fmt.Errorf("%s: open returned no directory", label)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.IsDir() {
		return fmt.Errorf("%s is not a regular directory", label)
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s permissions must not grant group or other access", label)
	}
	return nil
}

func validateHostPolicy(policy HostPolicy) (HostPolicy, error) {
	host, err := canonicalHost(policy.Name, policy.AllowPort)
	if err != nil {
		return HostPolicy{}, fmt.Errorf("host: %w", err)
	}
	api, err := parseOrigin(policy.APIBase, policy.AllowPort)
	if err != nil {
		return HostPolicy{}, fmt.Errorf("api_base: %w", err)
	}
	if policy.TokenEnv != "" && !envNamePattern.MatchString(policy.TokenEnv) {
		return HostPolicy{}, fmt.Errorf("token_env must be an uppercase environment variable name")
	}
	seen := map[string]bool{}
	redirects := make([]string, 0, len(policy.AssetRedirectHosts))
	for _, value := range policy.AssetRedirectHosts {
		redirect, err := canonicalHost(value, policy.AllowPort)
		if err != nil {
			return HostPolicy{}, fmt.Errorf("asset_redirect_hosts: %w", err)
		}
		if seen[redirect] {
			return HostPolicy{}, fmt.Errorf("duplicate asset redirect host %q", redirect)
		}
		seen[redirect] = true
		redirects = append(redirects, redirect)
	}
	sort.Strings(redirects)
	policy.Name = host
	policy.APIBase = api.String()
	policy.AssetRedirectHosts = redirects
	return policy, nil
}

func validatePackagePolicy(policy PackagePolicy, hosts map[string]HostPolicy) (PackagePolicy, error) {
	if !validPackageBase(policy.Package) {
		return PackagePolicy{}, fmt.Errorf("invalid package name %q", policy.Package)
	}
	host, err := canonicalHost(policy.Host, false)
	if err != nil {
		// A configured non-default port is accepted only when its matching host
		// policy explicitly enables it.
		host, err = canonicalHost(policy.Host, true)
		if err != nil {
			return PackagePolicy{}, fmt.Errorf("host: %w", err)
		}
	}
	hostPolicy, exists := hosts[host]
	if !exists {
		return PackagePolicy{}, fmt.Errorf("host %q has no configured API policy", host)
	}
	if strings.Contains(host, ":") && !hostPolicy.AllowPort {
		return PackagePolicy{}, fmt.Errorf("host %q uses a port not enabled by host policy", host)
	}
	parts := strings.Split(policy.Repository, "/")
	if len(parts) != 2 || !validGitHubComponent(parts[0]) || !validGitHubComponent(parts[1]) {
		return PackagePolicy{}, fmt.Errorf("repository must be canonical owner/name")
	}
	if policy.Channel == "" {
		policy.Channel = "stable"
	}
	if policy.Channel != "stable" && policy.Channel != "prerelease" {
		return PackagePolicy{}, fmt.Errorf("channel must be stable or prerelease")
	}
	if err := validatePolicyTemplate(policy.TagTemplate, "tag_template"); err != nil {
		return PackagePolicy{}, err
	}
	cleanTemplates := make(map[string]string, len(policy.AssetTemplates))
	for arch, template := range policy.AssetTemplates {
		if arch == "" || strings.ContainsAny(arch, "/\\\x00") {
			return PackagePolicy{}, fmt.Errorf("invalid asset architecture %q", arch)
		}
		if err := validatePolicyTemplate(template, "asset_templates["+arch+"]"); err != nil {
			return PackagePolicy{}, err
		}
		if filepath.Base(template) != template || strings.ContainsAny(template, "?&#%\\") {
			return PackagePolicy{}, fmt.Errorf("asset_templates[%s] must be a literal release filename", arch)
		}
		cleanTemplates[arch] = template
	}
	seenFingerprints := map[string]bool{}
	for index, fingerprint := range policy.TrustedFingerprints {
		fingerprint = strings.ToUpper(strings.TrimSpace(fingerprint))
		if !validFingerprintValue(fingerprint) {
			return PackagePolicy{}, fmt.Errorf("trusted_fingerprints[%d] is not a full OpenPGP fingerprint", index)
		}
		if seenFingerprints[fingerprint] {
			return PackagePolicy{}, fmt.Errorf("duplicate trusted fingerprint %s", fingerprint)
		}
		seenFingerprints[fingerprint] = true
		policy.TrustedFingerprints[index] = fingerprint
	}
	sort.Strings(policy.TrustedFingerprints)
	policy.Host = host
	policy.Repository = parts[0] + "/" + parts[1]
	policy.AssetTemplates = cleanTemplates
	return policy, nil
}

func validatePolicyTemplate(value, field string) error {
	if !isASCII(value) || strings.Count(value, "{version}") != 1 || strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("%s must contain exactly one literal {version} token", field)
	}
	return nil
}

func canonicalHost(value string, allowPort bool) (string, error) {
	if value == "" || !isASCII(value) || strings.ContainsAny(value, "/\\@?#") || strings.ToLower(value) != value {
		return "", fmt.Errorf("must be a canonical lowercase ASCII host")
	}
	u, err := url.Parse("https://" + value)
	if err != nil || u.Host != value || u.Hostname() == "" || u.User != nil {
		return "", fmt.Errorf("must be a canonical ASCII HTTPS host")
	}
	if u.Port() != "" && (!allowPort || u.Port() == "443") {
		return "", fmt.Errorf("nondefault ports require explicit host policy")
	}
	hostname := u.Hostname()
	if len(hostname) > 253 || strings.HasPrefix(hostname, ".") || strings.HasSuffix(hostname, ".") {
		return "", fmt.Errorf("must be a canonical DNS host")
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || !isASCIILetterOrDigit(label[0]) || !isASCIILetterOrDigit(label[len(label)-1]) {
			return "", fmt.Errorf("must be a canonical DNS host")
		}
		for index := 1; index < len(label)-1; index++ {
			if !isASCIILetterOrDigit(label[index]) && label[index] != '-' {
				return "", fmt.Errorf("must be a canonical DNS host")
			}
		}
	}
	return value, nil
}

func parseOrigin(value string, allowPort bool) (*url.URL, error) {
	if !isASCII(value) {
		return nil, fmt.Errorf("must be ASCII HTTPS")
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("must be an HTTPS origin without path, query, fragment, or userinfo")
	}
	if _, err := canonicalHost(u.Host, allowPort); err != nil {
		return nil, err
	}
	return u, nil
}

func validFingerprintValue(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func (p Policy) Package(name string) (PackagePolicy, bool) {
	value, ok := p.Packages[name]
	return value, ok
}
