package upstream

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"

	"go-rua/internal/pkgbuild"
	"golang.org/x/sys/unix"
)

const (
	maxArtifactSize = int64(2 << 30)
	maxSidecarSize  = int64(1 << 20)
)

type ApplyRequest struct {
	Name         string
	LocalVersion string
	PackageBase  string
	AURVersion   string
	Candidate    Candidate
}

type Mapping struct {
	Kind         string
	Architecture string
	SourceKey    string
	ChecksumKey  string
	Index        int
	Next         string
	Asset        Asset
	GitReference GitReference
}

type Plan struct {
	PackageBase string
	FromVersion string
	ToVersion   string
	Release     string
	Mappings    []Mapping
}

type SignatureResult struct {
	Fingerprint   string
	Valid         bool
	Revoked       bool
	Expired       bool
	KeyAlgorithm  int
	HashAlgorithm int
}

type SignatureVerifier interface {
	Verify(context.Context, []byte, []byte, []string) (SignatureResult, error)
}

type FileSignatureVerifier interface {
	VerifyFile(context.Context, string, []byte, []string) (SignatureResult, error)
}

type ApplyOptions struct {
	HTTP              *http.Client
	Verifier          SignatureVerifier
	HostArch          string
	EvidenceDir       string
	Audit             func(string) error
	Confirm           func(string, Evidence) (bool, error)
	Revalidate        func(context.Context, ApplyRequest) (Candidate, error)
	ValidateAllArches bool
}

type Evidence struct {
	PackageBase           string                 `json:"package_base"`
	AURVersion            string                 `json:"aur_version"`
	Upstream              string                 `json:"upstream_version"`
	Repository            string                 `json:"repository"`
	ProviderHostHash      string                 `json:"provider_host_hash"`
	APIOriginHash         string                 `json:"api_origin_hash"`
	ReleaseID             int64                  `json:"release_id"`
	Tag                   string                 `json:"tag"`
	ArtifactHashes        []string               `json:"artifact_hashes"`
	Sources               []string               `json:"sources"`
	Signers               []string               `json:"signers,omitempty"`
	Artifacts             []ArtifactEvidence     `json:"artifacts"`
	GitReferences         []GitReferenceEvidence `json:"git_references,omitempty"`
	HostArchitecture      string                 `json:"host_architecture"`
	BaselineRecipeSHA256  string                 `json:"baseline_recipe_sha256"`
	GeneratedRecipeSHA256 string                 `json:"generated_recipe_sha256"`
	AppliedAt             string                 `json:"applied_at"`
}

type GitReferenceEvidence struct {
	Architecture      string `json:"architecture"`
	SourceKey         string `json:"source_key"`
	SourceIndex       int    `json:"source_index"`
	TagHash           string `json:"tag_hash"`
	RefSHA            string `json:"ref_sha"`
	CommitSHA         string `json:"commit_sha"`
	ObjectType        string `json:"object_type"`
	SignatureRequired bool   `json:"signature_required"`
	SignatureVerified bool   `json:"signature_verified"`
	Signer            string `json:"signer,omitempty"`
}

type ArtifactEvidence struct {
	ID           int64             `json:"id"`
	Name         string            `json:"name"`
	Architecture string            `json:"architecture"`
	NameHash     string            `json:"name_hash"`
	SHA256       string            `json:"sha256"`
	Methods      []string          `json:"methods"`
	Signers      []string          `json:"signers,omitempty"`
	Size         int64             `json:"size"`
	URLHash      string            `json:"url_hash"`
	APIDigest    string            `json:"api_digest,omitempty"`
	Sidecars     []SidecarEvidence `json:"sidecars,omitempty"`
}

type SidecarEvidence struct {
	ID          int64  `json:"id"`
	Kind        string `json:"kind"`
	Size        int64  `json:"size"`
	URLHash     string `json:"url_hash"`
	APIDigest   string `json:"api_digest,omitempty"`
	LocalSHA256 string `json:"local_sha256"`
	Status      string `json:"status"`
}

func HostArchitecture() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "386":
		return "i686"
	case "arm64":
		return "aarch64"
	default:
		return runtime.GOARCH
	}
}

// PlanOverride proves a one-to-one mapping between the current recipe's
// GitHub sources, matching SHA-256 arrays, and selected assets or Git refs.
func PlanOverride(recipe []byte, request ApplyRequest, hostArch string) (Plan, error) {
	return PlanOverrideForArchitectures(recipe, request, hostArch, false)
}

func PlanOverrideForArchitectures(recipe []byte, request ApplyRequest, hostArch string, allArchitectures bool) (Plan, error) {
	meta, err := pkgbuild.Parse(recipe)
	if err != nil {
		return Plan{}, err
	}
	if hostArch == "" {
		hostArch = HostArchitecture()
	}
	nextSources, err := meta.SourcesAt(request.Candidate.Version, "1")
	if err != nil {
		return Plan{}, err
	}
	for key, sources := range meta.Sources {
		if allArchitectures {
			continue
		}
		if key == "source" || key == "source_"+hostArch {
			continue
		}
		for index, source := range sources {
			if source != nextSources[key][index] {
				return Plan{}, fmt.Errorf("%s is version-dependent non-host metadata", key)
			}
		}
	}
	if meta.PackageBase != request.PackageBase {
		return Plan{}, fmt.Errorf("recipe package base %q does not match %q", meta.PackageBase, request.PackageBase)
	}
	if request.Candidate.Provider != "github" || request.Candidate.Repository == "" || !stableVersionPattern.MatchString(request.Candidate.Version) || !request.Candidate.NewerThanAUR || !request.Candidate.NewerThanLocal || len(request.Candidate.Assets)+len(request.Candidate.GitReferences) == 0 {
		return Plan{}, fmt.Errorf("candidate is not a complete GitHub candidate")
	}
	for _, reference := range request.Candidate.GitReferences {
		if reference.Tag != request.Candidate.Tag || !validGitObjectID(reference.RefSHA) || !validGitObjectID(reference.CommitSHA) || (reference.ObjectType != "tag" && reference.ObjectType != "commit") || reference.SourceKey == "" || reference.SourceIndex < 0 {
			return Plan{}, fmt.Errorf("selected Git reference metadata is inconsistent")
		}
		if reference.SignatureRequired && (!reference.SignaturePresent || len(reference.Signature) == 0 || len(reference.Payload) == 0) {
			return Plan{}, fmt.Errorf("selected Git tag requires an anchored signature")
		}
	}
	for _, asset := range request.Candidate.Assets {
		host := request.Candidate.Host
		if host == "" {
			host = "github.com"
		}
		parsed, err := ParseGitHubReleaseAssetURLAt(asset.URL, host)
		if err != nil || parsed.Repository.String() != request.Candidate.Repository || parsed.Tag != request.Candidate.Tag || parsed.Name != asset.Name || asset.State != "uploaded" || asset.Size < 0 || asset.Size > maxArtifactSize {
			return Plan{}, fmt.Errorf("selected asset metadata is inconsistent")
		}
		if asset.Digest != "" && !assetDigestPattern.MatchString(asset.Digest) {
			return Plan{}, fmt.Errorf("selected asset digest is malformed")
		}
		seenSidecars := map[string]bool{}
		for _, sidecar := range asset.SidecarAssets {
			sidecarURL, sidecarErr := ParseGitHubReleaseAssetURLAt(sidecar.URL, host)
			if sidecarErr != nil || sidecarURL.Repository != parsed.Repository || sidecarURL.Tag != parsed.Tag || sidecarURL.Name != sidecar.Name || sidecar.Name != asset.Name+sidecar.Kind || seenSidecars[sidecar.Kind] || sidecar.State != "uploaded" || sidecar.Size < 0 || sidecar.Size > maxSidecarSize {
				return Plan{}, fmt.Errorf("selected sidecar metadata is inconsistent")
			}
			if sidecar.Kind != ".sha256" && sidecar.Kind != ".asc" && sidecar.Kind != ".sha256.asc" {
				return Plan{}, fmt.Errorf("unsupported selected sidecar kind %q", sidecar.Kind)
			}
			if sidecar.Digest != "" && !assetDigestPattern.MatchString(sidecar.Digest) {
				return Plan{}, fmt.Errorf("selected sidecar digest is malformed")
			}
			seenSidecars[sidecar.Kind] = true
		}
		if asset.Sidecars.SHA256 != seenSidecars[".sha256"] || asset.Sidecars.Signature != seenSidecars[".asc"] || asset.Sidecars.SHA256Signed != seenSidecars[".sha256.asc"] {
			return Plan{}, fmt.Errorf("selected sidecar presence is inconsistent")
		}
		hostApplicable := allArchitectures || asset.Architecture == "any" || asset.Architecture == hostArch
		if hostApplicable && asset.Sidecars.SHA256Signed && !asset.Sidecars.SHA256 {
			return Plan{}, fmt.Errorf("selected .sha256.asc is incomplete without .sha256")
		}
		if hostApplicable && asset.Digest == "" && !asset.Sidecars.SHA256 && !asset.Sidecars.Signature {
			return Plan{}, fmt.Errorf("selected asset has no authoritative digest, checksum, or signature")
		}
		if hostApplicable && (asset.Sidecars.Signature || asset.Sidecars.SHA256Signed) && len(meta.ValidPGPKeys) == 0 && len(request.Candidate.TrustedKeys) == 0 {
			return Plan{}, fmt.Errorf("selected signatures have no recipe-anchored validpgpkeys")
		}
	}
	if metadataFullVersion(meta) != request.AURVersion {
		return Plan{}, fmt.Errorf("reviewed recipe version %s does not match AUR baseline %s", metadataFullVersion(meta), request.AURVersion)
	}
	expectedCandidateVersion := request.Candidate.Version + "-1"
	if meta.Epoch != "" && meta.Epoch != "0" {
		expectedCandidateVersion = meta.Epoch + ":" + expectedCandidateVersion
	}
	if request.Candidate.FullVersion != expectedCandidateVersion {
		return Plan{}, fmt.Errorf("candidate version %s does not preserve recipe epoch and pkgrel reset", request.Candidate.FullVersion)
	}
	var mappings []Mapping
	seenAssets := map[string]bool{}
	mappedIndices := map[string]bool{}
	for sourceKey, sources := range meta.Sources {
		arch := strings.TrimPrefix(sourceKey, "source_")
		if sourceKey == "source" {
			arch = "any"
		}
		if !allArchitectures && arch != "any" && arch != hostArch {
			continue
		}
		checksumKey := "sha256sums" + strings.TrimPrefix(sourceKey, "source")
		checksums, ok := meta.Checksums[checksumKey]
		if !ok || len(checksums) != len(sources) {
			return Plan{}, fmt.Errorf("%s has no exact matching %s array", sourceKey, checksumKey)
		}
		for index, source := range sources {
			rawURL := sourceURL(source)
			host := request.Candidate.Host
			if host == "" {
				host = "github.com"
			}
			prospective := nextSources[sourceKey][index]
			parsed, assetErr := ParseGitHubReleaseAssetURLAt(rawURL, host)
			if assetErr == nil && parsed.Repository.String() == request.Candidate.Repository {
				if prospective == source && parsed.Tag == request.Candidate.Tag {
					return Plan{}, fmt.Errorf("recipe already references selected release tag %s", parsed.Tag)
				}
				prospectiveAsset, prospectiveErr := ParseGitHubReleaseAssetURLAt(sourceURL(prospective), host)
				if prospectiveErr != nil || prospectiveAsset.Repository.String() != request.Candidate.Repository || prospectiveAsset.Tag != request.Candidate.Tag {
					return Plan{}, fmt.Errorf("%s[%d] prospective pkgver/pkgrel source does not match selected release", sourceKey, index)
				}
				var matches []Asset
				for _, asset := range request.Candidate.Assets {
					if asset.Architecture == arch && asset.Name == prospectiveAsset.Name && asset.URL == sourceURL(prospective) {
						matches = append(matches, asset)
					}
				}
				if len(matches) != 1 {
					return Plan{}, fmt.Errorf("%s[%d] maps to %d selected assets", sourceKey, index, len(matches))
				}
				if seenAssets[arch+"\x00"+matches[0].Name] {
					return Plan{}, fmt.Errorf("selected asset %s maps more than once", matches[0].Name)
				}
				seenAssets[arch+"\x00"+matches[0].Name] = true
				mappings = append(mappings, Mapping{Kind: "asset", Architecture: arch, SourceKey: sourceKey, ChecksumKey: checksumKey, Index: index, Next: prospective, Asset: matches[0]})
				mappedIndices[sourceIndexKey(sourceKey, index)] = true
				continue
			}

			parsedGit, gitErr := ParseGitHubGitSourceURLAt(rawURL, host)
			if gitErr != nil || parsedGit.Repository.String() != request.Candidate.Repository {
				continue
			}
			prospectiveGit, err := ParseGitHubGitSourceURLAt(sourceURL(prospective), host)
			if err != nil || prospectiveGit.Repository != parsedGit.Repository || prospectiveGit.Tag != request.Candidate.Tag {
				return Plan{}, fmt.Errorf("%s[%d] prospective Git source does not match selected tag", sourceKey, index)
			}
			var references []GitReference
			for _, reference := range request.Candidate.GitReferences {
				if reference.SourceKey == sourceKey && reference.SourceIndex == index && reference.Architecture == arch && reference.Tag == prospectiveGit.Tag {
					references = append(references, reference)
				}
			}
			if len(references) != 1 {
				return Plan{}, fmt.Errorf("%s[%d] maps to %d selected Git references", sourceKey, index, len(references))
			}
			if references[0].SignatureRequired != prospectiveGit.Signed {
				return Plan{}, fmt.Errorf("%s[%d] Git signature requirement does not match the reviewed source", sourceKey, index)
			}
			if references[0].SourceName != "" {
				name, err := sourceDestination(prospective)
				if err != nil || name != references[0].SourceName {
					return Plan{}, fmt.Errorf("%s[%d] Git source destination does not match selected reference", sourceKey, index)
				}
			}
			if !strings.EqualFold(checksums[index], "SKIP") {
				return Plan{}, fmt.Errorf("%s[%d] Git source requires a SKIP SHA-256 entry", sourceKey, index)
			}
			keys := append([]string(nil), meta.ValidPGPKeys...)
			keys = appendUniqueFold(keys, request.Candidate.TrustedKeys...)
			if references[0].SignatureRequired && len(keys) == 0 {
				return Plan{}, fmt.Errorf("%s[%d] requests signed Git verification without an anchored fingerprint", sourceKey, index)
			}
			immutable, err := rewriteGitSourceToCommit(prospective, references[0].CommitSHA, host)
			if err != nil {
				return Plan{}, fmt.Errorf("%s[%d]: %w", sourceKey, index, err)
			}
			mappings = append(mappings, Mapping{Kind: "git", Architecture: arch, SourceKey: sourceKey, ChecksumKey: checksumKey, Index: index, Next: immutable, GitReference: references[0]})
			mappedIndices[sourceIndexKey(sourceKey, index)] = true
		}
		for index, source := range sources {
			if source == nextSources[sourceKey][index] {
				continue
			}
			if !mappedIndices[sourceIndexKey(sourceKey, index)] {
				return Plan{}, fmt.Errorf("%s[%d] is version-dependent but has no selected asset mapping", sourceKey, index)
			}
			for checksumKey, checksums := range meta.Checksums {
				if !checksumMatchesSource(checksumKey, sourceKey) || strings.HasPrefix(checksumKey, "sha256sums") {
					continue
				}
				if index >= len(checksums) || !strings.EqualFold(checksums[index], "SKIP") {
					return Plan{}, fmt.Errorf("%s[%d] changes but unsupported checksum family %s would remain stale", sourceKey, index, checksumKey)
				}
			}
		}
	}
	wanted := 0
	for _, asset := range request.Candidate.Assets {
		if allArchitectures || asset.Architecture == "any" || asset.Architecture == hostArch {
			wanted++
		}
	}
	for _, reference := range request.Candidate.GitReferences {
		if allArchitectures || reference.Architecture == "any" || reference.Architecture == hostArch {
			wanted++
		}
	}
	if len(mappings) == 0 || len(mappings) != wanted {
		return Plan{}, fmt.Errorf("host recipe maps %d of %d selected upstream sources", len(mappings), wanted)
	}
	sort.Slice(mappings, func(i, j int) bool {
		if mappings[i].SourceKey != mappings[j].SourceKey {
			return mappings[i].SourceKey < mappings[j].SourceKey
		}
		return mappings[i].Index < mappings[j].Index
	})
	return Plan{PackageBase: meta.PackageBase, FromVersion: meta.Version, ToVersion: request.Candidate.Version, Release: "1", Mappings: mappings}, nil
}

func sourceIndexKey(key string, index int) string {
	return fmt.Sprintf("%s\x00%d", key, index)
}

func appendUniqueFold(values []string, additions ...string) []string {
	for _, value := range additions {
		if !containsFold(values, value) {
			values = append(values, value)
		}
	}
	return values
}

func checksumMatchesSource(checksumKey, sourceKey string) bool {
	suffix := strings.TrimPrefix(sourceKey, "source")
	for _, family := range []string{"md5sums", "sha1sums", "sha224sums", "sha256sums", "sha384sums", "sha512sums", "b2sums"} {
		if checksumKey == family+suffix {
			return true
		}
	}
	return false
}

func metadataFullVersion(meta pkgbuild.Metadata) string {
	version := meta.Version
	if meta.Epoch != "" && meta.Epoch != "0" {
		version = meta.Epoch + ":" + version
	}
	return version + "-" + meta.Release
}

func sourceURL(source string) string {
	if _, rawURL, ok := strings.Cut(source, "::"); ok {
		return rawURL
	}
	return source
}

// ApplyBuildCopy revalidates the reviewed baseline, verifies the selected
// assets or Git refs, rewrites only buildDir, reruns audits, and asks for
// explicit approval of the exact recipe diff.
func ApplyBuildCopy(ctx context.Context, reviewDir, buildDir string, request ApplyRequest, options ApplyOptions) (Evidence, error) {
	if options.Revalidate == nil {
		return Evidence{}, fmt.Errorf("immediate upstream candidate revalidation is required")
	}
	fresh, err := options.Revalidate(ctx, request)
	if err != nil {
		return Evidence{}, fmt.Errorf("revalidate upstream candidate: %w", err)
	}
	if !reflect.DeepEqual(fresh, request.Candidate) {
		return Evidence{}, fmt.Errorf("upstream release or asset identity changed after planning")
	}
	reviewRecipe, err := readRegularFile(filepath.Join(reviewDir, "PKGBUILD"))
	if err != nil {
		return Evidence{}, err
	}
	reviewHash := sha256.Sum256(reviewRecipe)
	hostArch := options.HostArch
	if hostArch == "" {
		hostArch = HostArchitecture()
	}
	buildRecipePath := filepath.Join(buildDir, "PKGBUILD")
	buildRecipe, err := readRegularFile(buildRecipePath)
	if err != nil {
		return Evidence{}, err
	}
	if string(reviewRecipe) != string(buildRecipe) {
		return Evidence{}, fmt.Errorf("build copy differs from reviewed PKGBUILD before override")
	}
	plan, err := PlanOverrideForArchitectures(buildRecipe, request, options.HostArch, options.ValidateAllArches)
	if err != nil {
		return Evidence{}, err
	}
	meta, err := pkgbuild.Parse(buildRecipe)
	if err != nil {
		return Evidence{}, err
	}
	srcinfoPath := filepath.Join(buildDir, ".SRCINFO")
	srcinfo, err := readRegularFile(srcinfoPath)
	if err != nil {
		return Evidence{}, fmt.Errorf("read build-copy .SRCINFO: %w", err)
	}
	if err := pkgbuild.ValidateSRCINFO(srcinfo, meta); err != nil {
		return Evidence{}, err
	}
	type preparedMapping struct {
		Mapping
		LocalName string
	}
	prepared := make([]preparedMapping, 0, len(plan.Mappings))
	destinations := map[string]bool{"PKGBUILD": true, ".SRCINFO": true, "PKGBUILD.static": true, ".git": true}
	mappingIndices := make(map[string]bool, len(plan.Mappings))
	for _, mapping := range plan.Mappings {
		mappingIndices[sourceIndexKey(mapping.SourceKey, mapping.Index)] = true
	}
	for sourceKey, sources := range meta.Sources {
		if !options.ValidateAllArches && sourceKey != "source" && sourceKey != "source_"+hostArch {
			continue
		}
		for index, source := range sources {
			if mappingIndices[sourceIndexKey(sourceKey, index)] {
				continue
			}
			localName, err := sourceDestination(source)
			if err != nil {
				return Evidence{}, fmt.Errorf("%s[%d]: %w", sourceKey, index, err)
			}
			if destinations[localName] {
				return Evidence{}, fmt.Errorf("existing source destination %q is reserved or duplicated", localName)
			}
			destinations[localName] = true
		}
	}
	for _, mapping := range plan.Mappings {
		localName, err := sourceDestination(mapping.Next)
		if err != nil {
			return Evidence{}, fmt.Errorf("%s[%d]: %w", mapping.SourceKey, mapping.Index, err)
		}
		if destinations[localName] {
			return Evidence{}, fmt.Errorf("source destination %q is reserved or duplicated", localName)
		}
		destinations[localName] = true
		if _, err := os.Lstat(filepath.Join(buildDir, localName)); err == nil {
			return Evidence{}, fmt.Errorf("source destination %q already exists", localName)
		} else if !os.IsNotExist(err) {
			return Evidence{}, err
		}
		prepared = append(prepared, preparedMapping{Mapping: mapping, LocalName: localName})
	}
	override := pkgbuild.Override{Version: plan.ToVersion, Release: "1", Sources: map[string][]string{}, Checksums: map[string][]string{}}
	host := request.Candidate.Host
	if host == "" {
		host = "github.com"
	}
	apiOrigin := request.Candidate.APIOrigin
	if apiOrigin == "" {
		apiOrigin = defaultGitHubAPI
	}
	evidence := Evidence{PackageBase: request.PackageBase, AURVersion: request.AURVersion, Upstream: request.Candidate.FullVersion, Repository: request.Candidate.Repository, ProviderHostHash: hashString(host), APIOriginHash: hashString(apiOrigin), ReleaseID: request.Candidate.ReleaseID, Tag: request.Candidate.Tag, HostArchitecture: hostArch, BaselineRecipeSHA256: hex.EncodeToString(reviewHash[:]), AppliedAt: time.Now().UTC().Format(time.RFC3339)}
	trustedKeys := append([]string(nil), meta.ValidPGPKeys...)
	for _, key := range request.Candidate.TrustedKeys {
		if !containsFold(trustedKeys, key) {
			trustedKeys = append(trustedKeys, key)
		}
	}
	for _, item := range prepared {
		mapping, localName := item.Mapping, item.LocalName
		if mapping.Kind == "git" {
			verified := false
			signer := ""
			if mapping.GitReference.SignaturePresent && len(trustedKeys) > 0 {
				if options.Verifier == nil {
					return Evidence{}, fmt.Errorf("verify Git tag %s: no anchored signature verifier", mapping.GitReference.Tag)
				}
				result, err := options.Verifier.Verify(ctx, mapping.GitReference.Payload, mapping.GitReference.Signature, trustedKeys)
				if err != nil {
					return Evidence{}, fmt.Errorf("verify Git tag %s under anchored key: %w", mapping.GitReference.Tag, err)
				}
				if !result.Valid || result.Revoked || result.Expired || !containsFold(trustedKeys, result.Fingerprint) {
					return Evidence{}, fmt.Errorf("verify Git tag %s under anchored key: signature is not valid under a recipe-anchored key", mapping.GitReference.Tag)
				}
				verified, signer = true, strings.ToUpper(result.Fingerprint)
				evidence.Signers = appendUniqueFold(evidence.Signers, signer)
			}
			if mapping.GitReference.SignatureRequired && !verified {
				return Evidence{}, fmt.Errorf("Git tag %s requires anchored signature verification", mapping.GitReference.Tag)
			}
			values, ok := override.Sources[mapping.SourceKey]
			if !ok {
				values = append([]string(nil), meta.Sources[mapping.SourceKey]...)
			}
			values[mapping.Index] = mapping.Next
			override.Sources[mapping.SourceKey] = values
			evidence.Sources = append(evidence.Sources, hashString(request.Candidate.Repository+"\x00"+mapping.GitReference.CommitSHA))
			evidence.GitReferences = append(evidence.GitReferences, GitReferenceEvidence{Architecture: mapping.Architecture, SourceKey: mapping.SourceKey, SourceIndex: mapping.Index, TagHash: hashString(mapping.GitReference.Tag), RefSHA: mapping.GitReference.RefSHA, CommitSHA: mapping.GitReference.CommitSHA, ObjectType: mapping.GitReference.ObjectType, SignatureRequired: mapping.GitReference.SignatureRequired, SignatureVerified: verified, Signer: signer})
			continue
		}
		digest, signers, methods, sidecarEvidence, err := fetchAndVerifyCandidate(ctx, buildDir, localName, mapping.Asset, trustedKeys, request.Candidate, options)
		if err != nil {
			return Evidence{}, fmt.Errorf("verify %s: %w", mapping.Asset.Name, err)
		}
		values, ok := override.Sources[mapping.SourceKey]
		if !ok {
			values = append([]string(nil), meta.Sources[mapping.SourceKey]...)
		}
		values[mapping.Index] = mapping.Next
		override.Sources[mapping.SourceKey] = values
		checksums, ok := override.Checksums[mapping.ChecksumKey]
		if !ok {
			checksums = append([]string(nil), meta.Checksums[mapping.ChecksumKey]...)
		}
		checksums[mapping.Index] = digest
		override.Checksums[mapping.ChecksumKey] = checksums
		evidence.ArtifactHashes = append(evidence.ArtifactHashes, digest)
		evidence.Sources = append(evidence.Sources, hashString(mapping.Asset.URL))
		evidence.Signers = append(evidence.Signers, signers...)
		evidence.Artifacts = append(evidence.Artifacts, ArtifactEvidence{ID: mapping.Asset.ID, Name: mapping.Asset.Name, Architecture: mapping.Architecture, NameHash: hashString(mapping.Asset.Name), SHA256: digest, Methods: methods, Signers: append([]string(nil), signers...), Size: mapping.Asset.Size, URLHash: hashString(mapping.Asset.URL), APIDigest: mapping.Asset.Digest, Sidecars: sidecarEvidence})
	}
	rewritten, err := pkgbuild.Rewrite(buildRecipe, override)
	if err != nil {
		return Evidence{}, err
	}
	generatedHash := sha256.Sum256(rewritten)
	evidence.GeneratedRecipeSHA256 = hex.EncodeToString(generatedHash[:])
	rewrittenInfo, err := pkgbuild.RewriteSRCINFO(srcinfo, override)
	if err != nil {
		return Evidence{}, err
	}
	rewrittenMeta, err := pkgbuild.Parse(rewritten)
	if err != nil {
		return Evidence{}, err
	}
	if err := pkgbuild.ValidateSRCINFO(rewrittenInfo, rewrittenMeta); err != nil {
		return Evidence{}, fmt.Errorf("validate rewritten .SRCINFO: %w", err)
	}
	if err := writePrivateFile(buildRecipePath, rewritten); err != nil {
		return Evidence{}, err
	}
	if err := writePrivateFile(srcinfoPath, rewrittenInfo); err != nil {
		return Evidence{}, err
	}
	if options.Audit != nil {
		if err := options.Audit(buildDir); err != nil {
			return Evidence{}, fmt.Errorf("audit overridden build copy: %w", err)
		}
	}
	if options.Confirm == nil {
		return Evidence{}, fmt.Errorf("explicit upstream override confirmation is required")
	}
	diff := exactDiff(buildRecipe, rewritten)
	approved, err := options.Confirm(diff, evidence)
	if err != nil {
		return Evidence{}, err
	}
	if !approved {
		return Evidence{}, fmt.Errorf("upstream override was not approved")
	}
	after, err := readRegularFile(filepath.Join(reviewDir, "PKGBUILD"))
	if err != nil || sha256.Sum256(after) != reviewHash {
		return Evidence{}, fmt.Errorf("persistent review PKGBUILD changed during upstream override")
	}
	if options.EvidenceDir != "" {
		if err := persistEvidence(options.EvidenceDir, evidence); err != nil {
			return Evidence{}, err
		}
	}
	return evidence, nil
}

func fetchAndVerify(ctx context.Context, buildDir, localName string, asset Asset, keys []string, options ApplyOptions) (string, []string, []string, []SidecarEvidence, error) {
	return fetchAndVerifyCandidate(ctx, buildDir, localName, asset, keys, Candidate{Host: "github.com"}, options)
}

func fetchAndVerifyCandidate(ctx context.Context, buildDir, localName string, asset Asset, keys []string, candidate Candidate, options ApplyOptions) (string, []string, []string, []SidecarEvidence, error) {
	if asset.State != "uploaded" || asset.Size < 0 || asset.Size > maxArtifactSize {
		return "", nil, nil, nil, fmt.Errorf("asset metadata is not an uploaded bounded artifact")
	}
	path := filepath.Join(buildDir, localName)
	digest, _, err := downloadArtifactForCandidate(ctx, options.HTTP, asset.URL, path, asset.Size, maxArtifactSize, candidate)
	if err != nil {
		return "", nil, nil, nil, err
	}
	var claimed []string
	var methods []string
	var sidecarEvidence []SidecarEvidence
	if asset.Digest != "" {
		claimed = append(claimed, strings.TrimPrefix(strings.ToLower(asset.Digest), "sha256:"))
		methods = append(methods, "github-api-digest")
	}
	sidecars := map[string][]byte{}
	for _, sidecar := range asset.SidecarAssets {
		if sidecar.State != "uploaded" || sidecar.Size < 0 || sidecar.Size > maxSidecarSize {
			return "", nil, nil, nil, fmt.Errorf("sidecar %s is not bounded and uploaded", sidecar.Name)
		}
		sidecarDigest, body, err := downloadArtifactForCandidate(ctx, options.HTTP, sidecar.URL, "", sidecar.Size, maxSidecarSize, candidate)
		if err != nil {
			return "", nil, nil, nil, err
		}
		if sidecar.Digest != "" && strings.TrimPrefix(strings.ToLower(sidecar.Digest), "sha256:") != sidecarDigest {
			return "", nil, nil, nil, fmt.Errorf("sidecar API digest conflicts with downloaded SHA-256")
		}
		sidecarEvidence = append(sidecarEvidence, SidecarEvidence{ID: sidecar.ID, Kind: sidecar.Kind, Size: sidecar.Size, URLHash: hashString(sidecar.URL), APIDigest: sidecar.Digest, LocalSHA256: sidecarDigest, Status: "downloaded and API digest checked"})
		sidecars[sidecar.Kind] = body
	}
	if asset.Sidecars.SHA256 != (sidecars[".sha256"] != nil) || asset.Sidecars.Signature != (sidecars[".asc"] != nil) || asset.Sidecars.SHA256Signed != (sidecars[".sha256.asc"] != nil) {
		return "", nil, nil, nil, fmt.Errorf("sidecar evidence is inconsistent with release metadata")
	}
	if _, signedOnly := sidecars[".sha256.asc"]; signedOnly && sidecars[".sha256"] == nil {
		return "", nil, nil, nil, fmt.Errorf(".sha256.asc is incomplete without .sha256")
	}
	if checksum := sidecars[".sha256"]; checksum != nil {
		value, err := parseExactSHA256(checksum, asset.Name)
		if err != nil {
			return "", nil, nil, nil, err
		}
		claimed = append(claimed, value)
		methods = append(methods, "sha256-sidecar")
		setSidecarStatus(sidecarEvidence, ".sha256", "exact checksum parsed and matched")
	}
	var signers []string
	acceptSignature := func(result SignatureResult, err error) error {
		if err != nil {
			return err
		}
		if !result.Valid || result.Revoked || result.Expired || !containsFold(keys, result.Fingerprint) {
			return fmt.Errorf("signature is not valid under a recipe-anchored key")
		}
		fingerprint := strings.ToUpper(result.Fingerprint)
		if !containsFold(signers, fingerprint) {
			signers = append(signers, fingerprint)
		}
		return nil
	}
	verify := func(payload, signature []byte) error {
		if len(keys) == 0 || options.Verifier == nil {
			return fmt.Errorf("signature published but recipe has no usable anchored verifier")
		}
		return acceptSignature(options.Verifier.Verify(ctx, payload, signature, keys))
	}
	if signature := sidecars[".asc"]; signature != nil {
		var verifyErr error
		if fileVerifier, ok := options.Verifier.(FileSignatureVerifier); ok {
			verifyErr = acceptSignature(fileVerifier.VerifyFile(ctx, path, signature, keys))
		} else {
			artifact, err := readRegularFile(path)
			if err != nil {
				return "", nil, nil, nil, err
			}
			verifyErr = verify(artifact, signature)
		}
		if verifyErr != nil {
			return "", nil, nil, nil, verifyErr
		}
		methods = append(methods, "artifact-signature")
		setSidecarStatus(sidecarEvidence, ".asc", "recipe-anchored signature valid")
	}
	if signature := sidecars[".sha256.asc"]; signature != nil {
		if err := verify(sidecars[".sha256"], signature); err != nil {
			return "", nil, nil, nil, err
		}
		methods = append(methods, "checksum-signature")
		setSidecarStatus(sidecarEvidence, ".sha256.asc", "recipe-anchored checksum signature valid")
	}
	if len(claimed) == 0 && len(signers) == 0 {
		return "", nil, nil, nil, fmt.Errorf("release provides no authoritative digest or anchored signature")
	}
	for _, claim := range claimed {
		if claim != digest {
			return "", nil, nil, nil, fmt.Errorf("published checksum conflicts with downloaded SHA-256")
		}
	}
	return digest, signers, methods, sidecarEvidence, nil
}

func sourceDestination(source string) (string, error) {
	name := source
	if alias, _, ok := strings.Cut(source, "::"); ok {
		name = alias
	} else if parsed, err := url.Parse(source); err == nil && parsed.Scheme != "" {
		name = filepath.Base(parsed.Path)
		if parsed.Scheme == "git+https" {
			name = strings.TrimSuffix(name, ".git")
		}
	}
	if name != filepath.Base(name) || name == "" || name == "." || name == ".." || strings.ContainsAny(name, "\x00\r\n") {
		return "", fmt.Errorf("source destination %q is unsafe", name)
	}
	return name, nil
}

func setSidecarStatus(evidence []SidecarEvidence, kind, status string) {
	for i := range evidence {
		if evidence[i].Kind == kind {
			evidence[i].Status = status
		}
	}
}

func downloadArtifact(ctx context.Context, client *http.Client, rawURL, destination string, expected, limit int64) (string, []byte, error) {
	return downloadArtifactForCandidate(ctx, client, rawURL, destination, expected, limit, Candidate{Host: "github.com"})
}

func downloadArtifactForCandidate(ctx context.Context, client *http.Client, rawURL, destination string, expected, limit int64, candidate Candidate) (string, []byte, error) {
	host := candidate.Host
	if host == "" {
		host = "github.com"
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || !validCandidateDownloadURLMode(parsed, host, nil, candidate.Configured) {
		return "", nil, fmt.Errorf("download URL is not canonical GitHub HTTPS")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	requestClient := *client
	requestClient.Jar = nil
	requestClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !validCandidateDownloadURLMode(req.URL, host, candidate.AssetHosts, candidate.Configured) {
			return fmt.Errorf("release asset redirect refused")
		}
		req.Header.Del("Authorization")
		req.Header.Del("Cookie")
		req.Header.Del("Proxy-Authorization")
		return nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	resp, err := requestClient.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request == nil || !validCandidateDownloadURLMode(resp.Request.URL, host, candidate.AssetHosts, candidate.Configured) {
		return "", nil, fmt.Errorf("release asset HTTP %d or invalid final host", resp.StatusCode)
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return "", nil, fmt.Errorf("release asset content encoding %q is unsupported", encoding)
	}
	if resp.ContentLength > limit || expected < 0 || expected > limit || resp.ContentLength >= 0 && resp.ContentLength != expected {
		return "", nil, fmt.Errorf("release asset size does not match bounded metadata")
	}
	hash := sha256.New()
	var writer io.Writer
	var file *os.File
	var buffer strings.Builder
	if destination != "" {
		file, err = openCreateNoFollow(destination, 0o600)
		if err != nil {
			return "", nil, err
		}
		defer file.Close()
		writer = file
	} else {
		writer = &buffer
	}
	n, err := io.Copy(io.MultiWriter(writer, hash), io.LimitReader(resp.Body, limit+1))
	if err != nil || n > limit || n != expected {
		return "", nil, fmt.Errorf("release asset body has unexpected size")
	}
	if file != nil {
		if err := file.Close(); err != nil {
			return "", nil, err
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), []byte(buffer.String()), nil
}

func validCandidateDownloadURL(value *url.URL, initialHost string, redirects []string) bool {
	return validCandidateDownloadURLMode(value, initialHost, redirects, false)
}

func validCandidateDownloadURLMode(value *url.URL, initialHost string, redirects []string, configured bool) bool {
	if value == nil || value.Scheme != "https" || value.User != nil {
		return false
	}
	if value.Host == initialHost {
		return true
	}
	if !configured && initialHost == "github.com" && value.Port() == "" && strings.HasSuffix(value.Hostname(), ".githubusercontent.com") {
		return true
	}
	for _, allowed := range redirects {
		if value.Host == allowed {
			return true
		}
	}
	return false
}

func allowedDownloadHost(host string) bool {
	return host == "github.com" || strings.HasSuffix(host, ".githubusercontent.com")
}

func validDownloadURL(value *url.URL) bool {
	return value != nil && value.Scheme == "https" && value.User == nil && value.Port() == "" && allowedDownloadHost(value.Hostname())
}

func parseExactSHA256(data []byte, filename string) (string, error) {
	if filename != filepath.Base(filename) || strings.ContainsAny(filename, "\r\n\x00") {
		return "", fmt.Errorf("checksum filename is unsafe")
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	var result string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if (len(fields) != 1 && len(fields) != 2) || result != "" || len(fields[0]) != 64 {
			return "", fmt.Errorf("checksum sidecar must contain exactly one SHA-256 for %s", filename)
		}
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") != filename {
			return "", fmt.Errorf("checksum sidecar must contain exactly one SHA-256 for %s", filename)
		}
		if _, err := hex.DecodeString(fields[0]); err != nil {
			return "", fmt.Errorf("checksum sidecar contains invalid SHA-256")
		}
		result = strings.ToLower(fields[0])
	}
	if result == "" || scanner.Err() != nil {
		return "", fmt.Errorf("checksum sidecar contains no exact checksum")
	}
	return result, nil
}

func containsFold(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}

func exactDiff(before, after []byte) string {
	return "--- reviewed/PKGBUILD\n+++ build/PKGBUILD\n@@ exact replacement @@\n-" + strings.ReplaceAll(string(before), "\n", "\n-") + "\n+" + strings.ReplaceAll(string(after), "\n", "\n+")
}

func hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func writePrivateFile(path string, data []byte) error {
	file, err := openWriteNoFollow(path, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func persistEvidence(dir string, evidence Evidence) error {
	if err := rejectSymlinkComponents(filepath.Dir(dir)); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("evidence directory is not a private regular directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	if err := validateOpenedDirectory(dir, true, "evidence directory"); err != nil {
		return err
	}
	if err := validateEvidence(evidence); err != nil {
		return fmt.Errorf("refusing invalid upstream evidence: %w", err)
	}
	path := filepath.Join(dir, hashString(evidence.PackageBase)+".json")
	lock, err := acquireEvidenceLock(dir, evidence.PackageBase)
	if err != nil {
		return err
	}
	defer releaseEvidenceLock(lock)
	if err := validateOpenedDirectory(dir, true, "evidence directory"); err != nil {
		return err
	}
	entries, err := readEvidenceEntries(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if _, err := readEvidenceRecord(filepath.Join(dir, entry.Name())); err != nil {
			return fmt.Errorf("existing upstream evidence is invalid: %w", err)
		}
	}
	stored := evidenceRecord{}
	if _, err := os.Lstat(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if data, err := readEvidenceRecord(path); err == nil {
		if err := decodeStrict(data, &stored); err != nil {
			return fmt.Errorf("existing upstream evidence is invalid: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("existing upstream evidence is invalid: %w", err)
	}
	stored.History = append(stored.History, evidence)
	if len(stored.History) > 32 {
		stored.History = append([]Evidence(nil), stored.History[len(stored.History)-32:]...)
	}
	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return fmt.Errorf("upstream evidence exceeds 1048576 bytes")
	}
	tmp, err := os.CreateTemp(dir, ".evidence-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func rejectSymlinkComponents(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(abs, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("evidence path contains symlink %s", current)
		}
	}
	return nil
}

func readRegularFile(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("open %s returned no file", path)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return io.ReadAll(file)
}

func openWriteNoFollow(path string, mode os.FileMode) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode.Perm()))
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("open %s returned no file", path)
	}
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func openCreateNoFollow(path string, mode os.FileMode) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode.Perm()))
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("open %s returned no file", path)
	}
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}
