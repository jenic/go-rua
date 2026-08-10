// Package upstream provides provider-neutral discovery models for comparing
// distribution recipes with upstream releases.
package upstream

import "context"

type Source struct {
	Architecture string
	Key          string
	Index        int
	Name         string
	Alias        string
	URL          string
}

type Recipe struct {
	PackageBase   string
	Version       string
	Release       string
	Epoch         string
	Architectures []string
	Sources       []Source
	Checksums     map[string][]string
	ValidPGPKeys  []string
}

func (r Recipe) FullVersion() string {
	version := r.Version
	if r.Epoch != "" && r.Epoch != "0" {
		version = r.Epoch + ":" + version
	}
	if r.Release != "" {
		version += "-" + r.Release
	}
	return version
}

type Sidecars struct {
	SHA256       bool `json:"sha256"`
	Signature    bool `json:"signature"`
	SHA256Signed bool `json:"sha256_signed"`
}

type SidecarAsset struct {
	ID     int64  `json:"id"`
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Digest string `json:"digest,omitempty"`
	State  string `json:"state"`
	Size   int64  `json:"size"`
}

type Asset struct {
	ID            int64          `json:"id"`
	Architecture  string         `json:"architecture"`
	Name          string         `json:"name"`
	URL           string         `json:"url"`
	Digest        string         `json:"digest,omitempty"`
	State         string         `json:"state"`
	Size          int64          `json:"size"`
	Sidecars      Sidecars       `json:"sidecars"`
	SidecarAssets []SidecarAsset `json:"sidecar_assets,omitempty"`
}

type GitReference struct {
	Architecture      string `json:"architecture"`
	SourceKey         string `json:"source_key"`
	SourceIndex       int    `json:"source_index"`
	SourceName        string `json:"source_name"`
	Tag               string `json:"tag"`
	RefSHA            string `json:"ref_sha"`
	CommitSHA         string `json:"commit_sha"`
	ObjectType        string `json:"object_type"`
	SignatureRequired bool   `json:"signature_required"`
	SignaturePresent  bool   `json:"signature_present"`
	Signature         []byte `json:"-"`
	Payload           []byte `json:"-"`
}

type Candidate struct {
	Provider       string         `json:"provider"`
	Host           string         `json:"host"`
	APIOrigin      string         `json:"api_origin"`
	AssetHosts     []string       `json:"asset_hosts,omitempty"`
	Repository     string         `json:"repository"`
	ReleaseID      int64          `json:"release_id"`
	Tag            string         `json:"tag"`
	Version        string         `json:"version"`
	FullVersion    string         `json:"full_version"`
	Confidence     string         `json:"confidence"`
	Reasons        []string       `json:"reasons"`
	Assets         []Asset        `json:"assets"`
	GitReferences  []GitReference `json:"git_references,omitempty"`
	TrustedKeys    []string       `json:"trusted_fingerprints,omitempty"`
	Configured     bool           `json:"configured"`
	PolicyReason   string         `json:"policy_reason,omitempty"`
	NewerThanAUR   bool           `json:"newer_than_aur"`
	NewerThanLocal bool           `json:"newer_than_local"`
}

type Report struct {
	Package       string     `json:"package"`
	LocalVersion  string     `json:"local_version"`
	AURVersion    string     `json:"aur_version"`
	Source        string     `json:"source,omitempty"`
	Candidate     *Candidate `json:"candidate,omitempty"`
	LocalCompare  int        `json:"local_compare"`
	UnknownReason string     `json:"unknown_reason,omitempty"`
	PolicyReason  string     `json:"policy_reason,omitempty"`
}

type Request struct {
	Name         string
	PackageBase  string
	LocalVersion string
	AURVersion   string
}

type VersionComparator func(a, b string) (int, error)

type Provider interface {
	Detect(context.Context, Recipe, string, VersionComparator) (Candidate, bool, error)
}
