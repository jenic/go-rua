# Upstream Package

`internal/upstream` implements conservative discovery and application of
GitHub releases that are newer than an AUR recipe. It exists for cases where
the AUR package is stale but the recipe already identifies a GitHub project and
can be updated by changing a small, statically provable set of fields.

The package is intentionally narrower than a general `PKGBUILD` evaluator. It
does not execute shell code during discovery or rewriting, does not modify the
persistent review checkout, and does not make upstream overrides automatic.
Unsupported or ambiguous recipes remain report-only.

## User-visible workflows

The CLI exposes the package through two commands:

- `go-rua upgrade --plan` performs best-effort upstream reporting while
  retaining the normal AUR upgrade plan.
- `go-rua upgrade --plan --upstream` additionally proves that an override can
  be mapped to the reviewed recipe. It does not download release artifacts,
  modify a recipe, build, stage, or install packages.
- `go-rua upgrade --upstream` explicitly opts into verified upstream
  candidates. The candidate is revalidated, the ephemeral build copy is
  rewritten, and the exact diff requires approval before the normal audit,
  build, tarcheck, staging, and `pacman -U` workflow continues.
- `go-rua upgrade --upstream --validate-all-arches` requires complete source
  mappings and verification evidence for every declared architecture. The
  default validates only generic and host-architecture sources.
- `go-rua upgrade --no-upstream-check` disables best-effort upstream reporting.
- `go-rua upstream [packages...]` reports upstream status without changing
  recipes or downloading source content. `--json` emits structured reports;
  `--export-evidence` and `--gc-evidence` manage local verification evidence.

Bare `go-rua upgrade` remains AUR-only even though planning can report that the
AUR recipe lags GitHub. Applying an upstream candidate always requires
`--upstream`.

## Package layout

The implementation is divided by responsibility:

- `model.go` defines provider-neutral recipes, candidates, reports, assets,
  Git references, and the `Provider` interface.
- `metadata.go` parses the bounded AUR `.SRCINFO` snapshot into the neutral
  recipe model.
- `check.go` fetches `.SRCINFO`, proves that its package base and full version
  still match AUR RPC metadata, invokes a provider, and compares the candidate
  with both AUR and installed versions.
- `github.go` validates release URLs, queries release metadata, reconciles the
  ETag cache, detects release mutation, infers or applies templates, and
  selects a candidate.
- `github_tags.go` lists Git tags, resolves exact tag references, peels one
  annotated tag, records signature material, and detects tag movement.
- `git_source.go` parses the supported makepkg Git source syntax and rewrites a
  selected tag to an immutable commit source.
- `policy.go` loads and validates private schema-versioned host and package
  policy.
- `apply.go` proves source-to-candidate mappings, downloads and verifies
  release assets, rewrites only the build copy, reruns audits, requests
  approval, and records evidence.
- `gpg.go` verifies detached signatures with an isolated keyring populated
  only by externally anchored fingerprints.
- `evidence.go` validates, serializes, exports, and garbage-collects bounded
  evidence records.

Structured `PKGBUILD` parsing and rewriting live in `internal/pkgbuild`. This
package consumes that parser rather than interpreting Bash itself.

## Discovery and selection

Discovery follows this sequence:

1. Read AUR RPC metadata and a bounded `.SRCINFO` from the canonical cgit
   endpoint.
2. Require the snapshot package base and full version to match the RPC result.
   This prevents a mixed-version decision if AUR changes during planning.
3. Infer exactly one GitHub repository and conservative tag and asset
   templates, or use an exact per-package policy.
4. Query the bounded recent release or tag list and validate all required
   architectures, asset names, upload states, and sidecar identities.
5. Prove inferred templates against the recipe's current tag before using them
   to select a newer candidate.
6. Compare full Arch versions with `vercmp`, preserving `epoch` and treating
   the generated override as `pkgrel=1`.

The release query considers at most the recent 20 releases. Draft releases are
ignored. Stable policy ignores API-marked prereleases; prerelease policy
selects only API-marked prereleases. Asset names must identify the expected
product, channel, and architecture exactly.

If the current recipe tag has fallen off the recent page, the provider may
query GitHub's exact release-by-tag endpoint only to prove that baseline. The
exact-tag response cannot introduce an otherwise hidden newer candidate.
Its separate ETag cache is seeded from retained recent-page history so the
fallback cannot reset previously observed release or asset identity.

Ordinary planning treats provider and attributable package-policy failures as
an `unknown` upstream status so unrelated AUR upgrades can continue. Explicit
upstream application treats policy and verification failures as fatal.

## Supported sources

Release assets must use canonical, literal URLs of the form:

```text
https://github.com/OWNER/REPOSITORY/releases/download/TAG/ASSET
```

Configured GitHub Enterprise hosts use the same path structure on the exact
web host named by policy. makepkg aliases such as `local-name::URL` are
preserved.

Git sources support only exact tag-pinned HTTPS forms:

```text
git+https://github.com/OWNER/REPOSITORY.git#tag=TAG
git+https://github.com/OWNER/REPOSITORY#tag=TAG
git+https://github.com/OWNER/REPOSITORY.git?signed#tag=TAG
git+https://github.com/OWNER/REPOSITORY.git#tag=TAG?signed
```

The tag must be derived from the recipe version and must be a conservative Git
ref name. Branches, pre-pinned commits, unqualified repositories, encoded or
userinfo-bearing URLs, noncanonical hosts, ambiguous fragments, and Git
sources without an exact tag are rejected.

For an eligible Git source, the commit in the bounded tag list must agree with
the exact Git ref resolution. One annotated tag object may be peeled to its
commit. The build-copy source is then rewritten to
`#commit=<immutable-object-id>` and its SHA-256 entry remains `SKIP`; makepkg's
normal prefetch retrieves the Git content later. A `?signed` source requires
an annotated tag signature that verifies under an anchored fingerprint.

Version-dependent remote sources outside the one selected repository are
rejected. Version-independent local or remote sources may remain in the recipe
when their source and checksum metadata stay exact.

## Recipe eligibility and rewriting

`internal/pkgbuild` uses tree-sitter-bash to locate top-level assignments. The
eligible subset is deliberately small:

- One literal top-level `pkgver` and one literal top-level `pkgrel`.
- An optional literal top-level `epoch`.
- Literal or primitively expanded `source` and `source_<arch>` arrays.
- Literal checksum arrays whose indexes correspond exactly to source indexes.
- Expansion of `pkgbase`, `pkgname`, `pkgver`, `pkgrel`, and `epoch` using
  `$name` or `${name}`.
- The fixed `${pkgname%-bin}` suffix-removal operation used by
  `brave-origin-bin`.

The parser rejects duplicate or conditional assignments, command
substitutions, generated or appended arrays, unsupported parameter expansion,
comments inside relevant arrays, unquoted glob/brace/tilde behavior, and any
case where source and checksum indexes cannot be proved.

An override must establish a one-to-one relationship between every changing
applicable source and exactly one selected release asset or Git reference.
Changed release assets require a corresponding SHA-256 array. Other checksum
families at a changed index must already contain `SKIP`; they are not silently
left stale. Git sources require `SKIP` in the SHA-256 array because commit
identity pins their content.

Before any download, the build-copy `.SRCINFO` must exactly match the reviewed
`PKGBUILD` metadata: package identity, version, architectures, source and
checksum keys and values, and `validpgpkeys`. The new source arrays are
resolved with the candidate `pkgver` and `pkgrel=1`, regenerated as quoted
literals, parsed again, and used to produce consistent static `.SRCINFO`.

Host-only mode rejects version-dependent non-host source metadata. With
`--validate-all-arches`, every changing generic and architecture-specific
source must have a complete candidate mapping and verification chain before
any recipe mutation.

## Application sequence

`ApplyBuildCopy` enforces the trust transition in this order:

1. Revalidate the complete selected candidate and reject any release, asset,
   tag, ref, commit, or policy drift.
2. Hash the reviewed `PKGBUILD` and require the build copy to be byte-for-byte
   identical before the override.
3. Build the exact mapping plan and validate `.SRCINFO` against the reviewed
   recipe.
4. Validate all source destination names and reject reserved, duplicate,
   colliding, or pre-existing destinations.
5. Download applicable release assets and sidecars with bounded redirects,
   declared-size checks, and streaming hashes. Git content is not cloned here.
6. Require all supported integrity and signature evidence to agree.
7. Rewrite only the copied `PKGBUILD` and its static `.SRCINFO`, then reparse
   and validate both.
8. Rerun the configured source and shell audits.
9. Present the exact diff and verification evidence for explicit approval.
10. Confirm that the persistent review recipe is still unchanged and publish
    the evidence record atomically.

The caller also re-reads the installed package version immediately before
application. A stale local version or stale upstream candidate aborts rather
than applying a plan made against changed state.

## Checksums and signatures

For each selected release asset, the provider recognizes only exact,
case-sensitive sidecar names:

| Sidecar | Meaning |
| --- | --- |
| `<asset>.sha256` | Strict SHA-256 checksum record for the exact asset name. |
| `<asset>.asc` | Detached OpenPGP signature over the asset bytes. |
| `<asset>.sha256.asc` | Detached OpenPGP signature over `<asset>.sha256`. |

Checksum parsing accepts an exact 64-hex SHA-256 value with an optional
conventional filename field. If a filename is present, it must identify the
selected asset exactly. A `.sha256.asc` without the matching `.sha256` is an
incomplete chain and cannot authenticate the asset.

Verification accumulates all supported evidence rather than accepting the
first successful method. Evidence includes:

1. An anchored signature over the checksum sidecar plus a matching artifact
   hash.
2. An anchored signature directly over the artifact.
3. An upstream checksum matching the artifact.
4. A GitHub API `sha256:` asset digest matching the artifact.
5. The locally calculated streaming SHA-256 value.

Any disagreement among an API digest, checksum sidecar, signature result,
recipe metadata, or calculated hash is fatal and is not bypassed by normal
interactive approval. API digests and unsigned checksums provide integrity or
same-origin consistency, not independent publisher authentication.

OpenPGP verification uses an isolated temporary keyring. Accepted full
fingerprints come only from the reviewed recipe's `validpgpkeys` or private
per-package policy, and the keys must already exist in the user's keyring.
Keys or fingerprints published by the release being verified never become
trust anchors. Revoked, expired, unanchored, malformed, or cryptographically
invalid signatures fail verification.

## Policy

Optional policy is loaded from:

```text
$XDG_CONFIG_HOME/rua/github_upstream.json
```

or `~/.config/rua/github_upstream.json` when `XDG_CONFIG_HOME` is unset. The
schema is strict and currently requires version 1:

```json
{
  "version": 1,
  "hosts": [
    {
      "host": "github.com",
      "api_base": "https://api.github.com",
      "asset_redirect_hosts": ["objects.githubusercontent.com"],
      "token_env": "RUA_GITHUB_TOKEN"
    }
  ],
  "packages": [
    {
      "package": "brave-bin",
      "host": "github.com",
      "repository": "brave/brave-browser",
      "channel": "stable",
      "tag_template": "v{version}",
      "asset_templates": {
        "x86_64": "brave-browser-{version}-linux-amd64.zip"
      },
      "trusted_fingerprints": [
        "0123456789ABCDEF0123456789ABCDEF01234567"
      ]
    }
  ]
}
```

Host entries define an exact web host, HTTPS API origin, release-asset redirect
allowlist, and optional API-token environment variable. Nondefault ports are
accepted only when the matching host entry sets
`"allow_nondefault_port": true`. Tokens are read from the named environment
variable, never stored in policy, and sent only to the exact API origin.

Package entries bind one AUR package base to an exact host and `owner/name`
repository. `channel` is `stable` or `prerelease`. Tag and asset templates
contain exactly one literal `{version}` token. Asset templates are literal
filenames keyed by architecture, not globs or regular expressions; the map may
be empty for a Git-only recipe. Trusted fingerprints are external anchors for
the isolated OpenPGP verifier.

The policy file is bounded to 1 MiB, opened without following its final path
component, and must be a private regular file owned by the effective user. Its
directory must also be private, owned by the effective user, and free of
symlink path components. Unknown fields, trailing JSON, unsupported versions,
duplicate identities, unsafe origins, and malformed templates are rejected.
An entry whose package identity cannot be attributed invalidates the complete
policy so it cannot silently fall back to discovery. Errors attributable to a
specific package remain scoped diagnostics during status checks.

Without package policy, conservative discovery is available for canonical
`github.com` recipes and uses `RUA_GITHUB_TOKEN` only for the GitHub API.

## Metadata cache and mutation detection

GitHub API metadata is cached below:

```text
$XDG_CACHE_HOME/rua/upstream/github
```

or `~/.cache/rua/upstream/github` when `XDG_CACHE_HOME` is unset. Cache keys
include web-host, API-origin, endpoint, and repository identity. Conditional
requests use ETags, response bodies are bounded, and API redirects are refused.

Release identity is monotonic. For a previously observed release, removing an
asset or changing an existing release ID, asset ID, upload state, size,
download URL, or digest is a hard failure. A strict asset-set superset is
accepted only while the complete previous response is available and every old
asset is exactly unchanged. Once only a historical whole-release fingerprint
remains, any changed fingerprint is rejected because an append-only change can
no longer be proved.

A bounded, recency-ordered history retains tag and release/asset fingerprints
after releases leave an API page. Git tag/ref/commit identity receives the
same movement checks. Each endpoint update uses a persistent private no-follow
lock. Network I/O happens before locking; the writer then locks, re-reads the
cache, reruns reconciliation against the latest local state, and holds the lock
through atomic publication. This prevents concurrent clients from accepting
conflicting responses against the same stale cache.

## Verification evidence

Successful applications store typed evidence below:

```text
$XDG_DATA_HOME/rua/upstream_evidence
```

or `~/.local/share/rua/upstream_evidence` when `XDG_DATA_HOME` is unset.
Records include package and upstream versions, repository and release identity,
recipe hashes, artifact hashes and methods, sidecar status, signer
fingerprints, Git ref and commit identity, architecture, and application time.
Host, API-origin, URLs, asset names, and tags are hashed where disclosure is
not required. Tokens and raw credentials are never persisted.

Evidence writes validate existing records, retain bounded per-package history,
and serialize validation, append, and atomic publication under a persistent
owned private lock. Directories, records, and locks must be owned by the
effective user, private, regular where applicable, singly linked where
required, and accessed without following unsafe symlink paths.

`ExportEvidence` strictly decodes and validates at most 256 records and 32 MiB,
re-encodes only typed fields, and publishes a new private destination using
atomic no-replace semantics. `GCEvidence` retains valid history and removes
only owned private abandoned `.evidence-*` regular temporary files older than
24 hours.

## Security boundaries

An upstream override removes the AUR maintainer's version and checksum update
as an independent review point. It therefore relies more heavily on the
upstream account, release automation, and externally anchored signing keys.
The following invariants are mandatory:

- Treat all GitHub metadata and downloaded content as untrusted network input.
- Require canonical ASCII HTTPS hosts; reject userinfo, confusing encodings,
  implicit hosts, and unapproved ports.
- Refuse API redirects. Restrict asset redirects to the selected release host
  or explicit policy allowlist, remove credentials on every hop, and bound hop
  counts.
- Bound recipe, API, sidecar, cache, evidence, and artifact sizes. Stream large
  artifact hashes and verify declared sizes.
- Never use a network response as a filesystem path.
- Never execute `PKGBUILD` shell code for discovery or rewriting.
- Treat checksum generation as integrity evidence, not authentication.
- Require signature trust anchors from outside the release.
- Fail closed on incomplete, failed, or conflicting authoritative evidence.
- Revalidate candidate and local state immediately before application.
- Keep the persistent review checkout unchanged, rerun audits on the generated
  copy, and require approval of the exact diff before building.

See the repository [threat model](../../THREAT_MODEL.md) for the broader build,
sandbox, staging, and privileged installation boundaries.

## Unsupported cases

The following remain intentionally unsupported:

- Dynamic `PKGBUILD` recipes outside the parser's static subset.
- Generic checksum manifests such as `SHA256SUMS` and `SHA256SUMS.asc`.
- GitHub-generated source archives without an established release-asset or
  tag-pinned Git source mapping.
- Multiple independent upstream repositories in one recipe.
- Authoritative checksum algorithms other than SHA-256.
- Sigstore, provenance attestations, and GitHub release attestations.
- Automatic upstream opt-in or per-package upstream-by-default application.

Adding support for any of these requires preserving exact source-index
mapping, external trust anchoring, bounded I/O, mutation detection, ephemeral
rewrites, and review-before-build behavior.

## Development and tests

Tests are colocated with the implementation and use deterministic HTTP
transports and temporary files. Coverage includes URL grammar, release and tag
selection, exact-tag fallback, mutation detection, cache races, policy
validation, architecture completeness, parser rejection, source mapping,
redirect controls, checksum/signature conflicts, GPG status handling,
build-copy-only mutation, evidence locking/export/GC, and CLI integration.

Use the repository targets so formatting, vetting, tests, and the final binary
follow the same workflow:

```sh
GOCACHE="$PWD/.gocache" GOMODCACHE="$PWD/.gomodcache" go mod verify
GOCACHE="$PWD/.gocache" GOMODCACHE="$PWD/.gomodcache" make check
```
