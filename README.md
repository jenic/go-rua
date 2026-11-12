# go-rua

A lightweight reimplementation of RUA (AUR helper) in Go, sandboxed with Landlock and optionally bubblewrap + seccomp.

**Status:** prototype with install/upgrade flows, dependency planning, and sandboxing.

## Implemented Commands

- **builddir:** Build a PKGBUILD directory in a sandbox.
  - Flags: `--online`, `--offline` (default), `--force`, `--no-seccomp`, `--bwrap`.
- **shellcheck:** Run shellcheck for a PKGBUILD in a sandbox.
  - Uses a wrapper to set PKGBUILD-specific variables to reduce false positives.
- **namcap:** Run namcap for a PKGBUILD in a sandbox.
  - Standalone and guided upgrade checks read `/var/lib/pacman` for libalpm dependency analysis.
- **install:** Clone AUR repos, review, build, stage, and install by default.
  - Flags: `--online`, `--offline` (default), `--force`, `--stage-only`, `--asdeps`, `--plan`, `--install-repo-deps`, `--no-seccomp`.
  - Review warns about source URLs with Unicode/IDN hostname spoofing risks and suspicious shell logic; interactive installs require acknowledgement before continuing.
- **tarcheck:** Inspect a built package archive interactively (SUID, execs, INSTALL, etc.).
- **search:** Search AUR by name/description via RPC; ALL provided keywords must match (AND semantics).
- **info:** Show AUR package info via RPC (human-readable; use `--json` for raw JSON).
- **upgrade:** Preview outdated AUR packages and ask for confirmation before reviewing, building, and installing; `--plan` only prints the upgrade plan.
  - Alias: `update` accepts the same flags and performs the same actions.
  - Guided flow: automatic recipe diff and audits → approve → fast-forward → verify sources → sandboxed build → automatic artifact report → pacman confirmation.
  - Flags include `--upstream` for explicit verified GitHub overrides and `--validate-all-arches` for complete architecture validation.
- **upstream:** Inspect configured or discovered GitHub candidates as text or JSON and manage bounded verification evidence.

## Searching

Search terms are case-insensitive and combined with AND. Plain keywords match
substrings in package names or descriptions. A leading `^` anchors the start of
a package name, and a trailing `$` anchors its end. With both, the name must
match exactly. Patterns containing `*` match the whole package name, with each
`*` standing for any sequence of characters, including none.

```sh
go-rua search '^python'             # names starting with python
go-rua search '-git$'               # names ending with -git
go-rua search '^python' '-git$'     # both conditions
go-rua search '^python$'            # exact name
go-rua search 'python*'             # wildcard prefix
go-rua search '*-git'               # wildcard suffix
go-rua search 'python*-git'         # wildcard prefix and suffix
go-rua search '^python' terminal    # name prefix and keyword in name/description
```

Quote patterns to prevent shell expansion. Only `*`, a leading `^`, and a
trailing `$` have special meaning; other punctuation such as `.` and `+` is
literal. Anchored and wildcard terms match names only. Suffix patterns such as
`-git$` work directly; use `--` before other terms that begin with a dash.

At least one term must contain two consecutive literal characters to query
the AUR. A shorter pattern can be combined with another, longer term.
API errors, including queries that return too many candidates, are reported
instead of appearing as empty results; add a more specific term if needed.

## Dependency Planning and Summaries

- AUR info includes Depends/MakeDepends/CheckDepends fields.
- Pre-install summary shows missing repo deps and unknown/virtual deps.
- `install --plan` prints a build plan with topological order, repo deps to install, and unknowns.
- `upgrade --plan` prints the plan; `upgrade` previews versions, build order, and missing dependencies, then asks `Proceed with upgrade? [y/N]` before continuing. Only `y` or `yes` proceeds; empty input or EOF cancels.
- `upgrade --devel` considers VCS packages (-git/-hg/-bzr/-svn/-cvs/-darcs) as candidates.
- `upgrade --ignore` and pacman `IgnorePkg` omit packages from upgrade checks; nonexistent packages are reported.
- `upgrade --plan` performs best-effort GitHub reporting for supported static recipes. This includes canonical release assets and tag-pinned `git+https://github.com/OWNER/REPO[.git]#tag=...` sources. `upgrade --upstream` explicitly opts into an ephemeral verified recipe override; `--validate-all-arches` requires every declared architecture source and verification mapping.
- Optional GitHub and GitHub Enterprise policy is read from `$XDG_CONFIG_HOME/rua/github_upstream.json`. See the [`internal/upstream` package documentation](internal/upstream/README.md) for schema version 1, implementation details, and trust boundaries.
- Optional `--install-repo-deps` runs `pacman -S --needed` using the elevation tool (see below) for missing repo deps.

## Guided upgrades

`go-rua upgrade` (or `go-rua update`) first previews the upgrade plan and asks for
confirmation before installing repository dependencies or starting recipe reviews.
It then processes that dependency plan and reviews/builds each package base once.
Dependencies already at a sufficient version are reused. At the
recipe prompt, **A** approves the displayed recipe and findings, **D** redisplays
the diff, **S** skips that package base, and **Q** cancels. End-of-input cancels;
it never approves. A skipped dependency blocks consumers only when the installed
system cannot satisfy their dependency requirements.

Recipe diffs use Git's line-by-line unified hunks with three lines of context.
On terminals, deletions are red and additions are green; individual character
edits within equally sized replacement blocks are bold with inverse highlighting.
Unchanged text between separate edits keeps its ordinary line color. Very long
lines that exceed the character-comparison limit use ordinary line colors.
File-mode changes and missing final newlines remain visible. Without a confirmed
installed baseline, every recipe file is shown in full. Diffs
honor `--color=always|never|auto`, `RUA_COLOR`, `NO_COLOR`, `CLICOLOR_FORCE`, and
`CLICOLOR`. Redirected output stays plain unless color is explicitly forced;
terminal controls embedded in recipe content are displayed as escaped text.

Before approval, go-rua reads the fetched commit as data and shows every changed
recipe input. Checks compare source host/project identity, full Arch versions,
checksum mappings, signing keys, shell logic, and supported packaging metadata.
ShellCheck and namcap run automatically. `INFO` findings are informational;
`REVIEW` findings require approval; `BLOCK` findings must be corrected. Missing
tools and dynamic expressions remain visible, and inspection failures never
count as successful checks. A checksum match establishes integrity against the
reviewed recipe; it does not establish the source author's identity.

The approved commit is fast-forwarded into the persistent checkout. Existing
local changes or divergent history require manual resolution. HTTPS sources
that can be resolved statically are downloaded as data with redirect reporting;
new cross-host redirects require `accept sources`. After a confirmed installation,
accepted redirects are remembered for that package base and source/destination
host pair, even when archive filenames change with the version. They remain
visible as `INFO` with `(previously accepted)` and do not prompt again. A new host
pair, missing baseline, installed-version drift, or pending transaction requires
approval again. Source verification still runs on every upgrade. Dynamic and VCS
fetching requires explicit review each time, then runs inside the sandbox. The
effective recipe is verified with `makepkg --verifysource`; failures stop the
build. Default builds remain offline. `--upstream` retains its separate
generated-recipe approval.

Artifacts are copied into a private staging directory and inspected using tar
headers, including package identity, links, permissions, and content digests.
The report distinguishes paths added to the package, paths absent from disk,
and ownership conflicts. It highlights new executables, SUID/SGID files,
services/hooks, and `.INSTALL`. Press **A** to accept exceptional findings;
**F** displays the complete manifest, **S** skips, and **Q** cancels. Pacman then provides the installation
confirmation. Malformed archives, missing expected outputs, conflicting ownership,
wrong versions/architectures, and changed artifact digests block installation.
Recognized package metadata (`.PKGINFO`, `.BUILDINFO`, `.MTREE`, `.INSTALL`, and
`.CHANGELOG`) must use regular-file archive entries; links, directories, and
special entries are rejected before approval.
Supported compression is tar, gzip, xz, and zstd; compressed inspection requires
the corresponding system decompressor.

Successful installations save private, versioned recipe snapshots and artifact
manifests in `$XDG_DATA_HOME/rua/review_state` (default
`~/.local/share/rua/review_state`). The first guided upgrade requires full review.
Saved records are used only while installed package versions still match.
Pending evidence is written before installation, and the baseline advances only
after pacman succeeds and the installed versions are confirmed. An interrupted
or ambiguous transaction causes a full review on retry; it is never inferred to
have succeeded from a matching version alone. Failed build directories and staged
artifacts remain available for diagnosis. Concurrent guided sessions are excluded
by a private session lock.

Run `make test` for deterministic workflow and archive fixtures. On an Arch host,
`make integration-upgrade` exercises sandboxed namcap checks on a recipe and its
built package, a real sandboxed fixture build, archive inspection, and a pacman
transaction in a temporary root using a user namespace.
The transaction uses a fixture-only pacman configuration, cache, keyring, and
hook directory. It omits the host's `DownloadUser`, whose UID is unavailable in
the single-user namespace, and permits the unsigned local fixture package.
It does not install the fixture into the host package database.

## Sandboxing

- **Landlock:** Filesystem sandbox using the pinned upstream module and requiring kernel ABI 3+ (including truncation protection):
  - RO: `/etc`, `/proc`, `/sys`; ROX: `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`.
  - RW: `/dev/null`, `/dev/tty`, `/dev/pts`, `/dev/shm`; RWX: `/tmp`, `/var/tmp`.
  - RO permits reads; ROX adds execution; RW adds writes, truncation, creation, deletion, and cross-directory rename/link; RWX also permits execution. Rename/link cannot escape the policy or gain permissions. File and device grants use only rights valid for those path types.
  - Missing built-in paths are skipped; missing explicitly configured paths fail. Enforcement and `no_new_privs` apply to all Go/CGO threads and are inherited by children. Strict enforcement failures stop execution; explicit `BestEffort` warns and continues.
  - Minimal environment pass-through. The shared writable `/tmp`, `/var/tmp`, and `/dev/shm` defaults remain broad grants; this backend does not create private temporary mounts.
- **Bubblewrap:** When `--offline`, go-rua requires bubblewrap network isolation with `--unshare-net` and bubblewrap bind mounts. When bubblewrap is used, Landlock is not also applied in that sandbox process. To accept weaker Landlock-only offline isolation, set `RUA_ALLOW_WEAK_OFFLINE=1` with `RUA_NO_BWRAP=1`.
- **Seccomp denylist:** Optional and on by default. A minimal seccomp-bpf denylist blocks risky syscalls (ptrace, bpf, userfaultfd, kexec, perf_event_open, name/open_by_handle, setns, mount family, pivot_root, module load, keyctl, process_vm_* , fanotify_init, chroot, reboot, iopl/ioperm, swapon/swapoff). Disable with `--no-seccomp` for debugging.
- **Offline builds:** By default, go-rua builds offline. It first runs a prefetch step (`makepkg -f --verifysource`) with network allowed, using a static PKGBUILD generated from `.SRCINFO` when available for `install`/`builddir`, then builds with network disabled. Guided upgrades verify the approved effective recipe directly after review. Use `--online` to allow network during the build.
- **Source URL audit:** Before `install` and `builddir` builds, go-rua reviews `.SRCINFO` and simple literal or primitively resolved `PKGBUILD` source entries for Unicode/IDN hostname spoofing risks and warns when the two source lists differ. Interactive installs require acknowledging warnings with `U` before continuing.
- **Shell logic audit:** Before `install` and `builddir` builds, go-rua parses `PKGBUILD`, literal `install=...` hook files, package-local `*.sh` files, and shell-looking source files with tree-sitter-bash. It warns on `eval`, shell `-c`, download pipelines into shells, `/dev/tcp` or `/dev/udp`, embedded base64 blobs, and third-party module installer commands such as npm, bun, pip, rustup, cargo, and `go install`. Interactive installs require acknowledging warnings with `H`; `builddir` prints warnings and continues.

## Typical Flows

- Build a local PKGBUILD directory (offline by default, with seccomp):
  - `go-rua builddir /path/to/pkg`
  - Allow network: `go-rua builddir --online /path/to/pkg`
- Plan install for an AUR target:
  - `go-rua install --plan yay`
- Install an AUR target and auto-install repo deps:
  - `go-rua install --install-repo-deps yay`
- Build, review, and stage an AUR target without installing it:
  - `go-rua install --stage-only yay`
- Check the upgrade plan without making changes:
  - `go-rua upgrade --plan`
- Review, build, and install upgrades, including missing repo dependencies:
  - `go-rua upgrade --install-repo-deps`
- Inspect upstream candidates as JSON:
  - `go-rua upstream --json`
- Export retained verification evidence to a new directory:
  - `go-rua upstream --export-evidence ./rua-evidence`

## Notes

- Pacman dependencies must be installed outside the sandbox unless you use `--install-repo-deps`.
- Offline builds require bubblewrap by default. Landlock-only offline builds require the explicit `RUA_ALLOW_WEAK_OFFLINE=1` override.
- Network isolation cannot be guaranteed by Landlock alone; bubblewrap’s `--unshare-net` provides stronger isolation.
- The seccomp denylist returns EPERM for denied syscalls to reduce breakage; you can disable it per command with `--no-seccomp`.
- Elevation command: set `RUA_SUDO_COMMAND` to override the default `sudo` (e.g., `doas`, `suex`, etc.). Printed hints and pacman calls respect it.
- Colors: honors `NO_COLOR`, `CLICOLOR`/`CLICOLOR_FORCE`, and `RUA_COLOR=always|never|auto`.

## Development

- Toolchain: `make toolchain` (validates and displays the exact compiler)
- Build: `make build` (formats first, then writes `bin/go-rua`)
- Format: `make fmt`
- Test: `make test` (formats first)
- Enforcement tests: `make integration-landlock` (rebuilds the CLI and requires real kernel enforcement and pinned dependency provenance)
- Full local check: `make check` (verify, format, vet, test, build, vulnerability scan, enforcement tests)
- Global help: `go-rua help` or `go-rua --help`
- Detailed command help: `go-rua help <command>`, `go-rua <command> --help`, or `go-rua <command> -h`
- Smoke test: `make smoke` (best-effort; skips AUR checks if offline)

The `toolchain` directive in `go.mod` is the sole source of truth for the exact
supported Go toolchain version. The `go` directive specifies Go's minimum
requirement; supported builds additionally require the exact `toolchain` version,
even when a newer compiler is installed. Build tooling requires Python 3 (3.11+
for the full release test suite), using only its standard library.

`scripts/go_toolchain.py` centralizes selection and validation for Make and CI.
`make toolchain` reports the effective compiler;
`python3 scripts/go_toolchain.py print` displays the declaration without invoking Go. Unset or matching
`GOTOOLCHAIN` values are accepted; conflicting versions, `auto`, and `local` are
rejected. An unavailable compiler fails instead of falling back. Go may obtain
the exact compiler through its normal verified toolchain download mechanism;
offline builds require it installed or authentically cached first.

After compiler setup, CI runs `check-installed --github-env`. This check accepts
the setup action's `GOTOOLCHAIN=local` only to inspect the installed compiler
without switching. Once its version matches `go.mod`, the helper appends the
exact toolchain to `GITHUB_ENV` for subsequent steps. A mismatch fails before
exporting a version; build commands continue to reject `local` overrides.

To upgrade the supported compiler, edit only the `toolchain` directive in
`go.mod`, then run `make check test-release` and `make verify-repro`. Do not
repeat the current compiler version in Makefiles, workflows, or documentation.
For direct Go commands, use `python3 scripts/go_toolchain.py exec go <arguments>`
from the repository root, and run module verification before using dependencies.

Makefile Go commands set `GOWORK=off`, use local caches, verify module checksums,
and reject Landlock replacements. Offline builds require the authentic pinned
dependencies and toolchain in those caches. Local stubs are unsupported.
`make test` may skip enforcement probes on unsupported kernels;
`make integration-landlock`, `make check`, and `make publish` require ABI 3+ and
never skip that gate. Probe fixtures live under `.gocache-tests`; if the checkout
is inside a default allowed tree such as `/tmp`, set `RUA_LANDLOCK_TEST_ROOT` to a
private writable directory outside all default grants so denied-access checks
remain meaningful.

## CI and releases

GitHub Actions runs Linux amd64 checks for branches and pull requests. Releases
run the same checks against the tagged commit, then rebuild and validate the
actual archive executable before signing. Checks include formatting, module
integrity, vet, unit tests, pinned govulncheck, mandatory Landlock ABI 3+
enforcement, and an unprivileged Arch fixture build with an isolated pacman
transaction. Missing sandbox capabilities fail CI rather than skipping a gate.

Builds require the exact Go toolchain declared in `go.mod` and a native C
compiler: tree-sitter and all-thread Landlock enforcement require CGO.
Release executables retain PIE and dynamic
libc linking. CI builds with Ubuntu 24.04's glibc toolchain and tests the same
executable in current Arch userspace; no Windows, macOS, or ARM artifacts are
produced.

```sh
make test-release
make release-all VERSION=v1.2.3
make verify-repro VERSION=v1.2.3
mkdir -p .gocache/release-check
# Run after release-all or verify-repro:
tar -xzf dist/go-rua_linux_amd64.tar.gz -C .gocache/release-check
make test-release-binary VERSION=v1.2.3 RELEASE_BINARY="$PWD/.gocache/release-check/go-rua"
# On an Arch host, check the same executable without rebuilding it:
RELEASE_BINARY="$PWD/.gocache/release-check/go-rua" RUA_REQUIRE_ARCH_TESTS=1 \
  bash scripts/integration-upgrade.sh
```

`verify-repro` compares binaries, complete archives, and checksum manifests from
two builds with independent caches. Reproducibility assumes identical source,
Go toolchain, C compiler, libc, and build environment. Archives contain `go-rua`
and `README.md` with normalized permissions and timestamps. Existing signed or
attested output in `dist` must be moved aside before building a new release.

The toolchain decision keeps compiler upgrades in the same reviewed source
commit as the build inputs. CI installs from `go.mod`, checks the installed
compiler without automatic switching, and validates the compiler embedded in
the release binary before attestation. SLSA provenance binds artifact digests
to the source commit and workflow; that commit's `go.mod` defines the required
compiler. The existing attestation does not add a compiler-version field, and
this policy does not change the claimed SLSA level. Matching Go alone does not
make builds reproducible across different C compilers, libc, or environments.

### Maintainer setup and publishing

Create a public GitHub repository with Actions enabled and add a `github` remote
pointing to it. Keep the existing Gitea `origin` if desired. Remote configuration,
commits, and tag pushes are maintainer actions; this change does not perform them.
Push the reviewed source and make the Linux CI job a required status check
for the default branch. Protect release tags against unauthorized creation,
updates, and deletion. Review workflow changes and keep the SHA-pinned actions,
Cosign version, govulncheck version, and Arch image digest current.

```sh
make publish-check VERSION=v1.2.3
make publish VERSION=v1.2.3 PUBLISH=1
# Override the remote if it has another name:
make publish VERSION=v1.2.3 RELEASE_REMOTE=release-github PUBLISH=1
```

Publishing requires a clean worktree, git-cliff, a working local Git signing
identity, and a GitHub push URL. The command runs checks, creates a signed
annotated tag with git-cliff's notes, and pushes only that tag. GitHub Actions
creates the release; no long-lived signing key or release token is needed in CI.
SCP-style SSH aliases such as `github:OWNER/go-rua.git` are supported when
`ssh -G github` resolves to `hostname github.com` and `user git` on the publishing
machine. The original alias is preserved so its SSH identity settings apply.
Tags must be `vMAJOR.MINOR.PATCH`, optionally followed by a SemVer prerelease,
without build metadata. Prereleases do not become the latest stable release.
Validate setup with a new prerelease before publishing a stable version.

### Verifying downloads

New releases have exactly five uploaded assets:

- `go-rua_linux_amd64.tar.gz`
- `SHA256SUMS`
- `go-rua_linux_amd64.tar.gz.sigstore.json`
- `SHA256SUMS.sigstore.json`
- `provenance.sigstore.json`

The archive and manifest each have a keyless Cosign signature using GitHub
Actions OIDC and public Sigstore. Their identities and digests appear in public
transparency logs. The provenance bundle has its own Sigstore signature and
covers exactly those two files with SLSA v1 provenance. This targets SLSA Build
Level 2, linking the artifacts to their source commit, tag, and release workflow.
Signature bundles are excluded from `SHA256SUMS`. GitHub-generated source
archives are outside this signed set; older releases are not backfilled.

Install Cosign v3.0.6 or newer and a current GitHub CLI with attestation support.
Download all five assets from the same release. Replace the repository and tag
below with the trusted publisher and release you intend to verify:

```sh
repo=OWNER/go-rua
tag=v1.2.3
asset=go-rua_linux_amd64.tar.gz
identity="https://github.com/$repo/.github/workflows/release.yml@refs/tags/$tag"
issuer=https://token.actions.githubusercontent.com

for file in "$asset" SHA256SUMS; do
  cosign verify-blob --bundle "$file.sigstore.json" \
    --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$file"
  gh attestation verify "$file" --bundle provenance.sigstore.json \
    --repo "$repo" --cert-identity "$identity" --cert-oidc-issuer "$issuer" \
    --predicate-type https://slsa.dev/provenance/v1 \
    --source-ref "refs/tags/$tag" --deny-self-hosted-runners
done
sha256sum --check --strict SHA256SUMS
```

Stop if any verification fails. If you independently know the expected source
commit, add `--source-digest <trusted-commit-sha>` to the attestation command.
CI always requires that commit and checks the entire provenance subject set.
Publication uploads to a draft, downloads and verifies every asset, compares
bytes, and rechecks the remote tag before publishing. Failed drafts can be
retried by rerunning the workflow; already-published releases are never replaced.

See [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations),
[GitHub CLI verification](https://cli.github.com/manual/gh_attestation_verify), and
[Sigstore signature verification](https://docs.sigstore.dev/cosign/verifying/verify/).
