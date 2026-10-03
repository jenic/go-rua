# go-rua

A lightweight reimplementation of RUA (AUR helper) in Go, sandboxed with Landlock and optionally bubblewrap + seccomp.

**Status:** prototype with install/upgrade flows, dependency planning, and sandboxing.

## Implemented Commands

- **builddir:** Build a PKGBUILD directory in a sandbox.
  - Flags: `--online`, `--offline` (default), `--force`, `--no-seccomp`, `--bwrap`.
- **shellcheck:** Run shellcheck for a PKGBUILD in a sandbox.
  - Uses a wrapper to set PKGBUILD-specific variables to reduce false positives.
- **namcap:** Run namcap for a PKGBUILD in a sandbox.
- **install:** Clone AUR repos, review, build, stage, and install by default.
  - Flags: `--online`, `--offline` (default), `--force`, `--stage-only`, `--asdeps`, `--plan`, `--install-repo-deps`, `--no-seccomp`.
  - Review warns about source URLs with Unicode/IDN hostname spoofing risks and suspicious shell logic; interactive installs require acknowledgement before continuing.
- **tarcheck:** Inspect a built package archive interactively (SUID, execs, INSTALL, etc.).
- **search:** Search AUR by name/description via RPC; ALL provided keywords must match (AND semantics).
- **info:** Show AUR package info via RPC (human-readable; use `--json` for raw JSON).
- **upgrade:** Review, build, and install outdated AUR packages by default; `--plan` only prints the upgrade plan.
  - Guided flow: automatic recipe diff and audits → approve → fast-forward → verify sources → sandboxed build → automatic artifact report → pacman confirmation.
  - Flags include `--upstream` for explicit verified GitHub overrides and `--validate-all-arches` for complete architecture validation.
- **upstream:** Inspect configured or discovered GitHub candidates as text or JSON and manage bounded verification evidence.

## Dependency Planning and Summaries

- AUR info includes Depends/MakeDepends/CheckDepends fields.
- Pre-install summary shows missing repo deps and unknown/virtual deps.
- `install --plan` prints a build plan with topological order, repo deps to install, and unknowns.
- `upgrade --plan` prints the plan; `upgrade` reviews, builds, and installs outdated packages using the computed build order.
- `upgrade --devel` considers VCS packages (-git/-hg/-bzr/-svn/-cvs/-darcs) as candidates.
- `upgrade --ignore` and pacman `IgnorePkg` omit packages from upgrade checks; nonexistent packages are reported.
- `upgrade --plan` performs best-effort GitHub reporting for supported static recipes. This includes canonical release assets and tag-pinned `git+https://github.com/OWNER/REPO[.git]#tag=...` sources. `upgrade --upstream` explicitly opts into an ephemeral verified recipe override; `--validate-all-arches` requires every declared architecture source and verification mapping.
- Optional GitHub and GitHub Enterprise policy is read from `$XDG_CONFIG_HOME/rua/github_upstream.json`. See the [`internal/upstream` package documentation](internal/upstream/README.md) for schema version 1, implementation details, and trust boundaries.
- Optional `--install-repo-deps` runs `pacman -S --needed` using the elevation tool (see below) for missing repo deps.

## Guided upgrades

`go-rua upgrade` processes one dependency plan and reviews/builds each package
base once. Dependencies already at a sufficient version are reused. At the
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
cross-host redirects require `accept sources`. Dynamic and VCS fetching also
requires explicit review, then runs inside the sandbox. The effective recipe is
verified with `makepkg --verifysource`; failures stop the build. Default builds
remain offline. `--upstream` retains its separate generated-recipe approval.

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
`make integration-upgrade` exercises a real sandboxed fixture build, archive
inspection, and a pacman transaction in a temporary root using a user namespace.
It does not install the fixture into the host package database.

## Sandboxing

- **Landlock:** Default file-system sandbox with a minimal baseline:
  - RO: `/etc`, `/proc`, `/sys`; ROX: `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`.
  - RW: `/dev/null`, `/dev/tty`, `/dev/pts`, `/dev/shm`; RWX: `/tmp`, `/var/tmp`.
  - Minimal env pass-through. `no_new_privs` set best-effort before exec.
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

- Build: `make build` (formats first, then writes `bin/go-rua`)
- Format: `make fmt`
- Test: `make test` (formats first)
- Full local check: `make check` (format, vet, test, build)
- Global help: `go-rua help` or `go-rua --help`
- Detailed command help: `go-rua help <command>`, `go-rua <command> --help`, or `go-rua <command> -h`
- Smoke test: `make smoke` (best-effort; skips AUR checks if offline)
