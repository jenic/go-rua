# Threat Model

## Objective

go-rua exists to help users review, build, inspect, stage, and optionally install Arch Linux AUR packages while assuming that AUR package content may be malicious.

The primary security goal is risk reduction before installation. go-rua does not make arbitrary AUR packages safe to install. Once a built package is installed with `pacman -U`, its files, metadata, and install hooks become trusted by the local system in the same way as any other installed package.

## Security Goals

- Make untrusted AUR package content visible for human review before build and installation.
- Build AUR packages with reduced filesystem and network access by default.
- Separate source prefetch, package build, archive inspection, staging, and privileged installation into clear trust boundaries.
- Stage reviewed package archives before installation so the final privileged action is explicit.
- Surface risky package contents such as executable files, SUID/SGID files, and `.INSTALL` scripts.

## Non-Goals

- Proving that a package is benign.
- Safely installing a malicious package.
- Preventing all sandbox escapes, kernel bugs, parser bugs, or vulnerabilities in trusted host tools.
- Replacing the user's responsibility to inspect PKGBUILDs, install scripts, patches, upstream sources, and generated artifacts.
- Protecting a system after a malicious package has been installed.

## Assets

The threat model protects or exposes risk to these assets:

- User home data, credentials, SSH/GPG material, browser profiles, and other private files.
- System integrity, including `/usr`, `/etc`, package manager state, services, and boot/runtime configuration.
- The pacman local package database and trust decisions made through `pacman -U` or `pacman -S`.
- Network access, including the ability of build scripts to exfiltrate data or fetch unexpected content.
- Review directories under `~/.config/rua/pkg/<pkgbase>`.
- Build directories under `~/.cache/rua/build/<pkgbase>`.
- Staged package archives under `~/.local/share/rua/checked_tars/<pkgbase>`.

## Adversary Model

go-rua assumes these inputs may be hostile:

- AUR Git repository contents, including `PKGBUILD`, `.SRCINFO`, patches, helper scripts, and metadata.
- A malicious or compromised AUR maintainer account.
- Upstream source archives and VCS source repositories referenced by `source=`.
- Build-time generated files and package artifacts.
- Package `.INSTALL` scripts and other install-time hooks.
- Dependency declarations that attempt to confuse repo, AUR, virtual, or provided-package resolution.

The adversary may try to:

- Execute code during source verification, build, package functions, or install hooks.
- Read private host files or credential material.
- Modify files outside the intended build directory.
- Exfiltrate data over the network.
- Fetch or substitute different source content at build time.
- Spoof trusted source hostnames with Unicode or IDN characters that resemble ASCII domains.
- Hide suspicious payloads in generated package archives.
- Abuse package metadata, SUID/SGID bits, executables, service files, shell hooks, or post-install scripts.
- Trick the user into approving an unsafe package or dependency plan.

## Trusted Computing Base

This model assumes the following components are trusted but may still contain bugs:

- go-rua itself.
- The Linux kernel and configured sandbox primitives.
- Landlock, bubblewrap, and seccomp behavior as implemented by the host.
- Arch tooling including `makepkg`, `pacman`, `vercmp`, `pacman-conf`, and `tar`.
- `git`, the user's shell, `shellcheck`, and `namcap`.
- Official Arch repositories and packages already installed on the host.
- The Go runtime and standard library.

If any trusted component is compromised or has a vulnerability reachable from malicious package input, go-rua may not contain the attack.

## Workflow Trust Boundaries

### AUR Discovery and Planning

`search`, `info`, `install --plan`, and `upgrade --plan` consume AUR RPC data and local pacman state. AUR metadata is untrusted input. Dependency summaries and plans are advisory and should be reviewed before installing missing repo dependencies or building AUR dependencies.

Unknown or virtual dependencies require special attention because automated classification cannot prove what package should satisfy them.

### Review Checkout

For `install`, go-rua clones or updates AUR Git repositories into `~/.config/rua/pkg/<pkgbase>`. This directory is untrusted package source content.

Interactive review can show local or upstream diffs, run `shellcheck`, run `namcap`, or open a sandboxed shell. Approval in this phase only means "continue to build"; it does not establish that the package is safe.

go-rua audits source URLs from `.SRCINFO` and simple literal `PKGBUILD` source arrays before continuing. Hostnames with Unicode, IDN/Punycode differences, invisible/control characters, or mixed-script labels are highlighted. Differences between `.SRCINFO` and parsed `PKGBUILD` sources are also highlighted because stale metadata can hide source URLs from review. Interactive review requires acknowledging these warnings before continuing.

go-rua also parses `PKGBUILD` and literal `install=...` hook files with tree-sitter-bash to highlight suspicious shell logic such as `eval`, shell `-c`, download pipelines into shells, `/dev/tcp` or `/dev/udp`, embedded base64 blobs, and third-party module installer commands. Interactive review requires acknowledging these warnings before continuing. `builddir` prints these warnings but does not prompt.

### Build Directory

Before building, go-rua copies the reviewed checkout into `~/.cache/rua/build/<pkgbase>` and removes `.git`. The build directory is disposable and should be treated as hostile after package code has run.

### Source Prefetch

Offline builds first run a prefetch step with network access allowed using `makepkg -f --verifysource`. When `.SRCINFO` exists, go-rua attempts to generate a static `PKGBUILD.static` for source verification.

This step is a deliberate tradeoff: it allows required sources to be fetched before the main build runs offline. It is not equivalent to a fully offline workflow because source fetching still has network access.

### Sandboxed Build

Builds are offline by default. The main build runs `makepkg -f` in a sandbox with:

- Minimal environment pass-through.
- Build outputs directed into the build directory.
- Landlock filesystem restrictions.
- Bubblewrap network isolation with `--unshare-net` for offline builds by default.
- A seccomp denylist for selected high-risk syscalls unless disabled with `--no-seccomp`.

Landlock limits filesystem access but does not provide network isolation. Offline builds require bubblewrap by default; users who explicitly set `RUA_ALLOW_WEAK_OFFLINE=1` with `RUA_NO_BWRAP=1` accept weaker Landlock-only isolation without a private network namespace.

### Archive Review

After building, go-rua runs `tarcheck` on produced package archives. `tarcheck` lists package contents using sandboxed `tar` access and gives the user prompts to inspect:

- Executable files.
- All files.
- Files not already present on the filesystem.
- SUID/SGID files.
- `.INSTALL` content when present.
- A sandboxed shell with read-only access to the archive directory.

`tarcheck` is heuristic. It helps review obvious package contents but does not prove that binaries, scripts, services, hooks, or metadata are safe.

### Staging

Reviewed artifacts are moved to `~/.local/share/rua/checked_tars/<pkgbase>`. Staging marks that the archive passed the current review flow. It is not a cryptographic trust statement and does not imply the archive is safe.

### Privileged Installation

When `--install` is used, go-rua invokes pacman through the configured elevation command to install staged artifacts with `pacman -U --needed`. Repository dependencies may be installed with `--install-repo-deps`, which runs `pacman -S --needed`.

Privileged pacman operations are outside the sandbox. Installing a package is the final trust transition and can modify the system.

## Current Mitigations

- Review-first workflow for AUR Git contents.
- Dependency planning before install or upgrade.
- Unicode/IDN source URL spoofing warnings before install and builddir builds.
- Heuristic shell logic warnings before install and builddir builds.
- Offline-by-default main builds.
- Network-enabled prefetch separated from offline build.
- Sandboxed execution wrapper with explicit filesystem access rules.
- Bubblewrap network namespace isolation required for offline builds unless the explicit weak-offline override is set.
- Seccomp denylist for selected risky syscalls.
- Minimal environment construction for sandboxed commands.
- The main build sandbox does not mount the user's real GPG home.
- Build artifacts filtered by expected split package names where possible.
- Interactive archive inspection before staging.
- Staging under `checked_tars` before optional pacman installation.

## Known Limitations and Residual Risks

- A malicious package can still run code during source verification or build.
- Source prefetch has network access by design.
- `--online` allows network access during the main build.
- Landlock alone does not guarantee network isolation.
- Offline builds can run with Landlock-only isolation only when the user explicitly sets `RUA_ALLOW_WEAK_OFFLINE=1` and disables bubblewrap.
- Seccomp is a denylist, not a complete syscall policy.
- `--no-seccomp` disables the seccomp mitigation.
- Sandboxing depends on kernel and tool correctness.
- Trusted tools such as `makepkg`, `tar`, `git`, `shellcheck`, and `namcap` process untrusted input.
- Source URL spoofing detection is conservative and does not implement a full Unicode confusables skeleton.
- Shell logic detection is heuristic and may miss obfuscation or flag legitimate build/install behavior.
- PKGBUILD source parsing is best-effort and non-executing; dynamic source arrays may require manual review.
- Allowed filesystem paths may expose data needed by legitimate builds; local `wrap_args.d` policy can expand this access.
- `wrap_args.d` can intentionally expand sandbox access and should be treated as part of local policy.
- `tarcheck` does not deeply analyze binary behavior, service activation, package metadata side effects, or all install hook behavior.
- A malicious package installed with pacman can persist, modify system files, add users/services/hooks, or execute later as part of normal package behavior.

## Operational Guidance

- Prefer `install --plan` before building or applying changes. `upgrade` plans by default; use `upgrade --apply` only after reviewing the plan.
- Review AUR diffs before continuing, especially after updates.
- Treat source URL warnings as high-risk review items; compare the displayed host to the IDNA/Punycode form and codepoint details.
- Treat shell logic warnings as prompts for manual review of the exact `PKGBUILD` or install hook snippet.
- Treat unknown dependencies, virtual providers, and unexpected repo dependency suggestions as suspicious until understood.
- Keep the default offline build behavior unless a package genuinely requires `--online`.
- Avoid disabling bubblewrap or seccomp unless debugging a specific failure. If accepting weak offline isolation, treat that build as having no guaranteed network isolation.
- Inspect `.INSTALL` scripts, executable files, SUID/SGID files, service files, timers, hooks, and unexpected filesystem paths.
- Be cautious with packages that fetch code during build, use opaque binary blobs, or run large custom scripts.
- Do not install staged artifacts if review results are unclear.
- Remember that `--install-repo-deps` and `--install` perform privileged package manager operations.

## Future Hardening Ideas

- Record review decisions and artifact hashes in staging metadata.
- Expand archive review to highlight systemd units, pacman hooks, tmpfiles, sysusers, setcap usage, world-writable paths, and privileged paths.
- Provide clearer summaries of source URLs, checksums, VCS sources, and install scripts before build.
- Add policy controls for allowed network, allowed writable paths, and allowed environment variables.
- Improve provenance guidance for signed tags, PGP verification, and reproducible build checks.
