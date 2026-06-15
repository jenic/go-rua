go-rua

A lightweight reimplementation of RUA (AUR helper) in Go, sandboxed with Landlock and optionally bubblewrap + seccomp.

Status: prototype with install/upgrade flows, dependency planning, and sandboxing.

Implemented commands

- builddir: Build a PKGBUILD directory in a sandbox.
  - Flags: `--online`, `--offline` (default), `--force`, `--no-seccomp`.
- shellcheck: Run shellcheck for a PKGBUILD in a sandbox.
  - Uses a wrapper to set PKGBUILD-specific variables to reduce false positives.
- namcap: Run namcap for a PKGBUILD in a sandbox.
- install: Clone AUR repos, review, build, stage, optional install.
  - Flags: `--online`, `--offline` (default), `--force`, `--install`, `--asdeps`, `--plan`, `--install-repo-deps`, `--no-seccomp`.
- tarcheck: Inspect a built package archive interactively (SUID, execs, INSTALL, etc.).
- search: Search AUR by name/description via RPC; ALL provided keywords must match (AND semantics).
- info: Show AUR package info via RPC (human-readable; use `--json` for raw JSON).
- upgrade: Apply upgrades for outdated AUR packages by default; `--plan` prints the plan.
  - Flags: `--plan`, `--printonly`, `--devel`, `--ignore=<pkg1,pkg2>`, `--online`, `--offline` (default), `--force`, `--install-repo-deps`, `--no-seccomp`.

Dependency planning and summaries

- AUR info includes Depends/MakeDepends/CheckDepends fields.
- Pre-install summary shows missing repo deps and unknown/virtual deps.
- `install --plan` prints a build plan with topological order, repo deps to install, and unknowns.
- `upgrade --plan` prints the plan; without flags it builds/installs in plan order.
- `upgrade --devel` considers VCS packages (-git/-hg/-bzr/-svn/-cvs/-darcs) as candidates.
- `upgrade --ignore` and pacman `IgnorePkg` omit packages from upgrade checks; nonexistent packages are reported.
- Optional `--install-repo-deps` runs `pacman -S --needed` using the elevation tool (see below) for missing repo deps.

Sandboxing

- Landlock: Default file-system sandbox with a minimal baseline:
  - RO: `/etc`, `/proc`, `/sys`; ROX: `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`.
  - RW: `/dev/null`, `/dev/tty`, `/dev/pts`, `/dev/shm`; RWX: `/tmp`, `/var/tmp`.
  - Minimal env pass-through. `no_new_privs` set best-effort before exec.
- Bubblewrap (optional): When `--offline`, go-rua prefers bubblewrap if available to enforce network isolation with `--unshare-net`, while mapping Landlock-like binds. Disable with `RUA_NO_BWRAP=1`.
- Seccomp denylist (optional, default on): A minimal seccomp-bpf denylist blocks risky syscalls (ptrace, bpf, userfaultfd, kexec, perf_event_open, name/open_by_handle, setns, mount family, pivot_root, module load, keyctl, process_vm_* , fanotify_init, chroot, reboot, iopl/ioperm, swapon/swapoff). Disable with `--no-seccomp` for debugging.
- Offline builds: By default, go-rua builds offline. It first runs a prefetch step (`makepkg -f --verifysource`) with network allowed, using a static PKGBUILD generated from `.SRCINFO` when available, then builds with network disabled. Use `--online` to allow network during the build.

Typical flows

- Build a local PKGBUILD directory (offline by default, with seccomp):
  - `go-rua builddir /path/to/pkg`
  - Allow network: `go-rua builddir --online /path/to/pkg`
- Plan install for an AUR target:
  - `go-rua install --plan yay`
- Install an AUR target, auto-install repo deps, and install built artifacts:
  - `go-rua install --install --install-repo-deps yay`
- Check for upgrades (plan vs apply):
  - `go-rua upgrade --plan` (prints plan)
  - `go-rua upgrade --install-repo-deps` (applies by default)

Notes

- Pacman dependencies must be installed outside the sandbox unless you use `--install-repo-deps`.
- Bubblewrap is used only when available and when `--offline` is set; otherwise Landlock-only.
- Network isolation cannot be guaranteed by Landlock alone; bubblewrap’s `--unshare-net` provides stronger isolation.
- The seccomp denylist returns EPERM for denied syscalls to reduce breakage; you can disable it per command with `--no-seccomp`.
- Elevation command: set `RUA_SUDO_COMMAND` to override the default `sudo` (e.g., `doas`, `suex`, etc.). Printed hints and pacman calls respect it.
- Colors: honors `NO_COLOR`, `CLICOLOR`/`CLICOLOR_FORCE`, and `RUA_COLOR=always|never|auto`.

Development

- Build: `make build` (formats first, then writes `bin/go-rua`)
- Format: `make fmt`
- Test: `make test` (formats first)
- Full local check: `make check` (format, vet, test, build)
- Help: `go-rua help`, `go-rua help <command>` or `go-rua <command> -h`
- Smoke test: `make smoke` (best-effort; skips AUR checks if offline)
