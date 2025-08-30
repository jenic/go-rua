go-rua

A lightweight reimplementation of RUA (AUR helper) in Go, sandboxed with Landlock and optionally bubblewrap + seccomp.

Status: prototype with install/upgrade flows, dependency planning, and sandboxing.

Implemented commands

- builddir: Build a PKGBUILD directory in a sandbox.
  - Flags: `--offline`, `--force`, `--no-seccomp`.
- shellcheck: Run shellcheck for a PKGBUILD in a sandbox.
- namcap: Run namcap for a PKGBUILD in a sandbox.
- install: Clone AUR repos, review, build, stage, optional install.
  - Flags: `--offline`, `--force`, `--install`, `--plan`, `--install-repo-deps`, `--no-seccomp`.
- search: Search AUR by name/description via RPC.
- info: Show AUR package info via RPC (JSON output).
- upgrade: Print or apply upgrades for outdated AUR packages.
  - Flags: `--printonly`, `--apply`, `--offline`, `--force`, `--install-repo-deps`, `--no-seccomp`.

Dependency planning and summaries

- AUR info includes Depends/MakeDepends/CheckDepends fields.
- Pre-install summary shows missing repo deps and unknown/virtual deps.
- `install --plan` prints a build plan with topological order, repo deps to install, and unknowns.
- `upgrade` without flags prints the plan; with `--apply` it builds/install in plan order.
- Optional `--install-repo-deps` runs `sudo pacman -S --needed ...` for missing repo deps.

Sandboxing

- Landlock: Default file-system sandbox with a minimal baseline:
  - RO: `/etc`, `/proc`, `/sys`; ROX: `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`.
  - RW: `/dev/null`, `/dev/tty`, `/dev/pts`, `/dev/shm`; RWX: `/tmp`, `/var/tmp`.
  - Minimal env pass-through. `no_new_privs` set best-effort before exec.
- Bubblewrap (optional): When `--offline`, go-rua prefers bubblewrap if available to enforce network isolation with `--unshare-net`, while mapping Landlock-like binds. Disable with `RUA_NO_BWRAP=1`.
- Seccomp denylist (optional, default on): A minimal seccomp-bpf denylist blocks risky syscalls (ptrace, bpf, userfaultfd, kexec, perf_event_open, name/open_by_handle, setns, mount family, pivot_root, module load, keyctl, process_vm_* , fanotify_init, chroot, reboot, iopl/ioperm, swapon/swapoff). Disable with `--no-seccomp` for debugging.

Typical flows

- Build a local PKGBUILD directory (offline, with seccomp):
  - `go-rua builddir --offline /path/to/pkg`
- Plan install for an AUR target:
  - `go-rua install --plan yay`
- Install an AUR target, auto-install repo deps, and install built artifacts:
  - `go-rua install --install --install-repo-deps yay`
- Check for upgrades (print plan vs apply):
  - `go-rua upgrade` (prints plan)
  - `go-rua upgrade --apply --install-repo-deps`

Notes

- Pacman dependencies must be installed outside the sandbox unless you use `--install-repo-deps`.
- Bubblewrap is used only when available and when `--offline` is set; otherwise Landlock-only.
- Network isolation cannot be guaranteed by Landlock alone; bubblewrap’s `--unshare-net` provides stronger isolation.
- The seccomp denylist returns EPERM for denied syscalls to reduce breakage; you can disable it per command with `--no-seccomp`.

Development

- Build: `go build -o bin/go-rua ./cmd/go-rua`
- Help: `go-rua help`, `go-rua help <command>` or `go-rua <command> -h`
- Smoke test: `make smoke` (best-effort; skips AUR checks if offline)
