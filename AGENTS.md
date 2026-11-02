# Repository Guidelines

## Project Structure & Module Organization
- `cmd/go-rua/main.go`: CLI entrypoint (commands: builddir, shellcheck, namcap, install, search, info, upgrade).
- `internal/`: implementation packages
  - `aur`: AUR RPC client
  - `build`: makepkg builds via sandbox
  - `install`: clone/review/build/stage flow
  - `pacman`: pacman/vercmp helpers
  - `paths`: XDG dirs (`~/.config/rua`, `~/.cache/rua/build`, `~/.local/share/rua/checked_tars`)
  - `sandbox`: Landlock (go-landlock) wrapper
  - `shellutil`: shellcheck/namcap wrappers
  - `tarcheck`: post-build archive inspection

## Build, Test, and Development Commands
- Build: `make build` (runs `make fmt` first)
- Run: `make run ARGS="help"` or `./bin/go-rua help`
- Format: `make fmt`
- Vet: `make vet`
- Tests: `make test` (runs `make fmt` first; add `_test.go` alongside code)
- Enforcement tests: `make integration-landlock` (requires real Landlock ABI 3+)
- Full local check: `make check` (verify, format, vet, test, build, vulnerability scan, enforcement tests)
- Release automation tests: `make test-release` (offline GitHub/Cosign/publisher fixtures)
- Release build: `make release-all VERSION=v1.2.3`; reproducibility: `make verify-repro VERSION=v1.2.3`
- Packaged executable gate: `make test-release-binary VERSION=v1.2.3 RELEASE_BINARY=/absolute/path/go-rua` (does not rebuild it)

Requirements: Go 1.26+ with toolchain `go1.26.10`, Linux kernel with Landlock ABI 3+ for the Landlock backend, Arch tools (`makepkg`, `pacman`, `vercmp`, `tar`, `git`, `shellcheck`, `namcap`).

## Dependency Integrity and Workspaces

Use the pinned upstream `github.com/landlock-lsm/go-landlock` module from `go.mod` and `go.sum`. Never replace this security dependency with a local stub, fork, or workspace module. A successful no-op implementation would disable filesystem enforcement while reporting success.

All Makefile Go commands set `GOWORK=off` and use workspace-local `GOCACHE`, `GOMODCACHE`, and `GOPATH`. `make verify` verifies module checksums and rejects Landlock replacements. Direct Go commands must use the same environment and run module verification before using cached dependencies.

Use `make deps` to download pinned modules into those caches and verify them. Builds and tests use `-mod=readonly`. Release binaries require native Linux amd64 CGO and PIE; do not copy a `CGO_ENABLED=0` release configuration from another project. `make publish` runs both `make check` and `make test-release`, then requires `PUBLISH=1` to create and push a signed tag to `RELEASE_REMOTE` (default `github`). Git metadata operations remain maintainer-run.

Offline development requires the authentic pinned modules and Go toolchain to be present in the local cache. Missing dependencies must produce an error; do not introduce substitutes. Local `go.work` and `go.work.sum` files are ignored and cannot affect the supported Makefile build.

`make integration-landlock` rebuilds the CLI, checks its upstream module version/checksum and absence of a replacement, and exercises real permissions in subprocesses. It fails when Landlock ABI 3+ is unavailable. `make check` and `make publish` require this gate. Ordinary `make test` may skip kernel enforcement tests on unsupported hosts. Fixtures must be outside the sandbox's default grants; set `RUA_LANDLOCK_TEST_ROOT` to a private directory outside those paths if the checkout lives under `/tmp` or another allowed tree.

## Coding Style & Naming Conventions
- Use standard Go style; run `make fmt` before pushing changes. Tabs/indentation as produced by gofmt.
- Package names: short, lower-case; exported identifiers use `PascalCase`.
- Errors: return `error`; messages start lower-case, no trailing punctuation.
- Files mirror package domain (e.g., `aur/aur.go`, `pacman/pacman.go`).
- Always run `make fmt` after making changes. `make build` and `make test` also run formatting first.

## Testing Guidelines
- Place tests next to code in `*_test.go` using `testing` and subtests.
- Name tests `TestXxx` and keep them deterministic; mock external commands where possible.
- Run `make test`; target at least basic coverage for new code paths.

## Commit & Pull Request Guidelines
- Commits: clear, focused changes. Prefer Conventional Commits (e.g., `feat: add upgrade --plan`).
- PRs: include description, rationale, how to test, and sample CLI output. Link issues when applicable.
- CI expectations: `make check` succeeds, formatting applied, `go vet` clean, tests pass, and the binary builds.

## Security & Configuration Tips
- Sandboxing: the Landlock backend uses upstream ABI 3 enforcement on all threads and inherited child processes; strict failures stop execution. Explicit `BestEffort` keeps warning-and-continue behavior. Bubblewrap uses its own filesystem mounts instead of stacking Landlock. Builds are offline by default; use `--online` to allow network for fetching sources.
- System deps: makepkg and package build dependencies must be installed outside the sandbox.
- Paths: review at `~/.config/rua/pkg/<pkgbase>`, builds at `~/.cache/rua/build/<pkgbase>`, staged artifacts at `~/.local/share/rua/checked_tars/<pkgbase>`.
