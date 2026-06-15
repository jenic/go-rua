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
- Full local check: `make check` (format, vet, test, build)

Requirements: Go 1.26+ with toolchain `go1.26.4`, Linux kernel with Landlock support, Arch tools (`makepkg`, `pacman`, `vercmp`, `tar`, `git`, `shellcheck`, `namcap`).

## Workspaces (go work) and Local Replacements

This repo prefers using Go workspaces for local overrides instead of editing `go.mod` replaces. This is especially helpful when operating in restricted or offline environments.

Recommended setup (no network):

- Initialize workspace in the repo root: `go work init .`
- Add the local Landlock stub module: `go work use ./third_party/go-landlock`
- Ensure the stub’s module path matches upstream (`module github.com/landlock-lsm/go-landlock`).
- Do NOT add `replace` lines to `go.mod`. The workspace will satisfy the dependency.

Resulting `go.work` (example):

```
go 1.26

toolchain go1.26.4

use (
    .
    ./third_party/go-landlock
)
```

Toggling between stub and upstream:

- Use stub (offline): keep the `go.work` above and build normally.
- Use upstream (online): either remove `./third_party/go-landlock` from `go.work` or set `GOWORK=off` when building to ignore the workspace, then run `go mod tidy` as needed.

Notes:

- `go.work` affects local development only and is not published. CI can set `GOWORK=off` to ensure `go.mod` integrity.
- If you need a one-off mapping, you can also run: `go work edit -use ./third_party/go-landlock`.

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
- Sandboxing: builds and checks run via Landlock using go-landlock; builds are offline by default. Use `--online` to allow network for fetching sources.
- System deps: makepkg and package build dependencies must be installed outside the sandbox.
- Paths: review at `~/.config/rua/pkg/<pkgbase>`, builds at `~/.cache/rua/build/<pkgbase>`, staged artifacts at `~/.local/share/rua/checked_tars/<pkgbase>`.
