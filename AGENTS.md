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
- Build: `go build -o bin/go-rua ./cmd/go-rua`
- Run: `./bin/go-rua help` or `go run ./cmd/go-rua --help`
- Format: `go fmt ./...`
- Vet: `go vet ./...`
- Tests: `go test ./...` (none yet; add `_test.go` alongside code)

Requirements: Go 1.21+, Linux kernel with Landlock support, Arch tools (`makepkg`, `pacman`, `vercmp`, `tar`, `git`, `shellcheck`, `namcap`).

## Coding Style & Naming Conventions
- Use standard Go style; run `go fmt` before pushing. Tabs/indentation as produced by gofmt.
- Package names: short, lower-case; exported identifiers use `PascalCase`.
- Errors: return `error`; messages start lower-case, no trailing punctuation.
- Files mirror package domain (e.g., `aur/aur.go`, `pacman/pacman.go`).

## Testing Guidelines
- Place tests next to code in `*_test.go` using `testing` and subtests.
- Name tests `TestXxx` and keep them deterministic; mock external commands where possible.
- Run `go test ./...`; target at least basic coverage for new code paths.

## Commit & Pull Request Guidelines
- Commits: clear, focused changes. Prefer Conventional Commits (e.g., `feat: add upgrade --printonly`).
- PRs: include description, rationale, how to test, and sample CLI output. Link issues when applicable.
- CI expectations: build succeeds (`go build`), formatting applied, `go vet` clean, tests pass.

## Security & Configuration Tips
- Sandboxing: builds and checks run via Landlock using go-landlock; `builddir --offline` denies network; omit `--offline` to fetch sources.
- System deps: makepkg and package build dependencies must be installed outside the sandbox.
- Paths: review at `~/.config/rua/pkg/<pkgbase>`, builds at `~/.cache/rua/build/<pkgbase>`, staged artifacts at `~/.local/share/rua/checked_tars/<pkgbase>`.
