go-rua

A lightweight reimplementation of RUA (AUR helper) in Go, using Linux Landlock (via go-landlock) for sandboxing.

Status: initial MVP

Implemented commands

- builddir: Build a PKGBUILD directory inside a Landlock sandbox. Supports --offline and --force.
- shellcheck: Run shellcheck for a PKGBUILD in a sandbox.
- search: Search AUR by name/description via RPC.
- info: Show AUR package info via RPC (JSON output).

Planned/next

- install/upgrade flows with review and dependency handling
- tarcheck of built packages
- interactive review (diff/merge) similar to RUA

Sandboxing with Landlock

The build and checks run inside a Landlock sandbox applied in-process using the go-landlock library. With `--offline`, the sandbox aims to deny network access; without `--offline` builds may access the network as normal.
