#!/usr/bin/env bash
# Only for disposable GitHub-hosted Ubuntu runners.
set -euo pipefail
sudo apt-get update
sudo apt-get install -y --no-install-recommends build-essential binutils python3
# The Makefile owns workspace-local caches, toolchain, and integrity checks.
make deps
