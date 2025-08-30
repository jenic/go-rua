#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

echo "[smoke] Building CLI"
env GOMODCACHE="$ROOT_DIR/.gomodcache" GOCACHE="$ROOT_DIR/.gocache" \
  go build -o bin/go-rua ./cmd/go-rua

echo "[smoke] Running basic commands"
./bin/go-rua version
./bin/go-rua --help >/dev/null

have() { command -v "$1" >/dev/null 2>&1; }

echo "[smoke] Checking optional AUR/pacman-dependent flows"
if have pacman && have vercmp; then
  # Check network reachability to AUR RPC; skip if offline
  if curl -fsSL --max-time 5 "https://aur.archlinux.org/rpc/?v=5&type=info&arg[]=yay" >/dev/null 2>&1; then
    echo "[smoke] install --plan yay"
    ./bin/go-rua install --plan yay >/dev/null || true

    echo "[smoke] upgrade --printonly (exit 0 or 7 acceptable)"
    set +e
    ./bin/go-rua upgrade --printonly >/dev/null
    code=$?
    set -e
    if [[ $code -ne 0 && $code -ne 7 ]]; then
      echo "upgrade --printonly failed with code $code" >&2
      exit $code
    fi
  else
    echo "[smoke] Skipping AUR-dependent checks (no network)"
  fi
else
  echo "[smoke] Skipping pacman-dependent checks (pacman/vercmp missing)"
fi

echo "[smoke] OK"

