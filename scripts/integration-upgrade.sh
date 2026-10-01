#!/usr/bin/env bash
# A real Arch build and isolated package transaction; no host package installation.
set -euo pipefail
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
for tool in makepkg pacman vercmp bwrap unshare sha256sum; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "SKIP: integration-upgrade requires $tool on an Arch host"
    exit 0
  fi
done
if [[ $(id -u) == 0 ]]; then
  echo "SKIP: makepkg requires an unprivileged user"
  exit 0
fi
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/go-rua-integration.XXXXXXXX")
trap 'rm -rf -- "$fixture_dir"' EXIT
mkdir -p "$fixture_dir/recipe" "$fixture_dir/root/var/lib/pacman" "$fixture_dir/root/var/log"
printf 'guided upgrade integration fixture\n' > "$fixture_dir/recipe/payload"
fixture_hash=$(sha256sum "$fixture_dir/recipe/payload")
fixture_hash=${fixture_hash%% *}
cat > "$fixture_dir/recipe/PKGBUILD" <<'RECIPE'
pkgname=go-rua-integration-fixture
pkgver=1
pkgrel=1
pkgdesc='Temporary go-rua integration fixture'
arch=('any')
license=('MIT')
source=('payload')
package() {
    install -Dm644 "$srcdir/payload" "$pkgdir/usr/share/go-rua-integration-fixture/payload"
}
RECIPE
printf "sha256sums=('%s')\n" "$fixture_hash" >> "$fixture_dir/recipe/PKGBUILD"
# PKGEXT makes the fixture independent of compression tool configuration.
PKGEXT=.pkg.tar "$repo_dir/bin/go-rua" builddir "$fixture_dir/recipe"
fixture_archives=("$fixture_dir/recipe/"*.pkg.tar)
[[ ${#fixture_archives[@]} == 1 && -f ${fixture_archives[0]} ]]
printf 'o\n' | "$repo_dir/bin/go-rua" tarcheck "${fixture_archives[0]}"
unshare --user --map-root-user --mount \
  pacman --root "$fixture_dir/root" --dbpath "$fixture_dir/root/var/lib/pacman" \
  --logfile "$fixture_dir/root/var/log/pacman.log" --noscriptlet --noconfirm \
  -U "${fixture_archives[0]}"
unshare --user --map-root-user --mount \
  pacman --root "$fixture_dir/root" --dbpath "$fixture_dir/root/var/lib/pacman" \
  -Q go-rua-integration-fixture
cmp "$fixture_dir/recipe/payload" "$fixture_dir/root/usr/share/go-rua-integration-fixture/payload"
echo 'PASS: source verification, sandboxed build, archive inspection, isolated pacman transaction'
