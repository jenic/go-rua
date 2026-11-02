#!/usr/bin/env bash
# A real Arch build and isolated package transaction; no host package installation.
set -Eeuo pipefail
phase=preflight
trap 'failure_code=$?; printf "FAIL: Arch integration (%s), line %s: %s (exit %s)\n" "$phase" "$LINENO" "$BASH_COMMAND" "$failure_code" >&2; exit "$failure_code"' ERR
stage() {
  phase=$1
  printf '[arch] %s\n' "$phase"
}
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
binary=${RELEASE_BINARY:-$repo_dir/bin/go-rua}
unavailable() {
  if [[ ${RUA_REQUIRE_ARCH_TESTS:-0} == 1 ]]; then
    echo "FAIL: $*" >&2
    exit 1
  fi
  echo "SKIP: $*"
  exit 0
}
for tool in makepkg pacman vercmp namcap bwrap unshare sha256sum; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    unavailable "integration-upgrade requires $tool on an Arch host"
  fi
done
if [[ $(id -u) == 0 ]]; then
  unavailable 'makepkg requires an unprivileged user'
fi
[[ -x $binary ]] || { echo "FAIL: missing executable: $binary" >&2; exit 1; }
# Prove that the package transaction and offline sandbox can create namespaces.
unshare --user --map-root-user --mount true
bwrap --unshare-user --unshare-net --ro-bind / / -- true
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/go-rua-integration.XXXXXXXX")
trap 'rm -rf -- "$fixture_dir"' EXIT
mkdir -p "$fixture_dir/recipe" "$fixture_dir/root/var/lib/pacman" "$fixture_dir/root/var/log" \
  "$fixture_dir/cache" "$fixture_dir/gnupg" "$fixture_dir/hooks"
# Use only local fixture policy. The host's DownloadUser UID cannot be mapped
# by --map-root-user; its repositories, cache, keyring, and hooks are unrelated
# to this locally built, unsigned test package.
cat > "$fixture_dir/pacman.conf" <<'CONFIG'
[options]
Architecture = auto
SigLevel = Required DatabaseOptional
LocalFileSigLevel = Optional
CONFIG
pacman_args=(
  --config "$fixture_dir/pacman.conf"
  --root "$fixture_dir/root"
  --dbpath "$fixture_dir/root/var/lib/pacman"
  --logfile "$fixture_dir/root/var/log/pacman.log"
  --cachedir "$fixture_dir/cache"
  --gpgdir "$fixture_dir/gnupg"
  --hookdir "$fixture_dir/hooks"
)
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
stage 'lint fixture recipe with namcap'
"$binary" namcap "$fixture_dir/recipe"
stage 'build fixture package'
"$binary" builddir "$fixture_dir/recipe"
stage 'locate package archive'
# The build sandbox filters the caller's environment, including PKGEXT. Accept
# the supported makepkg formats instead of assuming an environment override.
shopt -s nullglob
fixture_archives=("$fixture_dir/recipe/"*.pkg.tar{,.xz,.gz,.gzip,.zst,.zstd})
if ((${#fixture_archives[@]} != 1)); then
  printf 'FAIL: expected exactly one package archive, found %s in %s\n' "${#fixture_archives[@]}" "$fixture_dir/recipe" >&2
  printf 'Directory contents:\n' >&2
  printf '  %s\n' "$fixture_dir/recipe/"* >&2
  exit 1
fi
fixture_archive=${fixture_archives[0]}
if [[ ! -f $fixture_archive || -L $fixture_archive ]]; then
  printf 'FAIL: invalid package archive: %s\n' "$fixture_archive" >&2
  exit 1
fi
printf '[arch] using archive: %s\n' "$fixture_archive"
stage 'lint fixture package with namcap'
"$binary" namcap "$fixture_archive"
stage 'review package archive'
printf 'o\n' | "$binary" tarcheck "$fixture_archive"
stage 'install into isolated pacman root'
unshare --user --map-root-user --mount \
  pacman "${pacman_args[@]}" --noscriptlet --noconfirm -U "$fixture_archive"
stage 'query installed fixture'
unshare --user --map-root-user --mount \
  pacman "${pacman_args[@]}" -Q go-rua-integration-fixture
stage 'compare installed payload'
cmp "$fixture_dir/recipe/payload" "$fixture_dir/root/usr/share/go-rua-integration-fixture/payload"
echo 'PASS: source verification, sandboxed build, archive inspection, isolated pacman transaction'
