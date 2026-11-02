#!/usr/bin/env bash
# Check an existing release executable against current Arch userspace.
set -euo pipefail
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
binary=$(realpath "${1:?release executable required}")
version=${2:?expected version required}
[[ -x $binary ]] || { echo 'release executable is missing' >&2; exit 1; }
# Official archlinux:base-devel amd64 image, created 2026-10-27. Update this
# digest explicitly; package updates below intentionally test current Arch.
image=archlinux:base-devel@sha256:cb06b309ab9424b354a8e1099a934fc48b13e62c3d4453d19d50beaa72c6caee
# Ubuntu's AppArmor restriction also applies to nested unprivileged namespaces.
# Change only this disposable hosted VM; never disable go-rua's sandbox checks.
if [[ -f /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]]; then
  sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
fi
docker run --rm --platform linux/amd64 \
  --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
  --mount "type=bind,src=$repo_dir,dst=/src,readonly" \
  --mount "type=bind,src=$binary,dst=/release/go-rua,readonly" \
  --env EXPECTED_VERSION="$version" "$image" bash -euo pipefail -c '
    pacman -Syu --noconfirm --needed bubblewrap git shellcheck namcap
    useradd --create-home release-test
    runuser -u release-test -- bash -euo pipefail -c '\''
      test "$(/release/go-rua version)" = "$EXPECTED_VERSION"
      /release/go-rua --help >/dev/null
      RELEASE_BINARY=/release/go-rua RUA_REQUIRE_ARCH_TESTS=1 \
        bash /src/scripts/integration-upgrade.sh
    '\''
  '
