#!/bin/sh

set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$root_dir"

action=${1:-check}
version=${VERSION:-}
publish=${PUBLISH:-0}

fail() {
	printf '%s\n' "$*" >&2
	exit 1
}

preflight() {
	[ -n "$version" ] || fail "VERSION is required, for example: make publish VERSION=v0.1.0"

	command -v git-cliff >/dev/null 2>&1 || fail "git-cliff is required before publishing."
	command -v git >/dev/null 2>&1 || fail "git is required before publishing."

	printf '%s\n' "$version" | grep -Eq \
		'^v[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$' ||
		fail "VERSION must be a semantic version tag such as v0.1.0 or v1.2.3-rc.1"

	[ -z "$(git status --porcelain)" ] ||
		fail "Refusing to publish from a dirty worktree. Commit or stash changes first."

	git remote get-url origin >/dev/null 2>&1 ||
		fail "The git remote 'origin' is required before publishing."

	if git rev-parse --verify --quiet "refs/tags/$version" >/dev/null; then
		fail "Git tag $version already exists."
	fi
}

case "$action" in
check)
	preflight
	;;
publish)
	preflight
	if [ "$publish" != 1 ]; then
		printf '%s\n' "Preflight complete. Refusing to tag or publish without PUBLISH=1."
		printf '%s\n' "When ready, run: make publish VERSION=$version PUBLISH=1"
		exit 1
	fi

	tag_message_file=$(mktemp)
	trap 'rm -f "$tag_message_file"' EXIT HUP INT TERM
	git-cliff --unreleased --tag "$version" >"$tag_message_file"
	git tag -s --cleanup=verbatim "$version" -F "$tag_message_file"
	git push origin "$version"
	;;
*)
	fail "Usage: $0 {check|publish}"
	;;
esac
