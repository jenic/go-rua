#!/usr/bin/env bash
# Maintainer-invoked tooling. CI publishes artifacts after this signed tag push.
set -euo pipefail
root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$root_dir"
version=${VERSION:-}
remote=${RELEASE_REMOTE:-github}
fail() { echo "publish: $*" >&2; exit 1; }

validate_push_url() {
  local url=$1 target config key value hostname= user=
  [[ $url != *$'\n'* ]] || fail 'RELEASE_REMOTE must have exactly one push URL'
  if [[ $url =~ ^(git@github\.com:|https://github\.com/|ssh://git@github\.com/)[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    return
  fi
  # SCP-style remotes may use an SSH Host alias to select an account/key.
  # Resolve configuration locally (-G makes no network connection), preserving
  # the alias for the actual ls-remote and push commands.
  if [[ $url =~ ^(([A-Za-z0-9_.-]+)@)?([A-Za-z0-9][A-Za-z0-9_.-]*):[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    target=${BASH_REMATCH[1]}${BASH_REMATCH[3]}
    command -v ssh >/dev/null || fail 'ssh is required to resolve the release remote host alias'
    config=$(ssh -G "$target") || fail "unable to resolve SSH configuration for $target"
    while read -r key value; do
      case $key in
        hostname) hostname=$value ;;
        user) user=$value ;;
      esac
    done <<< "$config"
    [[ ${hostname,,} == github.com && $user == git ]] ||
      fail "SSH destination $target resolves to $user@$hostname; expected git@github.com"
    return
  fi
  fail 'RELEASE_REMOTE must use a GitHub URL or an SSH alias resolving to git@github.com'
}

preflight() {
  RELEASE_TAG="$version" bash .github/scripts/release.sh metadata >/dev/null
  [[ $remote =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || fail 'invalid RELEASE_REMOTE'
  for tool in git git-cliff; do
    command -v "$tool" >/dev/null || fail "$tool is required before publishing."
  done
  [[ $(git rev-parse --is-inside-work-tree) == true ]] || fail 'a Git worktree is required'
  local status tags push_url result
  status=$(git status --porcelain)
  [[ -z $status ]] || fail 'refusing to publish from a dirty worktree'
  push_url=$(git remote get-url --push --all "$remote")
  validate_push_url "$push_url"
  tags=$(git tag --list "$version")
  [[ -z $tags ]] || fail "Git tag $version already exists locally"
  if git ls-remote --exit-code --tags "$push_url" "refs/tags/$version" >/dev/null; then
    fail "Git tag $version already exists on $remote"
  else
    result=$?
    [[ $result == 2 ]] || fail "unable to check tags on $remote"
  fi
}

publish() (
  preflight
  [[ ${PUBLISH:-0} == 1 ]] || fail "preflight complete; use make publish VERSION=$version PUBLISH=1 to sign and push"
  local commit tag_message_file status
  commit=$(git rev-parse --verify 'HEAD^{commit}')
  tag_message_file=$(mktemp)
  trap 'rm -f -- "$tag_message_file"' EXIT
  git-cliff --unreleased --tag "$version" > "$tag_message_file"
  [[ -s $tag_message_file ]] || fail 'git-cliff produced an empty tag message'
  # Check again after notes generation, immediately before creating the tag.
  preflight
  status=$(git status --porcelain)
  [[ -z $status && $(git rev-parse --verify 'HEAD^{commit}') == "$commit" ]] ||
    fail 'worktree or HEAD changed while preparing the release'
  git tag -s --cleanup=verbatim -F "$tag_message_file" "$version" "$commit"
  git push "$remote" "refs/tags/$version:refs/tags/$version"
)

case ${1:-check} in
  check) preflight ;;
  publish) publish ;;
  *) fail 'usage: publish.sh check|publish' ;;
esac
