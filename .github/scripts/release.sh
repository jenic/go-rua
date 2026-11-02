#!/usr/bin/env bash
# Release automation only; never called by the go-rua executable.
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

fail() { echo "release: $*" >&2; exit 1; }

validate_tag() {
  local number='(0|[1-9][0-9]*)'
  local identifier='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
  local pattern="^v${number}\\.${number}\\.${number}(-${identifier}(\\.${identifier})*)?$"
  [[ ${RELEASE_TAG:-} =~ $pattern ]] || fail 'expected a v-prefixed SemVer tag without build metadata'
}

prerelease() {
  if [[ $RELEASE_TAG == *-* ]]; then echo true; else echo false; fi
}

archives=(
  go-rua_linux_amd64.tar.gz
)
assets=("${archives[@]}" SHA256SUMS)
attested_assets=("${assets[@]}" provenance.sigstore.json)
signed_assets=("${attested_assets[@]}")
for asset in "${assets[@]}"; do signed_assets+=("$asset.sigstore.json"); done

check_assets() (
  cd "$1"
  local mode=$2 expected actual asset
  [[ $mode == unsigned || $mode == attested || $mode == signed ]] || fail 'invalid asset mode'
  local files=("${assets[@]}")
  if [[ $mode == attested ]]; then files=("${attested_assets[@]}"); fi
  if [[ $mode == signed ]]; then files=("${signed_assets[@]}"); fi
  expected=$(printf '%s\n' "${files[@]}" | LC_ALL=C sort)
  actual=$(find . -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)
  [[ $actual == "$expected" ]] || fail 'unexpected or missing release assets'
  for asset in "${files[@]}"; do
    [[ -f $asset && ! -L $asset && -s $asset ]] || fail "invalid asset: $asset"
  done
  # Compare the complete manifest, including names and ordering, before trusting it.
  diff -u SHA256SUMS <(sha256sum "${archives[@]}")
)

check_tag() {
  local object type sha depth
  object=$(gh api "repos/$GITHUB_REPOSITORY/git/ref/tags/$RELEASE_TAG" --jq '[.object.type, .object.sha] | @tsv')
  # Dereference annotated tags, including nested tags, without local Git writes.
  for ((depth=0; depth<16; depth++)); do
    IFS=$'\t' read -r type sha <<< "$object"
    if [[ $type == commit ]]; then
      [[ $sha == "$GITHUB_SHA" ]] || fail 'remote tag no longer matches the triggering commit'
      return
    fi
    [[ $type == tag && $sha =~ ^[0-9a-f]{40}$ ]] || fail 'invalid remote tag object'
    object=$(gh api "repos/$GITHUB_REPOSITORY/git/tags/$sha" --jq '[.object.type, .object.sha] | @tsv')
  done
  fail 'too many nested annotated tags'
}

verify_blob() {
  cosign verify-blob --bundle "$1.sigstore.json" \
    --certificate-identity "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/.github/workflows/release.yml@refs/tags/$RELEASE_TAG" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com "$1"
}

verify_provenance() (
  cd "$1"
  [[ -f provenance.sigstore.json && ! -L provenance.sigstore.json && -s provenance.sigstore.json ]] ||
    fail 'missing or invalid provenance bundle'
  local asset
  for asset in "${assets[@]}"; do
    # A failing verifier must fail the pipeline even if it emits valid JSON.
    gh attestation verify "$asset" --bundle provenance.sigstore.json \
      --repo "$GITHUB_REPOSITORY" \
      --cert-identity "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/.github/workflows/release.yml@refs/tags/$RELEASE_TAG" \
      --cert-oidc-issuer https://token.actions.githubusercontent.com \
      --predicate-type https://slsa.dev/provenance/v1 \
      --source-ref "refs/tags/$RELEASE_TAG" --source-digest "$GITHUB_SHA" \
      --deny-self-hosted-runners --format json |
      python3 -B "$script_dir/verify_provenance.py" "${assets[@]}"
  done
)

verify_signed() (
  check_assets "$1" signed
  cd "$1"
  verify_provenance .
  for asset in "${assets[@]}"; do verify_blob "$asset"; done
)

sign_assets() (
  check_tag
  check_assets "$1" attested
  cd "$1"
  verify_provenance .
  for asset in "${assets[@]}"; do
    cosign sign-blob --yes --oidc-provider github-actions --bundle "$asset.sigstore.json" "$asset"
    verify_blob "$asset"
  done
  check_assets . signed
)

publish() (
  check_tag
  verify_signed "$1"
  cd "$1"
  local draft download_dir asset
  local flags=()
  if [[ $(prerelease) == true ]]; then flags+=(--latest=false); fi
  # Listing distinguishes a missing release from API/authentication failures.
  draft=$(gh api --paginate "repos/$GITHUB_REPOSITORY/releases?per_page=100" \
    --jq ".[] | select(.tag_name == \"$RELEASE_TAG\") | .draft")
  if [[ -n $draft ]]; then
    [[ $draft == true ]] || fail 'release is already published; refusing to change its assets'
  else
    gh release create "$RELEASE_TAG" --verify-tag --draft --title "$RELEASE_TAG" --generate-notes \
      --prerelease="$(prerelease)" "${flags[@]}"
  fi
  # Only drafts are replaced on retry. A published release is never overwritten.
  gh release upload "$RELEASE_TAG" "${signed_assets[@]}" --clobber
  download_dir=$(mktemp -d)
  trap 'rm -rf "$download_dir"' EXIT
  gh release download "$RELEASE_TAG" --dir "$download_dir"
  verify_signed "$download_dir"
  for asset in "${signed_assets[@]}"; do cmp "$asset" "$download_dir/$asset"; done
  check_tag
  gh release edit "$RELEASE_TAG" --draft=false --prerelease="$(prerelease)" \
    "${flags[@]}"
)

validate_tag
case ${1:-} in
  metadata)
    printf 'tag=%s\nprerelease=%s\n' "$RELEASE_TAG" "$(prerelease)"
    ;;
  check-assets) check_assets "${2:?artifact directory required}" "${3:-unsigned}" ;;
  verify-provenance) verify_provenance "${2:?artifact directory required}" ;;
  sign) sign_assets "${2:?artifact directory required}" ;;
  publish) publish "${2:?artifact directory required}" ;;
  *) fail 'usage: release.sh metadata|check-assets|verify-provenance|sign|publish [directory] [unsigned|attested|signed]' ;;
esac
