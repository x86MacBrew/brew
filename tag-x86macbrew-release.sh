#!/bin/bash
# Create or verify x86MacBrew release tags on the Intel maintenance line.
# See docs/X86MacBrew-Intel-Continuation.md, "Release tags".

set -euo pipefail

readonly INTEL_BRANCH="x86macbrew-intel-2027"
readonly INTEL_LINE_MARKER="docs/X86MacBrew-Intel-Continuation.md"
readonly RELEASE_TAG_PATTERN='^20[0-9][0-9]\.(1[0-2]|[1-9])\.[0-9]+$'
readonly LEGACY_LIGHTWEIGHT_RELEASE_TAG="2026.9.0"
# Local clones also hold upstream Homebrew tags in refs/tags, so keep the
# fork's own tags apart from them.
readonly ORIGIN_TAGS="refs/x86macbrew-origin-tags"

usage() {
  printf '%s\n' \
    "usage: tag-x86macbrew-release.sh [--dry-run] [<commit>]" \
    "       tag-x86macbrew-release.sh --verify" \
    "" \
    "<commit>   Commit to tag (default: origin/${INTEL_BRANCH})." \
    "--dry-run  Check and print the next tag without creating it." \
    "--verify   Check every tag on origin is a release on ${INTEL_BRANCH}." \
    "" \
    "Tags are created locally and never pushed."
}

mode="create"
target="refs/remotes/origin/${INTEL_BRANCH}"
while [[ $# -gt 0 ]]
do
  case "$1" in
    --dry-run) mode="dry-run" ;;
    --verify) mode="verify" ;;
    -h | --help)
      usage
      exit 0
      ;;
    -*)
      usage >&2
      exit 64
      ;;
    *) target="$1" ;;
  esac
  shift
done

fail() {
  printf 'FAIL  %s\n' "$*" >&2
}

git fetch --quiet origin "+refs/heads/${INTEL_BRANCH}:refs/remotes/origin/${INTEL_BRANCH}"
git fetch --quiet --prune --no-tags origin "+refs/tags/*:${ORIGIN_TAGS}/*"
origin_tags="$(git for-each-ref --format='%(refname:strip=2)' "${ORIGIN_TAGS}")"

is_release_tag() {
  [[ "$1" =~ ${RELEASE_TAG_PATTERN} ]]
}

is_annotated_release_tag() {
  [[ "${1##*/}" == "${LEGACY_LIGHTWEIGHT_RELEASE_TAG}" ]] ||
    [[ "$(git cat-file -t "$1")" == "tag" ]]
}

on_intel_line() {
  git merge-base --is-ancestor "$1" "refs/remotes/origin/${INTEL_BRANCH}" &>/dev/null &&
    git cat-file -e "$1:${INTEL_LINE_MARKER}" &>/dev/null
}

if [[ "${mode}" == "verify" ]]
then
  if [[ -z "${origin_tags}" ]]
  then
    echo "PASS  origin has no tags; brew update follows origin/HEAD"
    exit 0
  fi
  invalid=0
  while IFS='' read -r tag
  do
    if ! is_release_tag "${tag}"
    then
      fail "${tag} is not a YYYY.M.PATCH release tag"
      invalid=$((invalid + 1))
    elif ! is_annotated_release_tag "${ORIGIN_TAGS}/${tag}"
    then
      fail "${tag} must be an annotated tag"
      invalid=$((invalid + 1))
    elif ! on_intel_line "${ORIGIN_TAGS}/${tag}"
    then
      fail "${tag} is not an x86MacBrew commit on ${INTEL_BRANCH}"
      invalid=$((invalid + 1))
    fi
  done <<<"${origin_tags}"
  if [[ "${invalid}" -ne 0 ]]
  then
    echo "${invalid} tag(s) on origin are not x86MacBrew releases" >&2
    exit 1
  fi
  echo "PASS  $(wc -l <<<"${origin_tags}" | tr -d ' ') tag(s) on origin are x86MacBrew releases"
  exit 0
fi

if ! commit="$(git rev-parse --quiet --verify "${target}^{commit}")"
then
  fail "${target} is not a commit"
  exit 1
fi
short_commit="$(git rev-parse --short "${commit}")"

if ! on_intel_line "${commit}"
then
  fail "${short_commit} is not on origin/${INTEL_BRANCH} with ${INTEL_LINE_MARKER}"
  exit 1
fi

released_as=""
while IFS='' read -r tag
do
  [[ -n "${tag}" ]] || continue
  if ! is_release_tag "${tag}"
  then
    fail "origin has tag ${tag}, which is not an x86MacBrew release; delete it first"
    exit 1
  fi
  if ! is_annotated_release_tag "${ORIGIN_TAGS}/${tag}"
  then
    fail "${tag} must be an annotated tag"
    exit 1
  fi
  if ! on_intel_line "${ORIGIN_TAGS}/${tag}"
  then
    fail "${tag} is not an x86MacBrew commit on ${INTEL_BRANCH}"
    exit 1
  fi
  if ! git merge-base --is-ancestor "${ORIGIN_TAGS}/${tag}" "${commit}"
  then
    fail "${short_commit} would roll back release ${tag}; release a descendant instead"
    exit 1
  fi
  [[ "$(git rev-parse "${ORIGIN_TAGS}/${tag}^{commit}")" == "${commit}" ]] && released_as="${tag}"
done <<<"${origin_tags}"

if [[ -n "${released_as}" ]]
then
  fail "${short_commit} is already released as ${released_as}"
  exit 1
fi

year="$(date -u +%Y)"
month="$((10#$(date -u +%m)))"
latest_this_month="$(grep -E "^${year}\.${month}\.[0-9]+$" <<<"${origin_tags}" | sort -V | tail -n 1 || true)"
if [[ -n "${latest_this_month}" ]]
then
  patch="$((${latest_this_month##*.} + 1))"
else
  patch=0
fi
new_tag="${year}.${month}.${patch}"

newest="$(printf '%s\n%s\n' "${origin_tags}" "${new_tag}" | sed '/^$/d' | sort -V | tail -n 1)"
if [[ "${newest}" != "${new_tag}" ]]
then
  fail "${new_tag} would not be the newest tag because ${newest} exists; check the clock"
  exit 1
fi

echo "commit:  ${short_commit} $(git log -1 --format=%s "${commit}")"
echo "tag:     ${new_tag}"

if [[ "${mode}" == "dry-run" ]]
then
  echo "Dry run: no tag created."
  exit 0
fi

if git rev-parse --quiet --verify "refs/tags/${new_tag}" &>/dev/null
then
  fail "a local tag ${new_tag} already exists"
  exit 1
fi

git tag --annotate "${new_tag}" "${commit}" --message "x86MacBrew ${new_tag}

Released from ${INTEL_BRANCH} at ${short_commit}."

echo "Created local tag ${new_tag}. Review it, then publish it with:"
echo "  git push origin refs/tags/${new_tag}"
