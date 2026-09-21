#!/bin/bash
# Bootstrap the x86MacBrew client on a fresh Intel macOS installation.

set -euo pipefail

readonly CLIENT_REMOTE="https://github.com/x86MacBrew/brew.git"
readonly EXPECTED_BRANCH="x86macbrew-intel-2027"
readonly RELEASE_TAG_PATTERN='^20[0-9][0-9]\.(1[0-2]|[1-9])\.[0-9]+$'
readonly PREFIX="/usr/local"
readonly REPOSITORY="${PREFIX}/Homebrew"
readonly BREW_LINK="${PREFIX}/bin/brew"
readonly INTEL_LINE_MARKER="docs/X86MacBrew-Intel-Continuation.md"

usage() {
  printf '%s\n' \
    'usage: install-x86macbrew.sh [--dry-run | --experimental-install]' \
    '' \
    '--dry-run               Print the verified bootstrap plan without changing the host.' \
    '--experimental-install  Install the verified x86MacBrew client release on a' \
    '                        fresh Intel macOS host only.' \
    '' \
    'The installer refuses to overwrite an existing Homebrew checkout or brew link.'
}

mode="dry-run"
case "${1:---dry-run}" in
  --dry-run) ;;
  --experimental-install) mode="experimental-install" ;;
  --help | -h)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 64
    ;;
esac

if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "x86_64" ]]
then
  echo "x86MacBrew bootstrap requires an Intel macOS host." >&2
  exit 1
fi

if [[ ( -e "${REPOSITORY}" || -e "${BREW_LINK}" || -L "${BREW_LINK}" ) && \
      "${mode}" != "dry-run" ]]
then
  echo "Refusing to overwrite existing Homebrew files in ${PREFIX}." >&2
  echo "Use the documented migration path instead of this experimental bootstrap." >&2
  exit 2
fi

printf 'x86MacBrew experimental client bootstrap\n\n'
printf 'client remote:       %s\n' "${CLIENT_REMOTE}"
printf 'expected branch:     %s\n' "${EXPECTED_BRANCH}"
printf 'prefix:              %s\n' "${PREFIX}"
printf 'bootstrap:           x86MacBrew-owned Git bootstrap\n'

# Homebrew selects the newest release tag after it has created the prefix, so
# verify that tag before the x86MacBrew bootstrap changes the host.
preflight="$(mktemp -d "${TMPDIR:-/tmp}/x86macbrew-preflight.XXXXXX")"
trap 'rm -rf "${preflight}"' EXIT HUP INT TERM

if ! remote_tags="$(git ls-remote --tags --refs "${CLIENT_REMOTE}")"
then
  echo "Could not reach ${CLIENT_REMOTE} to inspect its tags." >&2
  exit 1
fi
# `tail` reads all input; `head` can close the pipe early and fail under pipefail.
latest_tag="$(awk -F'refs/tags/' 'NF > 1 { print $2 }' <<<"${remote_tags}" | sort -V | tail -n 1)"

if [[ -z "${latest_tag}" ]]
then
  tag_state="none"
  printf 'release tag:         none published\n'
else
  git -C "${preflight}" init --quiet
  git -C "${preflight}" fetch --quiet --filter=blob:none "${CLIENT_REMOTE}" \
    "refs/heads/${EXPECTED_BRANCH}:refs/remotes/origin/${EXPECTED_BRANCH}" \
    "refs/tags/${latest_tag}:refs/tags/${latest_tag}"
  if [[ "${latest_tag}" =~ ${RELEASE_TAG_PATTERN} ]] &&
     git -C "${preflight}" merge-base --is-ancestor "${latest_tag}" \
     "refs/remotes/origin/${EXPECTED_BRANCH}" &>/dev/null &&
     git -C "${preflight}" cat-file -e "${latest_tag}:${INTEL_LINE_MARKER}" &>/dev/null
  then
    tag_state="intel-line"
    printf 'release tag:         %s\n' "${latest_tag}"
  else
    tag_state="not-intel-line"
    printf 'release tag:         %s (not an x86MacBrew release)\n' "${latest_tag}"
  fi
fi

if [[ "${mode}" == "dry-run" ]]
then
  printf '%s\n' \
    '' \
    'Dry run only. Nothing on this host was installed or changed; the remote' \
    'was read to find the release tag the installer would check out.' \
    'Use --experimental-install only on a fresh Intel macOS host after reviewing' \
    'the support policy. A clean-host validation has not yet been recorded.'
  exit 0
fi

case "${tag_state}" in
  intel-line) ;;
  none)
    echo "Refusing to install: ${CLIENT_REMOTE} has no release tag yet." >&2
    echo "The pinned installer would download the client into ${REPOSITORY}," >&2
    echo "then abort, leaving a partial checkout that blocks a retry." >&2
    exit 3
    ;;
  *)
    echo "Refusing to install: the newest tag, ${latest_tag}, is not an x86MacBrew" >&2
    echo "release, so installing and brew update would both follow it." >&2
    exit 3
    ;;
esac

if ! /usr/bin/xcode-select -p >/dev/null
then
  echo "Xcode Command Line Tools are required before bootstrap." >&2
  exit 1
fi

if ! /usr/bin/sudo -v
then
  echo "Administrator access is required to create ${PREFIX}." >&2
  exit 1
fi

owner="$(/usr/bin/id -un)"
group="$(/usr/bin/id -gn)"
prefix_directories=(
  bin Cellar Caskroom Frameworks etc include lib opt sbin share var
  var/homebrew var/homebrew/linked var/log
)

for directory in "${prefix_directories[@]}"
do
  /usr/bin/sudo /bin/mkdir -p "${PREFIX}/${directory}"
  /usr/bin/sudo /usr/sbin/chown "${owner}:${group}" "${PREFIX}/${directory}"
done

/usr/bin/sudo /bin/mkdir -p "${REPOSITORY}"
/usr/bin/sudo /usr/sbin/chown "${owner}:${group}" "${REPOSITORY}"

git -C "${REPOSITORY}" init --quiet
git -C "${REPOSITORY}" config remote.origin.url "${CLIENT_REMOTE}"
git -C "${REPOSITORY}" config remote.origin.fetch '+refs/heads/*:refs/remotes/origin/*'
git -C "${REPOSITORY}" config fetch.prune true
git -C "${REPOSITORY}" config core.autocrlf false
git -C "${REPOSITORY}" config core.symlinks true
git -C "${REPOSITORY}" fetch --quiet --force origin
git -C "${REPOSITORY}" fetch --quiet --force --tags origin
git -C "${REPOSITORY}" remote set-head origin --auto >/dev/null

installed_tag="$(git -C "${REPOSITORY}" tag --list --sort=-version:refname | head -n 1)"
if [[ "${installed_tag}" != "${latest_tag}" ]]
then
  echo "The available x86MacBrew release changed during bootstrap." >&2
  echo "Run the installer again to review the new release tag." >&2
  exit 1
fi

git -C "${REPOSITORY}" checkout --quiet --force -B stable "${installed_tag}"
/usr/bin/sudo /bin/ln -s "../Homebrew/bin/brew" "${BREW_LINK}"

actual_remote="$(git -C "${REPOSITORY}" remote get-url origin)"
if [[ "${actual_remote}" != "${CLIENT_REMOTE}" ]]
then
  echo "Installed client remote differs from x86MacBrew: ${actual_remote}" >&2
  exit 1
fi

if ! git -C "${REPOSITORY}" cat-file -e "HEAD:${INTEL_LINE_MARKER}" 2>/dev/null
then
  echo "Installed client is not an x86MacBrew release:" >&2
  echo "  checked out $(git -C "${REPOSITORY}" describe --tags --always HEAD 2>/dev/null)" >&2
  exit 1
fi

actual_head="$(git -C "${REPOSITORY}" symbolic-ref --short refs/remotes/origin/HEAD)"
if [[ "${actual_head}" != "origin/${EXPECTED_BRANCH}" ]]
then
  echo "Installed client default branch differs from ${EXPECTED_BRANCH}: ${actual_head}" >&2
  exit 1
fi

HOMEBREW_NO_ANALYTICS=1 "${BREW_LINK}" update --force --quiet
"${BREW_LINK}" --version
echo "x86MacBrew experimental bootstrap completed. Run brew update, then tap x86macbrew/x86mac."
