#!/bin/bash
# Bootstrap the x86MacBrew client fork on a fresh Intel macOS installation.
# This remains opt-in until a clean-host installation test has passed.

set -euo pipefail

readonly CLIENT_REMOTE="https://github.com/x86MacBrew/brew.git"
readonly EXPECTED_BRANCH="x86macbrew-intel-2027"
readonly INSTALLER_COMMIT="8949852f785a3bacaba2a979d0790337950b0a4a"
readonly INSTALLER_SHA256="25548e1da7930c1563dbbe2cb05834a4131c4da09234540b6fdac812fda3c287"
readonly INSTALLER_URL="https://raw.githubusercontent.com/Homebrew/install/${INSTALLER_COMMIT}/install.sh"
readonly PREFIX="/usr/local"
readonly REPOSITORY="${PREFIX}/Homebrew"
readonly INTEL_LINE_MARKER="docs/X86MacBrew-Intel-Continuation.md"

usage() {
  printf '%s\n' \
    'usage: install-x86macbrew.sh [--dry-run | --experimental-install]' \
    '' \
    '--dry-run               Print the verified bootstrap plan without changing the host.' \
    '--experimental-install  Run the pinned upstream installer against the x86MacBrew' \
    '                        client remote on a fresh Intel macOS host only.' \
    '' \
    'The installer refuses to overwrite an existing /usr/local/Homebrew checkout.'
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

if [[ -e "${REPOSITORY}" && "${mode}" != "dry-run" ]]
then
  echo "Refusing to overwrite existing Homebrew checkout: ${REPOSITORY}" >&2
  echo "Use the documented migration path instead of this experimental bootstrap." >&2
  exit 2
fi

printf 'x86MacBrew experimental client bootstrap\n\n'
printf 'client remote:       %s\n' "${CLIENT_REMOTE}"
printf 'expected branch:     %s\n' "${EXPECTED_BRANCH}"
printf 'prefix:              %s\n' "${PREFIX}"
printf 'pinned installer:    %s\n' "${INSTALLER_COMMIT}"
printf 'installer SHA-256:   %s\n' "${INSTALLER_SHA256}"

# The pinned installer checks out the newest tag, not the default branch, and
# only after creating /usr/local/Homebrew. Check that tag before the host changes.
preflight="$(mktemp -d -t x86macbrew-preflight)"
installer=""
trap 'rm -rf "${preflight}" ${installer:+"${installer}"}' EXIT HUP INT TERM

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
  git -C "${preflight}" fetch --quiet --depth 1 "${CLIENT_REMOTE}" \
    "refs/tags/${latest_tag}:refs/tags/${latest_tag}"
  if git -C "${preflight}" cat-file -e "${latest_tag}:${INTEL_LINE_MARKER}" 2>/dev/null
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

installer="$(mktemp -t x86macbrew-install)"

curl --fail --location --proto '=https' --tlsv1.2 --output "${installer}" "${INSTALLER_URL}"
actual_sha="$(shasum -a 256 "${installer}" | awk '{print $1}')"
if [[ "${actual_sha}" != "${INSTALLER_SHA256}" ]]
then
  echo "Pinned Homebrew installer checksum mismatch." >&2
  echo "expected: ${INSTALLER_SHA256}" >&2
  echo "actual:   ${actual_sha}" >&2
  exit 1
fi

export HOMEBREW_BREW_GIT_REMOTE="${CLIENT_REMOTE}"
/bin/bash "${installer}"

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

git -C "${REPOSITORY}" remote set-head origin --auto >/dev/null
actual_head="$(git -C "${REPOSITORY}" symbolic-ref --short refs/remotes/origin/HEAD)"
if [[ "${actual_head}" != "origin/${EXPECTED_BRANCH}" ]]
then
  echo "Installed client default branch differs from ${EXPECTED_BRANCH}: ${actual_head}" >&2
  exit 1
fi

"${PREFIX}/bin/brew" --version
echo "x86MacBrew experimental bootstrap completed. Run brew update, then tap x86macbrew/x86mac."
