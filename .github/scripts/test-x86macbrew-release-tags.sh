#!/bin/bash
set -euo pipefail

release_script="$(cd "$(dirname "$0")/../.." && pwd)/tag-x86macbrew-release.sh"
fixture=$(mktemp -d)
trap 'rm -rf "${fixture}"' EXIT
# Isolate signing, hooks and identity from the maintainer's configuration.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=Test GIT_COMMITTER_NAME=Test
export GIT_AUTHOR_EMAIL=test@example.invalid GIT_COMMITTER_EMAIL=test@example.invalid
git init --quiet --bare "${fixture}/origin.git"
git init --quiet "${fixture}/seed"
cd "${fixture}/seed"
git checkout --quiet -b x86macbrew-intel-2027
mkdir docs
echo baseline >docs/X86MacBrew-Intel-Continuation.md
git add docs
git commit --quiet -m baseline
first_commit=$(git rev-parse HEAD)
echo next >>docs/X86MacBrew-Intel-Continuation.md
git commit --quiet -am next
git remote add origin "${fixture}/origin.git"
git push --quiet origin x86macbrew-intel-2027

expect_failure() {
  local message=$1
  shift
  if /bin/bash "${release_script}" "$@" >"${fixture}/result" 2>&1
  then
    echo "FAIL: unexpectedly accepted ${message}" >&2
    exit 1
  fi
  grep -F "${message}" "${fixture}/result"
}

/bin/bash "${release_script}" --verify
/bin/bash "${release_script}" --dry-run
test -z "$(git tag --list)"
git checkout --quiet --orphan unrelated
git commit --quiet -m unrelated
git tag 2020.1.0
git push --quiet origin refs/tags/2020.1.0
git checkout --quiet x86macbrew-intel-2027
expect_failure 'not an x86MacBrew commit on' --verify
expect_failure 'not an x86MacBrew commit on' --dry-run
git push --quiet origin :refs/tags/2020.1.0
git tag -d 2020.1.0 >/dev/null
git tag 2020.1.0
git push --quiet origin refs/tags/2020.1.0
expect_failure 'would roll back release' --dry-run "${first_commit}"
expect_failure 'already released as' --dry-run
echo newer >>docs/X86MacBrew-Intel-Continuation.md
git commit --quiet -am newer
git push --quiet origin x86macbrew-intel-2027
/bin/bash "${release_script}" --dry-run
test "$(git tag --list | wc -l | tr -d ' ')" = 1
echo 'PASS: release tag ancestry, rollback and dry-run checks'
