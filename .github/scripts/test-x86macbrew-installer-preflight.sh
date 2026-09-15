#!/bin/bash
set -euo pipefail

installer="$(cd "$(dirname "$0")/../.." && pwd)/install-x86macbrew.sh"
fixture=$(mktemp -d)
trap 'rm -rf "${fixture}"' EXIT

export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=Test GIT_COMMITTER_NAME=Test
export GIT_AUTHOR_EMAIL=test@example.invalid GIT_COMMITTER_EMAIL=test@example.invalid

mkdir "${fixture}/bin"
cat >"${fixture}/bin/uname" <<'EOF'
#!/bin/bash
case "$1" in
  -s) echo Darwin ;;
  -m) echo x86_64 ;;
  *) /usr/bin/uname "$@" ;;
esac
EOF
chmod +x "${fixture}/bin/uname"
export PATH="${fixture}/bin:${PATH}"

git init --quiet --bare "${fixture}/origin.git"
test_installer="${fixture}/install-x86macbrew.sh"
sed "s|https://github.com/x86MacBrew/brew.git|${fixture}/origin.git|" "${installer}" >"${test_installer}"
chmod +x "${test_installer}"
git init --quiet "${fixture}/seed"
cd "${fixture}/seed"
git checkout --quiet -b x86macbrew-intel-2027
mkdir docs
echo baseline >docs/X86MacBrew-Intel-Continuation.md
git add docs
git commit --quiet -m baseline
git remote add origin "${fixture}/origin.git"
git push --quiet origin x86macbrew-intel-2027

run_installer() {
  /bin/bash "${test_installer}" --dry-run >"${fixture}/result" 2>&1
}

assert_output() {
  grep -F "$1" "${fixture}/result"
}

run_installer
assert_output 'release tag:         none published'

git tag --annotate 2026.9.0 --message release
git push --quiet origin refs/tags/2026.9.0
run_installer
assert_output 'release tag:         2026.9.0'

git checkout --quiet --orphan unrelated
git rm --quiet -r -f .
mkdir docs
echo unrelated >docs/X86MacBrew-Intel-Continuation.md
git add docs
git commit --quiet -m unrelated
git tag --annotate 2027.1.0 --message unrelated
git push --quiet origin refs/tags/2027.1.0
run_installer
assert_output 'release tag:         2027.1.0 (not an x86MacBrew release)'

echo 'PASS: installer only accepts Intel-line release tags'
