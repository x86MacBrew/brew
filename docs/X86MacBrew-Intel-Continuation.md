# X86MacBrew Intel Client Continuation

This branch is part of **x86MacBrew**, an independent community project that
continues Homebrew-compatible developer tooling for Intel Macs. It is not
maintained by, endorsed by, or an official release of Homebrew.

The goal is to retain familiar `brew` commands and workflows while maintaining
only the Intel compatibility boundaries that upstream no longer supports.
This repository remains a fork of `Homebrew/brew` and keeps changes small,
reviewable and attributable to their upstream base.

## Tested baseline

| Item | Value |
| --- | --- |
| x86MacBrew client branch | `baseline/intel-macos15-2026-09-11` |
| Upstream base | `Homebrew/brew` commit `088d2f79849d1b08792459b65026207a91c545d6` |
| Reported client version | `6.0.22-295-g088d2f7` |
| Architecture | Intel `x86_64` (Broadwell) |
| macOS | 15.7.7 |
| Command Line Tools | 26.3.0.0.1.1769666919 |
| Apple Clang | 17.0.0, build 1700.6.4.2 |

On 2026-09-11, a fresh isolated checkout of this client successfully ran:

```sh
brew config
brew update
brew tap x86MacBrew/x86Mac
brew install x86MacBrew/x86Mac/x86macbrew-doctor
brew upgrade x86MacBrew/x86Mac/x86macbrew-doctor
x86macbrew-doctor --json
```

The doctor reported four passing checks: `x86_64` architecture, macOS major
version 15, `/usr/local` as the normal Homebrew prefix, and the SSSE3 CPU
baseline.

This is a compatibility baseline, not a promise that every formula, cask, or
future macOS version is supported.

## Experimental bootstrap prototype

`install-x86macbrew.sh` pins a reviewed `Homebrew/install` revision, verifies
its checksum and points a fresh Intel macOS installation at the x86MacBrew
client remote. It defaults to `--dry-run` and refuses to overwrite an existing
`/usr/local/Homebrew` checkout.

The pinned installer checks out the newest release tag, and only after it has
created `/usr/local/Homebrew`, so the script checks that tag first. It refuses
when there is no release tag or when the newest tag is not an x86MacBrew
release, before anything on the host changes.

The actual `--experimental-install` path has not yet passed a clean-host
installation test. It is not the published migration path and must not be
presented as a production installer until that evidence exists.

## How `brew update` chooses a revision

For non-developer users, `brew update` sets `HOMEBREW_UPDATE_TO_TAG` and moves
to the newest tag matching `X.Y.Z`. It follows `refs/remotes/origin/HEAD` only
when no such tag exists. The pinned Homebrew installer also checks out the
newest tag and aborts when there is none.

The GitHub default branch must still be `x86macbrew-intel-2027`, which covers
clones that have no release tag. Once release tags exist, they decide what
normal users receive.

## Release tags

x86MacBrew releases are tagged `YYYY.M.PATCH` on `x86macbrew-intel-2027`, for
example `2026.9.0`.

- The version sorts above every upstream Homebrew version, so if upstream tags
  ever reach this fork, `brew update` and the installer still select the
  x86MacBrew release.
- It is a plain `X.Y.Z` tag, because `brew update` ignores tags with a fourth
  component.
- `brew --version` reports it, for example `Homebrew 2026.9.0`.

Create a release with `./tag-x86macbrew-release.sh`. It tags
`origin/x86macbrew-intel-2027` locally and prints the command to push it. It
refuses a commit that is already released or is not on the Intel line, and it
never pushes.

Release tags must be annotated. `2026.9.0` is a fixed legacy exception because
the GitHub release form created it as a lightweight tag; do not rewrite that
published tag.

`.github/workflows/x86macbrew-tag-guard.yml` runs the script with `--verify` on
every tag push, every push to `x86macbrew-intel-2027` and once a day. It fails
if any tag on this fork is not a `YYYY.M.PATCH` release on the Intel line.

Never run `git push --tags` from a clone that also fetches `Homebrew/brew`. It
would publish upstream's tags to this fork.

## Branch roles

| Branch | Role |
| --- | --- |
| `main` | Tracks the reviewed upstream client baseline as closely as practical. |
| `x86macbrew-intel-2027` | Holds the maintained Intel client line once x86MacBrew needs compatibility changes. |
| `baseline/*` | Records a tested upstream candidate and the evidence used to review an Intel sync. |

Before moving `x86macbrew-intel-2027` forward, maintainers must test the
candidate branch on a supported Intel host. A client sync must not be released
solely because it merges cleanly.

## Required client checks

At minimum, each client baseline must prove these workflows in an isolated
Intel prefix:

```sh
brew config
brew update
brew tap x86MacBrew/x86Mac
brew install x86MacBrew/x86Mac/x86macbrew-doctor
brew upgrade x86MacBrew/x86Mac/x86macbrew-doctor
x86macbrew-doctor --json
```

When a supported formula exists, the baseline also needs a source install,
formula test, and runtime smoke test. Bottle releases add a separate clean-host
installation requirement.

## Manual builder workflow

`.github/workflows/x86macbrew-intel-baseline.yml` is intentionally manual. It
runs only on a dedicated runner labelled `self-hosted`, `macos`, `x86_64`, and
`x86macbrew-builder`, then captures `brew config` and the doctor JSON result as
workflow artifacts.

Do not add a `pull_request` trigger to this workflow. A self-hosted Intel
builder is a release-adjacent machine, so only a maintainer should dispatch a
reviewed client revision onto it.

## Support boundary

x86MacBrew currently distributes a diagnostic tool from its stable tap and
keeps other formulae on experimental candidate branches until their promotion
requirements are met. It does not claim broad Homebrew formula parity, cask
parity, Intel bottles, or support for closed-source applications whose vendors
no longer provide Intel binaries.

See the distribution-tap policy and package status in
[`x86MacBrew/Homebrew-x86Mac`](https://github.com/x86MacBrew/Homebrew-x86Mac).

## Future compatibility patches

Do not add speculative Intel patches. When upstream removes an Intel code path
or an upstream change breaks the tested baseline, the x86MacBrew patch must:

1. reference the upstream change that caused the regression;
2. preserve familiar `brew` behavior where possible;
3. include an Intel reproduction and regression test;
4. document its macOS and CPU applicability; and
5. be reviewed and released with the exact client base revision.

If x86MacBrew eventually replaces an upstream unsupported-platform message,
the replacement must state x86MacBrew's independent support policy clearly. It
must not imply ongoing official Homebrew support.
