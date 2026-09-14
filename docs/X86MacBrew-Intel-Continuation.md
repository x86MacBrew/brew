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

The actual `--experimental-install` path has not yet passed a clean-host
installation test. It is not the published migration path and must not be
presented as a production installer until that evidence exists.

## Default branch is part of the update contract

Homebrew's updater follows `refs/remotes/origin/HEAD`, which GitHub sets from
the repository's default branch. Therefore, once this baseline has been
reviewed and merged, the `x86MacBrew/brew` GitHub default branch **must** be
`x86macbrew-intel-2027`, not `main`.

`main` remains the reviewed upstream-tracking branch. Making it the GitHub
default would cause a normal `brew update` in a cloned Intel client to check
out `main` and abandon the maintained Intel branch. A disposable public-clone
test on 2026-09-11 verified that setting `origin/HEAD` to the maintained branch
preserves that branch across `brew update`.

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
