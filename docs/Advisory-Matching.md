---
last_review_date: "2026-09-10"
---

# Advisory Matching

`brew advisory-match` prepares candidate records for the [Homebrew advisory database](https://github.com/Homebrew/advisory-database).
It is an authoring tool, not the installed-package scanner provided by `brew vulns`.
Candidates still need [human review](https://github.com/Homebrew/advisory-database/blob/HEAD/CONTRIBUTING.md#reviewing-matched-candidates) before publication.

## Range accuracy and coverage

With history enabled, a candidate with a comparable current state and no reviewed range must have an affected interval that can be established from formula history.
This applies even when the current formula is known to be affected: knowing today's state does not establish when the affected range began.
An `introduced: "0"` boundary asserts that every earlier version is affected; it is not a marker for an unknown introduction.

Automatic matching deliberately favours range accuracy over coverage.
Unreadable or uncomparable history, disjoint affected intervals and affected and unaffected builds sharing a `pkg_version` can prevent a new record from being emitted.
The command warns and counts these as history-unavailable skips instead of inventing a boundary.
A skip does not mean the formula is unaffected, so an ingest run can omit a currently affected formula and is not evidence of complete vulnerability coverage.
Reviewers must establish the ranges and matching provenance together from upstream evidence and formula build history, then contribute the record manually.

A reviewed state override does not establish historical boundaries.
When its state disagrees with comparable upstream evidence, or the upstream evidence cannot be checked, a new range needs manual review.
Existing reviewed ranges are preserved rather than replaced with guessed introductions; range transitions and changed provenance still require their own checks.

## History options

`--new-history` requires `--output` and reuses existing reviewed ranges where possible; a successful replay does not independently verify those boundaries.
`--json` without `--output` has no existing reviewed records to reuse, so history checks still apply to new comparable candidates.
`--no-history` explicitly uses unverified zero/current-version boundaries for new ranges and cannot be combined with `--new-history`.
It is an unchecked authoring mode, not a way to validate a skipped candidate.
