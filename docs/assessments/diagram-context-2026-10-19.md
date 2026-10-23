# Bounded context from diagram evidence

October 19, 2026. Draft on main, based on `a2a38eedf1`.

## Result

Diagram `g` now opens the existing context-study planner instead of selecting a
legacy leaf and dispatching `threat-model:build` directly. It binds the exact
displayed context and selected evidence files. The operator reviews one full
architecture draft, the model, source limits and shared allowance, then
separately approves and launches its fixed job. No discovery work is added.

The additive `sourcePaths` option accepts 1 to 256 literal relative files with
an exact, current `inheritedContextRef`. It rejects traversal, directories,
duplicates, symlinks, missing inventory membership, stale source and a competing
`scanScopeRef`. Membership remains within the inherited context's recorded
scope or file group. There is one tool-free synthesis and no model repair loop.
The result is a separate inactive model. The original and active model remain.

Its `fileContext` receipt distinguishes selected files, actual source excerpts,
omissions and inherited architecture. Later selected-text regeneration retains
the recorded files. The context browser compares explanatory text with the
exact inherited revision; this is not a complete structural diagram diff.

Back preserves the original diagram and parent study within the session.
Unsaved child inputs offer Stay or explicit Discard. Opening the job browser
retains that origin, and reopening the result restores it. Returning refreshes
the parent's durable accounting without replacing its draft settings. Restart
reads the recorded campaign and exact inactive result through history.

Public tool names and old accepted-group artifacts remain supported. The
legacy TUI leaf-selection helpers remain as test fixtures; their direct
hotkey route is replaced. No module implementation is retired by this change.
See [migration details](../../RELEASING.md#evidence-bound-architecture-context).

## Verification

- 163 distinct focused Rust checks pass across ten retained test logs.
  Coverage includes shared prepared dispatch, exact file selection, inheritance,
  source drift, no repair, no added preparation jobs, selected-text membership,
  recovery authentication, input ownership and context comparison.
- Workspace build, Core/TUI boundary lints, CRAP-risk proxy and all ten repository
  summary checks pass. The draft receipt is separate from the published clean
  receipt and remains unsigned.
- Final sequential tmux J339 records **46 machine passes, zero failures and
  three pending operator judgments**, with 43 text/ANSI capture pairs. It covers
  all six viewport sizes, every narrow plan page, explicit approval and launch,
  explanatory-text comparison, return to the original inactive Alpha context
  and five-pass parent draft, and no-color restart.
- Thirteen ANSI cell replays were inspected across the six sizes and result,
  comparison, origin and restart surfaces. These use Menlo 15 and a chosen dark
  background. They are not OS screenshots or reference-parity certification.

Final binary SHA-256:
`f6e665d355faf34a01a9fc0ed16a9592b0492fda60f7937457bc2d0c65ebb8a0`.
The runner verifies 6,365 repository inputs, 13 frozen programs and selected
system entry points before and after the journey. It does not authenticate
every installed dependency. No product source or runtime script changed during
the journey. Evidence documents added afterward are recorded separately.

The owned four-file fixture uses an intercepted request through the real
adapter with explicitly selected GPT-5.5 and medium reasoning. Every fetch is
intercepted, with no network fallback. The completed job consumes one synthetic
reservation under a nine-call allowance with two protected Review calls. An
independent SQLite backup confirms one work attempt, one settled reservation,
zero findings, zero review decisions and no unresolved or Review reservations.
File hashes and the exact active-context reference remain unchanged.
The fixture borrows an existing repository SHA and has a dirty working tree;
its files do not match that commit. The recorded tree hash binds the actual
fixture bytes. This journey does not qualify a two-SHA transition.

An earlier retained attempt completed its job but failed a stale UI assertion:
it expected `1 job(s)` while the current screen says `Jobs: 1`. Correcting that
assertion and capturing the remaining narrow pages required no product change.
There are two intercepted requests across the two attempts and **zero new live
provider requests**. The earlier live experiment total remains fourteen.

## Limits and remaining work

This verifies integration and operator controls, not live inference quality.
The three formal operator judgments remain open. The forms remain text-dense,
and this increment makes no claim of reference-level interaction quality.

At this checkpoint the exact-file build requires complete inventory enumeration. A
repository whose inventory stops early is refused even when some selected
files were enumerated. This is an honest but restrictive path for very large
repositories. Accepted-boundary context generation remains separately available;
supporting known selected members from a partial inventory with explicit
completeness receipts remains work for this shortcut. It must not widen scope
or imply complete repository coverage.

The [partial-inventory follow-up](partial-evidence-context-2026-10-19.md)
implements known-member selection, with wide-repository qualification still
blocked by the reproduced import persistence cost.

Original diagram evidence rows also retain their existing location formatting;
the new plan and result receipt quote literal paths. A complete structural
diagram comparison, broader module qualification, live generation usefulness
and full operator acceptance remain open. Delivery remains four locally
verified items and five open items.

## Retained local evidence

Ignored root: `scripts/devex/artifacts/diagram-context-20261019/`.

- `distinct-rust-checks.json`, `final-results.json`,
  `qualification-results.json` and `draft-receipt.json`.
- Final native: `attempt-2/native/J339/20261019-095925/J339/`.
- `attempt-2/J339-terminal.json`, `independent-artifact-check.json`,
  `independent-ledger.sqlite3`, `visual-review.json` and ANSI replays.
- Earlier attempt: `native/J339/20261019-095617/J339/`.

Raw artifacts are local evidence and are not included in the committed report.
