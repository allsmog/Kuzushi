# Study-local engine selection

October 5, 2026. The engine selector is implemented and locally verified on
`5dcaa600ebb4ef50548ad713e56716218bb380e1` with uncommitted implementation work.
The complete investigation plan remains in progress.

## Behavior

The study form exposes Discovery engines before Source and context. Its picker
projects the existing SAST tasks and the executor's accepted-file scope contract.
It explains unsupported choices without replacing engines, models or scopes.
Automatic selection remains explicit; selecting a supported engine deliberately
switches the local draft to manual selection. Unknown saved engines remain
removable. Arrows select, Space/Enter toggles, `a` applies and Esc cancels.

Changed choices invalidate only the immutable study draft. Source/context
references, custom scan options, investigation identity, limits and consumed
allowance remain intact. Global stored options are untouched. Identical choices
retain the saved plan. Input task order is preserved; execution keeps existing
orchestration ordering. Selection starts no jobs or model requests.

Wide terminals use a bounded list/detail layout. Narrow terminals stack a short
list above a pageable explanation, with a visible reading range and permanent
apply/cancel controls. Reasons precede descriptions. The picker owns paste and
does not mutate the hidden composer. Plain output lists every engine and the
selected explanation. Background work still uses existing input ownership.

## Verification

- Eight focused selector tests pass, including cancellation, scope/context/custom
  option preservation, retained limits, task order, identical selection, unknown
  saved engines, paste ownership, six render sizes and full narrow-screen paging.
- The wider study regression run passed 54 tests before the final copy cleanup;
  all eight selector tests passed again after it.
- Two shared core planning tests pass. Accepted-file capability preview uses the
  executor contract without reading an absent scope artifact and rejects unknown
  task names and conflicting path input.
- Workspace build passes. The CRAP-risk proxy passes 239 changed code files.
- Quick summary verification passes all ten gates, recorded at
  `.git/bounded-investigations/study-engine-final-verification.json`, finished
  `2026-10-06T01:09:19.478Z`. The receipt explicitly records dirty source and a
  conservative drift flag. It excludes full CI, cross-platform checks and live
  provider validation. This verification precedes the documentation closeout.
- J84 at `/tmp/kuzushi-bounded-investigations-tui/20261005-180208/J84/` passes
  29 machine checks and eight separately recorded screen judgments. Text, ANSI,
  dimensions and native binary hashes are recorded in `manual-review.json`.
  The raw harness remains `REVIEW_REQUIRED`.
- Native binary SHA-256 is
  `aff27833a281c57f50a694830869f797aaa539b650a7959b6bc3edf4100482b1`.
  The journey captures that same binary at 40x12, 60x20, 80x24, 96x89, 120x36
  and 160x48, reaches the final resource guidance and restores the exact saved
  plan after actual exit and a no-color restart. No discovery or provider work
  starts. The fixture is an unversioned source tree; SHA transitions and
  finding/decision comparisons are not exercised here.

Earlier failed runs and judgments remain at `20261005-174109/J84`,
`20261005-175448/J84` and `20261005-175737/J84` under the same artifact root.
They retain the narrow-screen reading defect and driver mistakes involving idle
exit, the saved-study command and a reversed count phrase. Existing study
journeys now account for the added form row; they were not all rerun here.

## Audit and limits

The audit inventory now matches all 97 non-hidden operator-visible tools from
the rebuilt binary, including the previously missing `threat-model:diff`.
Descriptor facts are separate from nine pending outcome dimensions per tool.
Missing serialized runtime declarations are marked unknown. This is a registry
inventory update. Functional verdicts and retirement evidence remain unfinished.
Internal hidden nodes still need separate execution evidence.

The picker preview authenticates neither source nor dependencies, credentials,
useful outputs or allowance. Prepared dispatch remains the admission boundary.
Accepted logical scopes currently permit exact Secret/Semgrep discovery only.
Legacy directory/path constraints still require final prepared validation;
conflicting saved path filters now have an explicit study-local repair. Its
native recovery evidence is tracked separately in the
[scope-filter assessment](scope-filter-recovery-2026-10-05.md).
Multi-scope jobs, scoped model sessions, inherited scanner context, useful engine
defaults, complete resource estimates, experiments and reviewed lessons remain
unfinished. Full interaction parity with the reference terminal assistants and
live model validation remain open.
