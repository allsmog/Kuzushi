# Committed-path review without finding pollution

`chrome-rce:review-trigger` now answers a Map question: which committed paths
match recorded review patterns? The earlier implementation inserted medium/high
vulnerability observations from filenames and recorded completed Scan work.
A shared-dispatch regression reproduced that behavior on inert owned paths.
The action now emits unverified `reviewHints`, with empty `findings`, null
`persisted` and an explicit `countKind`. It writes no finding run or decision,
accepts no context and creates no scan job. Historical observations remain.

The descriptor is auxiliary Labs Map/read work without a phase result or
required finding store. Its old scanner dependency is removed. Exact dispatch
and the optional `diffBase` input remain. Public consumers that used path-derived
findings must migrate to `reviewHints`; compatible fields and saved histories
remain readable. The obsolete private path-to-finding constructor was removed
because it no longer has a production consumer. All seven path-match rules and
stable rule identifiers remain, without severity or guessed line-one evidence.
No module implementation is retired.

## Git identity and bounds

The result distinguishes the requested base commit, the actual merge base and
the compared HEAD. It compares pinned merge-base and HEAD commits, then checks
that HEAD has not moved. Dirty, staged and untracked content is explicitly
excluded. The operation reads path names, not source bodies; a changed path
establishes neither a vulnerability verdict nor a fix at another SHA.

Git output uses NUL framing and strict UTF-8 decoding. Newlines and whitespace
inside names are preserved, and displayed names are quoted. Nested targets
restrict path membership while repository prefixes preserve pattern matching.
Invalid references, ambiguous merge bases, escaping paths, malformed output,
capture overflow, cancellation and expired deadlines fail honestly. The process
removes inherited Git target steering, disables filesystem-monitor hooks,
external diff/text conversion, optional locks and remote transport.

Shared descriptor options are `maxChangedFiles` (default 1,000),
`maxGitOutputBytes` (default 1 MiB) and `gitTimeoutMs` (default 30,000).
The deadline is shared across the complete comparison. Retained path limits
produce partial results, including a zero-hint result whose omitted paths may
contain matches. Output previews show at most 32 hints and 32 retained paths,
with disclosure; complete retained lists stay in result data. Very large result
reading and every cancellation race remain unqualified.

## Excluded work and stage routing

The source audit establishes that `systems-hunt:systems-trigger-synth` requests
ordered attacker actions, boundary assignments and expected primitives. The
bundled `systems-hunt:systems-hunt` executes that trigger stage between its
invariant and finding stages. Both are excluded from this agreed source-only
investigation. They were not executed, repaired or qualified. Their exact public
dispatch paths remain, with legacy bundle selection requiring exact opt-in;
they are not default-enabled shell scan tasks.

The audit also found that standalone context, invariant and deep-discovery
stage names used as `sast:scan tasks` silently selected that larger bundle.
The regression reproduces this in pure selection without executing any stage.
Shared preparation now rejects those deprecated values before model or finding
store requirements, rather than widening the requested work. Runtime planning
uses the same stage classification. Exact standalone tool names remain and
canonical legacy bundle names retain their explicit identity. Saved plans are
not rewritten; replacement work needs a separately planned exact action.

The internal audit now has zero unknown source-only boundaries. Two in-scope
hidden Core actions still need complete functional qualification: UAF and the
bounded systems context producer. The count change reflects scope exclusion
and Labs curation, not newly proven engine quality. All nine broad delivery
milestones remain open.

## Per-action evidence

| Dimension | Evidence and limits |
| --- | --- |
| Purpose | Model-free committed-path prioritization for later source review. Filename matching produces no vulnerability opinion. |
| Phase | Auxiliary Labs Map/read descriptor; no primary phase result or scanner prerequisite. |
| Inputs | Explicit repository target, optional Git base and declared file/output/deadline limits. No model, credentials or accepted context is needed. Accepted discovery scopes are unsupported. |
| Execution | Shared prepared dispatch and real bounded Git adapter. New stage-alias rejection uses the same task selection consumed by study preview, runtime policy and execution. |
| Outputs | Exact comparison identities, selected-target path membership, review hints, retained/omitted counts and honest completed/partial/skipped/failed outcomes. No ledger finding write. |
| Failure | Missing/invalid baseline, malformed path framing/encoding, path escapes, cancellation, capture bounds and zero-hint partial results have focused checks. Crisscross-history and every branch-switch race remain unqualified. |
| Resources | One shared Git deadline with explicit stdout/stderr bounds and cancellation. Zero provider requests and no automatic source scan or follow-up job. |
| Interfaces | Canonical descriptor options and shared prepared dispatch; CLI and shell expose the same result. Source-only stage names cannot become a larger engine through task aliases. |
| Value | Owned divergent Git history checks make the compared SHAs and excluded working tree understandable. Broad path-pattern usefulness, large-repository performance and operator UX acceptance remain open. |

## Verification

Evidence is retained in `/tmp/kuzushi-changed-path-review-20261017`:

- All 59 focused Rust checks and the workspace build pass. The risk gate passes
  for 457 changed code files, including its 15 proxy checks. All ten repository
  summary gates pass. The receipt honestly records a dirty draft; it is not a
  clean signed publication receipt.
- Fresh linked production registry evidence has 189 registered actions and 118
  visible tools. Only `chrome-rce:review-trigger` changes descriptor facts. The
  visible catalog remains 81 Core, 32 Labs and five Compatibility entries.
  The reviewed policy tuple changes only that action to Map/read/optional
  findings; source, unit and native checks separately prove prerequisite removal.
- Final sequential J327/J279 have 54 machine passes, zero failures and 59 live
  capture pairs at 120x36, 160x48, 96x89, 80x24, 60x20 and 40x12. Three J327 and
  five J279 human judgments remain `REVIEW_REQUIRED`. All source/runtime inputs
  and six frozen programs are unchanged before and after both journeys.
- J327 uses owned divergent Git history whose requested base differs from the
  actual merge base. Exact paths, nested target membership, missing/invalid
  baseline, stage-alias refusal, partial path limits, no-color restart and zero
  observation/decision/reservation writes are checked. Source bytes, HEAD and
  Git status stay unchanged; this is not a claim about every Git metadata byte.
- All 45 narrow Result rows are reached across 14 capture pages. Fourteen of 59
  generated ANSI cell replays were visually inspected: all six comparison
  sizes, partial start/tail, no-color recovery and zero-call approval/report.
  These are terminal-cell replays, not OS screenshots or formal human signoff.
- J279 retains three completed local discovery jobs, six raw observations, two
  human FP decisions, an explicit zero-provider-call ceiling, export and restart.
  Neither journey uses real or intercepted model transport or executes target
  source. It establishes bounded local behavior, not model usefulness.

The finding-pollution and stage-expansion regressions are retained. A response
builder exceeded the risk gate's line limit and was split. Initial option-type
and obsolete severity-test compile errors are retained. The first native setup
assumed no fixture Git directory, although the harness initializes one; a later
restart assertion expected a wide heading at 40 columns. Both fixture mistakes
were corrected and the final pair rerun. No validation gate was bypassed.

The visual review finds readable hint/finding counts and explicit partial output.
Narrow chrome still leaves only five content rows. Repeated path explanations
add density, and the Report footer emphasizes historical severity after human
FP decisions. Complete path-pattern usefulness, large histories, human UX and
reference parity remain open. The original 366-file publication proposal and
primary staged patch remain separate and unchanged.

The work remains a draft on `main`. There is no project commit, push or new
live-model request. Fourteen historical live requests remain spent, with no
remaining live allowance. The complete investigation and reference-level TUI
experience remain unqualified.
