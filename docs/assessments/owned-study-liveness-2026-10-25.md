# Local work during an owned study

An owned dispatcher widened the shell's running-work predicate beyond local
foreground work. That suppressed external findings probes and workspace-state
refreshes, delayed operator commands until study exit, blocked foreground origin
restoration and let a session-budget abort stop a separately metered study.
The [PR review](https://github.com/allsmog/Kuzushi/pull/344#issuecomment-6404955908)
identified these paths. Seven new regressions reproduce all seven affected
behaviors before the fix.

The shell now uses its existing local-work predicate for external refresh,
single-slot local tool dispatch, ready command draining and foreground completion.
Broad liveness remains for operator cancellation, exit and live-work chrome.
Shared prepared dispatch, explicit approval, runtime selection and the finite
study job list are unchanged. A separate operator-requested runtime-free tool
does not append work to the study.

Session-budget cancellation applies to local work. Operator Stop still reaches
the owned dispatcher, including after switching targets. The budget card and
footer distinguish stopping session work from requesting study Stop. Escape
restores inspection while the spending halt remains armed. There is no new
allowance, model fallback, implicit cap increase or accounting refund.

## Cancellation guidance

Native review exposed another defect: canceling before any job completed produced
the dispatcher's canonical `1 parked` cause, while the shell expected a literal
zero-completed count. It fell through to failure and source-repair advice.

The formatter now shares the actual nonzero state-count summary between its
allowance and operator-stop readers. Exact cause matching and terminal-state
checks remain. Mixed failures, new source errors and unavailable explanations
retain their existing failure treatment. Early Stop now explains saved partial
work, consumed attempts, unresolved spending and the globally valid report and
campaign commands.

## Verification

The initial seven lifecycle regressions all fail. They pass after the guard
correction, and the expanded budget-card sequence also passes. Sixty-eight
distinct focused checks cover refresh, watcher updates, draft return, Stop,
budget keys and advisory presentation. The separate early-cancellation regression
fails against the old formatter; all thirteen dispatcher-result checks pass
after correction. These are 81 distinct TUI checks. The accompanying dependency
inventory followup has nine passing Core integration checks.

TUI all-target Clippy, formatting and the workspace build pass. Final repository
summary and risk results are recorded separately with the draft. These checks
do not replace required hosted CI or independent review.

Sequential final J370 records **20 machine passes, zero failures and fourteen
authenticated live capture pairs**. Thirteen frozen programs and 6,671 source
inputs remain unchanged during execution. Native SHA-256:
`7ed780c8a087d57f9f9926b984a3f4ad94ceb4c4ab28577fd81ed47aa158d4cf`.

The owned fixture freezes one context job, one worker and one attempt. Its
two-call allowance protects one Review call. Exactly one intercepted request
waits without returning a model response. While it waits, an explicitly requested
local inventory completes and restores Logs. An independent headless importer
adds one clearly labeled synthetic observation. The shell refreshes without a
manual command while retaining its view and complete typed draft.

Operator Stop parks the same consumed attempt as canceled. One unresolved
reservation remains; no job or request is added. Both recorded dispatcher and
bridge processes are observed absent. The completed inventory and imported
observation persist. Idle controls then appear, and the existing unsaved-draft
confirmation requires an explicit exit choice before discarding the synthetic
draft. This followup changes no exit semantics.

Captures cover 40x12, 60x20, 80x24, 96x89, 120x36 and 160x48 in no-color mode.
All fourteen have matching requested and actual dimensions and no color SGR
codes. Eight inspected PNGs replay captured ANSI cells with Menlo and a chosen
dark background; they are not OS screenshots. All four current questions have
State, Intent, Honesty and Craft answers. Raw exit 4 remains `REVIEW_REQUIRED`
with four formal operator judgments pending.

## Retained failures and limits

The first two native attempts launched no dispatcher and reserved no request:
the first sent L in Prompt mode; the second batched Escape and L without observing
navigation. The unchanged harness's `nav-mode` helper supplies that observation.
The third inventory completed, but its new assertion expected the wrong plural.
Its original intercepted hold later expired as one consumed failed attempt.
Both recorded processes exited. A retained database copy preserves its final
ledger after direct post-exit read-only probes failed; the source bytes remain
unchanged. The fourth reached Stop but omitted the existing draft confirmation.

The fifth has 18 machine passes and no machine failures, but agent review rejects
its misleading early-cancellation advice. It is not a visual pass. The final
sixth run adds explicit positive and negative cancellation-message assertions.
All earlier failures, prompts and their source cuts remain recorded.

Local evidence: `scripts/devex/artifacts/study-liveness-20261025/`.
`native-attempt-6/` contains the current source and program manifests, receipts,
process-reaping evidence, four agent answers, provenance checks and cell replays.
Subsequent audit documentation is separate from the frozen product inputs.

This qualifies the named local scheduling and refresh paths with owned synthetic
data. It does not establish arbitrary parallel model work, every liveness caller,
all restart races, strict dollar enforcement, model usefulness or reference-level
UX. Legacy diagnostic chrome, narrow transcript density, mode discovery and
repeated exit wording remain polish gaps. No maturity tier or broad delivery
checkbox changes. There are zero new live provider requests; the sixteen-request
real experiment allowance remains exhausted.
