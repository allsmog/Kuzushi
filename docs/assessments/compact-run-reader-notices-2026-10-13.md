# Compact saved-run reading with notices

At 40x12 a retained warning or error occupied three rows and the embedded
transcript occupied another. Replay's first frame could show its heading without
the recorded outcome. The operator had to dismiss a notice before assessing the
run it described. Three regression tests reproduce that behavior before repair.

Saved-run readers now reserve one row for notices at heights up to 12 and omit
the redundant transcript strip. Replay, Trace, failure handoff and run comparison
share this rule. Their ordinary short frame retains at least six primary rows.
The notice keeps its severity, dismissal action and route through the palette to
Logs. Its full stored message is unchanged. Larger frames retain the existing
preview, and approval/budget input ownership remains unchanged.

The change is presentation only. It does not dismiss alerts, alter run receipts,
move focus, clear the composer, switch models or change shared dispatch. Gallery
notice behavior remains the same. Logs retains its existing preview policy.

## Verification

Fifty-seven distinct focused Rust tests pass across notice rendering, reader
geometry and paging, input ownership, budget/advisory projections and full-message
access. The three new regressions pass after the fix. The locked workspace build
and CRAP-risk proxy over 505 changed code files pass. The full Rust suite was not
run for this increment.

All ten exact quick-plan commands pass, including 391 Node tests, workspace
checking, architecture/model-safety contracts and the changed-code risk proxy.
They ran directly without disabling the pinned package-manager signature check.

Final sequential J234 records 17 machine passes, no failures and 19 live text/ANSI
capture pairs across six sizes and no-color restart. At 40x12, failed and partial
outcomes appear on the first frame with their notices still present. The failed
frame also begins its recorded cause. The partial frame discloses unknown cost.
The route through the palette to Logs preserves a typed draft and its editing
position, proven by inserting a character three positions before the end after
navigation. Both original metadata-import receipts survive restart unchanged.
There are no model requests, source executions, findings or new phase attempts.

Native SHA-256:
`ed4642c8b023aac8b29649bff9e74da7f067335d56bac12c4db9d35418a57da3`.
Captures:
`/tmp/kuzushi-tui-integration-20261012/compact-reader-notice-final-tui/20261013-083825/J234`.
Tests, retained failures and assistant screen review:
`/tmp/kuzushi-tui-integration-20261012/compact-reader-notice-audit`.

An intermediate compile failed because the renamed helper lacked its internal
re-export; that result is retained. The first native cursor check incorrectly
compared hidden terminal-cursor coordinates. Kuzushi renders a block cursor in
the prompt, so the final check uses insertion position instead. The subsequent
fixture cleanup left the suffix after Ctrl+U; moving to End before cleanup fixes
that test without changing the editor. Journeys and helpers changed only after
their processes terminated.

## Remaining acceptance

The same native bundle also reruns the complete owned-fixture journey J121:
fresh Setup, actual Map preparation/generation, explicit context acceptance,
three frozen discovery jobs, shared-allowance halt, partial triage/export, a
specific allowance revision, only the remaining original job, reassessment,
final export and no-color recovery. It records 89 machine passes, zero failures
and 72 authenticated capture pairs. All four provider requests are intercepted
with dummy OAuth credentials and no network fallback; no live request occurs.
The fixture verifies unchanged source and active context, durable decisions,
unchanged fixed jobs and consumption, and no injected queue completion.

J121 captures are at
`/tmp/kuzushi-tui-integration-20261012/complete-investigation-current-tui/20261013-084040/J121`.
Its separate assistant review is in `complete-investigation-screen-review.json`
under the audit directory. Raw status remains `REVIEW_REQUIRED`, with 13 human
questions pending. The dirty fixture borrows an existing commit identity and
does not create a commit; its source bytes do not match that commit. Grounding
and inventory disclosures remain visible, exact context reading requires JSON
detail, and compact Report controls still require paging. This is current
end-to-end plumbing evidence, not live-model quality or full UX acceptance.

The raw native result remains `REVIEW_REQUIRED`, with three human judgments
pending and operator approval false. Native coverage here is Replay; the other
saved-run surfaces have focused geometry evidence. Long details still need
paging, and Logs keeps a larger alert preview. This does not establish complete
reference-product UX acceptance, every viewport or the entire investigation
workflow. All broader delivery milestones remain open. The live allowance stays
exhausted at six of six.
