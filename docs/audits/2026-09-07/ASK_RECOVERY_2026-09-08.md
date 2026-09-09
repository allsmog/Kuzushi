# Real Ask cancellation and conversation recovery

September 8, 2026. Kuzushi `586a6fda6d` plus uncommitted hardening.

OpenAI OAuth with GPT-5.5 and medium reasoning now passes real Ask cancellation,
explicit follow-up, same-target restart, and editing a canceled question before
retrying. The existing accepted Map, Scan and Review remain intact. The broader
interaction checklist is still open.

## Observed failure and repair

The initial real 80-column run stopped while public answer text was arriving.
Kuzushi retained the preview as **INCOMPLETE** and completed an explicit follow-up.
After exit and restart, Answers opened empty. The saved transcript had ordinary
question/answer events, but no context-bound conversation checkpoint suitable for
reconstruction. Run artifacts intentionally retain answer counts rather than
complete answer text.

Ask now records a typed public conversation checkpoint at admitted dispatch and
terminal settlement in the existing operator-owned, redacted session transcript.
It retains the exact target, source revision, Map and tool-policy receipt. Recovery
runs in the background and cannot replace a newer request, a cleared conversation
or another target's state. It does not open a pane, move focus, change model
selection or dispatch work. If history is still loading when a question is
submitted, the question stays editable for an explicit retry.

A restored unfinished dispatch is marked interrupted. A canceled answer retains
its incomplete preview; its submitted question returns to the editor when there
is no newer reply draft. The existing prompt projection includes earlier
questions, completed answers and terminal error labels. It excludes incomplete
response text. Consequently an attached-turn count of one after cancellation
means one settled question/error record, not a completed assistant answer.
The context binding is rechecked before the next request; changes start a fresh
conversation. No assembled prompt, private reasoning or failure handoff was added
to the checkpoint.

[Recovery and persistence](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/answer_recovery.rs),
[bounded transcript reader](~/vibe-code/Kuzushi/crates/kuzushi-core/src/session_transcript/store/conversations.rs),
[model-history projection](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/agent_session/ask_agent/agent_prompt.rs:151).

## Sequential terminal acceptance

All checks used J54, the ordinary global launcher, the existing real six-file
target, and the stored OAuth credential. No native screenshot or local provider
simulation was used in this pass.

| Recipe | Result |
| --- | --- |
| Initial 80-column submission | Harness failed to recognize a long, wrapped shell draft; stopped before any model call. Retained as a failed attempt. |
| 80-column cancellation and restart | Real cancellation and follow-up passed; restart reproduced the empty Answers defect. Three review items passed, one failed. |
| Repaired 80-column restart | Real answer restored; an explicit follow-up repeated the prior answer's memory marker and explained the accepted Review. Clear plus restart left no recovered conversation. Five review items passed. |
| Final 40×12 cancellation/retry | Real partial answer canceled; exit disclosed the retained draft. Restart restored the incomplete answer and editable question. Paging, replacement without submission, explicit retry and final exit passed. Five review items passed. |

The first failed harness run also recorded a wait timeout and an unknown directive
after its recipe was edited during cleanup. It created no Ask run. Later recipes
were launched after the prior process completed.

The successful harness runs exit `4` until their review questions are judged;
those exits are not machine failures or automatic acceptance. The original
restart failure remains recorded. Final exit captures in the repaired 80- and
40-column recipes show `NATIVE_EXIT=0`; other recorded exits show the terminal
restored but do not separately record the native status.

[80-column restored answer](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/ask-recovery/journeys/20260908-163052/J54/06-answer-restored.txt),
[history-dependent follow-up](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/ask-recovery/journeys/20260908-163052/J54/08-resumed-followup-complete.txt),
[40-column restored question](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/ask-recovery/journeys/20260908-163646/J54/11-restored-question-editable.txt),
[edited retry result](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/ask-recovery/journeys/20260908-163646/J54/13-narrow-retry-complete.txt).

Six new real Ask runs account for two cancellations and four completed answers.
All name the same GPT-5.5 OAuth model, medium reasoning and captured context.
Eight new checkpoint records cover the four post-repair requests. The restored
canceled checkpoint contains 335 public preview characters, no completed answer,
and a cancellation error. Both restarted follow-ups attach one prior settled
turn. Provider spend remains unresolved; observed zero is not a price claim.

The final native binary is `990082b6fefd8c3cfeeec219fc81c123232d494d69e0c5f33be6bacb3068ecec`.
The complete-answer restart recipe used the earlier `c92488e6…` build; the final
build adds failed-question restoration and extracts the submission presentation
helper to satisfy the function-length gate.

## Integrity, validation and limits

Source files, protected Map artifacts, accepted workflow attempts, prior run
receipts and all six report formats retain their baseline hashes. Of 313 existing
target files, 308 are unchanged. Five bookkeeping files changed: the workspace
and run-history databases, shell history, latest-run pointer and event log. The
workspace database passes its integrity check and retains the four prior
false-positive decision rows; no new Review decision was added. The saved model
configuration is byte-identical.

Focused checks pass: **59 Answer tests**, **34 Ask-session tests**, **5 TUI
transcript tests** and **41 core transcript tests**. Groups overlap. These include
18 new recovery tests for redaction, limits, malformed records, live/current
session exclusion, clear, interruption, context changes, background restoration,
stale results, preserved drafts/focus and explicit retry. The normal CRAP-risk
gate passes for 256 cumulative changed code files. The final repository quick
gate passes; its dirty-tree receipt is not a release certification. No new full
TUI-suite run or independent/post-commit review is claimed.

Recovery checks the 64 most recently started sessions, with a 32 MiB total read
budget, 8 MiB per file and a 512 KiB checkpoint limit. It restores at most twelve
earlier turns plus the current turn. Corrupt or oversized history refuses
recovery instead of silently choosing an older checkpoint. Clear prevents the
current target's cleared conversation from returning. Older transcripts without
checkpoints remain inspectable; they are not retroactively reconstructed.
Unsent drafts are not persisted. Disabling session persistence also disables
recovery. Hard process termination, very large history stores and concurrent
sessions have not had live acceptance in this pass.

OpenCode still provides a searchable session chooser and pinned/current-session
handling in its [session list](~/clone-references/opencode/packages/tui/src/component/dialog-session-list.tsx:62).
Kuzushi now closes the tested same-target restart gap; selecting among multiple
saved conversations remains a comparison gap. Fresh login/expired-auth recovery,
concurrent Run/Ask, full actionable Prove/Fix, batch acceptance and aggregate
spend remain open in the [broad checklist](INTERACTION_HARDENING.md).

[Run receipts](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/ask-recovery/run-receipts.json),
[checkpoint receipts](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/ask-recovery/snapshot-receipts.json),
[integrity receipt](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/ask-recovery/post-live-integrity.json),
[verification receipt](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/ask-recovery/REVALIDATION.json).
