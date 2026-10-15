# Completion keeps drafts in the composer

October 10, 2026. Two failing return contracts showed that a foreground run
restored Navigate mode over a newer draft. The buffer survived, but its keys no
longer belonged to the composer. This affected ordinary Home, Logs, Workbench
and Setup origins, including collapsed multiline paste. The special Prove reader
already preserved draft focus; ordinary surfaces did not.

## Operator behavior

Completion now restores Prompt mode whenever the composer contains a draft.
It preserves the cursor, expanded paste bytes and undo history. Empty drafts
still restore the original mode, and background completion keeps the current
view. Existing explicit reader/navigation behavior remains available.

A separate failing key-dispatch contract showed that stale Navigate state could
apply `u` over a held draft. Result actions now require an empty composer. Default
and remapped result keys use the same guard. The footer and result card consume
that guard too, so they do not advertise unavailable acceptance/discard/rerun
keys. A held Navigate draft names the configured prompt-focus action, or discloses
that it is unbound. Read-only navigation with a parked draft remains separate.

Two prerequisite contracts exposed the same problem over its approval question:
letters could approve/reuse/regenerate/cancel work while a draft was held, and
Escape canceled the queued plan. Choice keys now require an empty composer.
Escape clears a held draft first, retaining the plan. TTY and plain output use
the same blocked-input state and tell the operator to finish or clear the draft.

These changes protect operator decisions and approved work. They do not alter
phase receipts, findings, model selection, allowance reservations or module
contracts. Choosing a result still requires an explicit action. A page visit or
an unsent character cannot complete or discard an investigation phase.

## Verification

The return tests cover printable input after completion at a retained Unicode
cursor, multiline paste/undo, empty return and background focus. Actual stored
Map/Scan fixtures also exercise pending result cards without accepting them.
Default and remapped result actions remain usable with an empty composer.
The held-draft dispatch tests refuse selection, disposition and rerun effects.

The first regression run caught two old tests that expected Navigate despite a
held draft. Their expectations now match composer ownership, and the Scan test
also types `n` and verifies the pending attempt remains unresolved. Presentation
tests use an active Workbench when assessing its actionable controls. 221 distinct
focused checks pass: 76 return/phase contracts, 93 phase presentation checks,
result-key/remapping checks, and 41 prerequisite checks, with duplicate names
counted once. Workspace build and the risk proxy pass for 34 changed code files,
including the previously staged work. All ten repository summary gates pass.
The unsigned precommit receipt records dirty/drifted state honestly and cannot
serve as a clean-commit publication receipt.

## Native evidence and limits

J181 performs real default Map work over 65 owned metadata/text files, followed
by one explicitly requested dependency-policy scan. The operator model remains
selected, while these actions are runtime-free. No target source executes and
no model call is requested. The fixture hashes source before work and reads real
phase events and observation accounting after each stage. Scripted Map selection
is kept separate from operator acceptance of the screens.

Initial native runs corrected two fixture assumptions: onboarding was explicitly
skipped, so Setup had to be opened, and Setup owns its arrows directly rather
than the shell Navigate helper. It has eight current rows. The next run completed
Map and preserved the paste and typed `ud` without a disposition. Later snapshots
caught blank resize frames. A batched Escape/End sequence also inserted `[4~`
into the draft. The journey now separates those key events and requires painted
draft content after resizing. This does not prove the terminal parser's behavior
under arbitrarily coalesced escape sequences.

Later runs needed to wait for the real asynchronous Map disposition. SAST then
paused for its explicit cached-context prerequisite choice. The journey now
checks that `r` extends a held draft without starting work, clears the draft,
deliberately chooses reuse, and waits for the actual scan receipt before reading
its observation. No result or accounting record is fabricated by the fixture.

Final J181 is at
`/tmp/kuzushi-completion-input-20261010/exit-tui/20261010-191316/J181`.
It records 27 machine passes, zero failures and 21 authenticated live text/ANSI
captures. Native SHA-256 is
`45ba4a90817ed2cdaea2a30e9d57185238701fa669592df26578983eb3ddbded`.
All six sizes contain painted draft content. The paste inspector preserves both
Unicode lines; clear/restore retains the paste and appended text. The held
prerequisite draft starts no work, while deliberate reuse yields exactly one
policy observation. `X` edits at the retained cursor. No-color restart preserves
one scripted Map selection and that observation, with no review decision or new
provider reservation. Optional allowance tables remain absent, not fabricated
zero rows. Source hashes stay unchanged.

Three scoped assistant judgments remain separate from raw REVIEW_REQUIRED and
operator approval false. At 40x12 the paste label is horizontally cropped and
the inspection shortcut is absent from the compact footer. The settled Map
footer repeats paging guidance. These discovery/presentation gaps remain open.
The [compact input follow-up](compact-input-controls-2026-10-10.md) records the
subsequent repairs and native checks for paste discovery, inspector readability
and paging. It also confirms the batched Escape/End defect and tests literal
quit directly. Broader terminal input and complete workflow acceptance remain open.

The fixture is unversioned and cannot qualify a SHA transition. A typed-quit
harness reconciliation attempt failed; final recovery uses the visible idle
Ctrl+C control. Typed quit and coalesced escape handling need separate evidence.
All failed captures and original process outputs are retained.
Broad input latency, background pressure, terminal accessibility, operator
screen acceptance and complete reference-product comfort remain open. The full
investigation goal and all nine delivery milestones remain active on main.
