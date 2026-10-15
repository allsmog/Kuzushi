# Compact paste controls and terminal input

October 10, 2026. J181 exposed hidden paste controls at 40×12 and duplicate Map
paging guidance. A focused editor test also reproduced Ctrl+Y failing when the
cursor was beyond a paste marker after appended text.

## Behavior

The composer now gives collapsed paste four visible controls: inspect, clear,
interrupt and undo. Owned pickers and dialogs retain their own controls, and
active cancellation still distinguishes request abort from cleanup. The compact
inspector fits its expansion, removal, cancel and undo guidance into three rows.

Ctrl+Y inspects the block at the cursor or the nearest remaining block. Equal
distances choose the earlier block. Inspection preserves the draft and cursor;
direct deletion and expansion retain their existing cursor-based targeting.
Map gallery paging replaces the generic paging binding before adding its local
label, so the resting context-only Map names paging once.

No module, option, finding, context, source-revision, allowance or persisted
artifact contract changes. These are repairs to existing input and reading
surfaces, without additional discovery jobs or provider requests.

## Verification

125 distinct focused tests pass across paste/editor/inspection and footer
contracts. The compact inspector test failed at 40×12 before the shorter copy;
all six viewport sizes now expose its controls. The appended-text inspection
test failed before nearest-block selection. Workspace build passes, and the
required risk proxy passes for 40 changed production files across this staged
batch. Exact test names and logs are at
`/tmp/kuzushi-compact-input-20261010/focused-tests.json`.

All ten repository summary gates pass. The unsigned precommit receipt is
`/tmp/kuzushi-compact-input-20261010/precommit-verify-receipt.json`. It records
dirty and drifted state and cannot attest to a clean commit. The configured
verification key is trusted, but this receipt is not signed or used to publish.

Final J182 is at
`/tmp/kuzushi-compact-input-20261010/final-native/20261010-193258/J182`.
It has 38 machine passes, zero machine failures and 28 authenticated live
text/ANSI captures. All captures bind to native SHA-256
`48c986eb46b822996c1ee4124006879ea20795e27216ef55bad61159be0d66a0`.
It exercises 40×12, 60×20, 80×24, 96×89, 120×36 and 160×48, plus no-color restart.

The fixture performs real default runtime-free Map work over 65 owned inert
metadata/text files, followed by one explicitly requested dependency-policy
scan. It never executes target source. Source hashes remain unchanged; the
ledger retains one observation and zero review decisions. Optional provider
reservation and investigation work tables remain absent, represented as null.
The resulting Map truthfully discloses that it has no threat-model context.

The first J182 run remains preserved under
`/tmp/kuzushi-compact-input-20261010/native/20261010-192937/J182`.
Its failed exit expectation revealed the legitimate held-draft confirmation
dialog. The final journey deliberately cancels exit, restores the paste draft,
clears it and then exits. Journey files and helpers were not edited while live.

Scoped assistant screen judgments are separate from raw REVIEW_REQUIRED and
operator approval false in `assistant-screen-review.json`. The complete
investigation journey and reference parity remain open.

## Confirmed terminal gap

The subsequent [terminal keyboard repair](terminal-keyboard-2026-10-10.md)
addresses this recorded defect in the pinned Unix dependency and preserves
literal typed/pasted content. The observations below remain the original J182
evidence; broader terminal acceptance is still open.

Batched Escape/End inserts `[4~` into the composer. Both J182 runs preserve this
observation. The pinned crossterm 0.29.0 Unix parser emits one Escape for two
consecutive Escape bytes; its event source then clears the buffered bytes. This
is consistent with losing the second prefix of an End sequence. That mechanism
is an inference from the pinned local dependency source, rather than proof for
all terminals and input timing.

This increment does not strip sequence-looking text, replace the decoder or
claim the gap fixed. Literal paste preservation remains necessary. Broad input
latency and pressure testing remain open too.

Literal `quit` followed by Enter exits successfully. The protected harness's
`submit` reconciliation was bypassed for that check; inline completion ghost
matching remains unqualified. A passing direct command does not establish that
the protected matcher works for every prompt.
