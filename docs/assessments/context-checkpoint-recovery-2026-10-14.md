# Private context-copy checkpoint recovery

October 14, 2026. Implementation remains on main at `f8649511f746`.

An unfinished manual context copy now survives a process crash after its local
checkpoint is acknowledged. Text, Unicode cursor, selected field and reading
position bind to the canonical target and exact inspected context reference.
Recovery offers saved drafts for explicit selection; it does not choose one,
activate context, start a job or approve an allowance. Pending copy-save state
returns to review, with guidance to inspect the context catalog first.

Private version-1 records live beside session transcripts in the operator's
`.kuzushi/v3/context-drafts`. Their directory and file permissions are 0700 and
0600 on Unix. Atomic publication retains the previous file on interruption.
The reader excludes symlinks and nonregular paths, authenticates target,
revision and session membership, and rejects malformed or unsupported records
without rewriting them. These files are not transcript events or target context.
Drafts contain no runtime, selected model, jobs or spending authority.

One asynchronous writer coalesces updates per draft; a bounded reader supports
recovery without filesystem work in the input handler. Limits are 32 retained
draft keys and 32 MiB of conservative queue accounting per shell, 128 directory
entries and 32 MiB per recovery, 8 MiB per record, and 32 adopted origin hashes.
Existing 16 KiB text-field and 64-edit limits remain. Reaching a limit preserves
session text and discloses missing durability. Explicit copy saving and discard
resolve exact adopted record hashes. Independent edits with different hashes
remain recoverable; resolved records survive later writes in their session.

The editor distinguishes saving, saved and failed local writes. Quit distinguishes
uncheckpointed edits, recoverable copies, pending writes and failed cleanup.
Recording-disabled shells retain the previous session-only behavior. Back and
quit retain their draft-protection controls. Recovery shows field previews and
cursor position, preserves its selection marker at 40 columns and exposes only
controls available in the current loading, choice or failure state.

## Verification

Eighty distinct focused Rust checks pass: 50 session-store checks including nine
checkpoint cases, 11 editor checks and 19 exit checks. They cover restart,
coalesced typing, explicit discard, independent sessions, private permissions,
unsafe paths, malformed records, limits, interruption and all six viewports.
The locked workspace build passes. All ten repository summary gates pass,
including 391 Node checks and the risk proxy over 681 changed code files.
The retained dirty receipt is
`/tmp/kuzushi-tui-integration-20261012/context-checkpoint-green-receipt.json`.
It is not clean-commit release proof. No full Rust-suite claim is made.

The frozen native product SHA-256 is
`81ea4f0560d104d7eb57c5f35a6dab58994c785fa717197a2621659c5d81e6f5`.
Sequential native evidence is under
`/tmp/kuzushi-tui-integration-20261012/context-checkpoint-final-tui/20261014-115200`:

- J255 records 30 machine passes and no failures. The helper confirms the owned
  fixture's executable and target, kills only that process after checkpoint
  publication, restores its terminal and reopens the exact context. Recovery
  retains multiline text and cursor; Delete edits the expected third character.
  Explicit discard does not resurrect the adopted draft.
- J254 records 45 machine passes and no failures. It distinguishes unprepared
  context cases from recoverable hidden copies, retains Back/Stay ownership and
  recovers the saved matrix without starting work.
- J121 records 109 machine passes and no failures. The supported context,
  finite discovery, exhaustion, explicit revised allowance, review, export and
  restart workflow retains its receipts and decisions on the same build.

All source fixtures are owned and inert. J255 and J254 create no provider
reservation, scan queue, observation or finding decision. The global context
stays inactive. J121's four model responses are fully intercepted. No fresh
live provider request or target-source execution occurs.

The 149 text/ANSI capture pairs authenticate the native identity, actual
dimensions and live alternate-screen ownership. Raw journey verdicts remain
`REVIEW_REQUIRED`, with 21 pending human judgments.
Assistant screen review does not establish operator approval or full reference
UX parity. Initial helper failures retain the mistaken session path and overly
narrow executable check; they stopped before killing a process. A later failed
capture retains the combined Escape/discard sequence. The passing sequence
separates those inputs and waits for the actual field chooser. A formatting gate
failure is retained; only the new module declaration file required correction.

## Remaining acceptance

Acknowledged checkpoints provide the demonstrated crash recovery. Unsaved
in-flight IO remains honestly pending. Kernel IO latency and arbitrary process
failure timing are not strictly bounded. Large histories, non-Unix equivalents,
unprepared study-case and goal-field crash recovery still require evidence.
Real-model scope and context usefulness and full human UX qualification remain
open. The prepared two-request live scope allowance is still pending; the prior
six-request allowance remains exhausted. No broad milestone, module promotion,
retirement, commit or push follows from this increment.
