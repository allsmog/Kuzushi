# A recovered panic reached the operator without its reason (2026-10-29)

## The defect

[`recovered-panic-terminal-2026-10-28.md`](recovered-panic-terminal-2026-10-28.md)
stopped the terminal panic hook from tearing down a live shell for a panic one
of the seven in-process recovery boundaries was going to catch. Its
`LeaveToBoundary` branch does nothing at all, which left the panic's text
nowhere: the hook does not print it, and the recovering boundary never had it.
That file records carrying the text onward as a follow-up. This is it.

`std::panic::PanicHookInfo` is also the only place the panic's **source
location** is available — `catch_unwind`'s `Err` payload carries the message
alone — so dropping the hook's view of a recovered panic discards the one fact
that names where it came from.

What the operator read as a result, on the boundary reachable from on-disk
data:

- `caught_read` (`app/view_hydration/runtime.rs`) mapped every recovered panic
  to `Err(())` and pushed a `ViewHydrationFailure { target, key }`. A
  `ViewHydrationFailure` carried no cause, so each surface's recorder in
  `app/view_state/workbench_cache/` substituted a fixed sentence — "Decision
  source reader failed. Refresh to retry.", "Study queue unavailable; retrying
  this read.", "Report read failed. Press r to refresh." A malformed
  `.kuzushi` artifact — the case `caught_read` exists for — therefore produced
  a pane that says a read failed and cannot say why, with the panic text
  discarded at the hook and the location never captured.
- The same type was used for a read that simply returned nothing: the
  `Ok(None) | Err(())` arm in `hydrate_blocking` reported a canceled read and a
  panicking reader identically, so the two states were indistinguishable
  downstream.

## Why it ranked highest

It is the standing follow-up to yesterday's merged fix, on the boundary that
fix called out as reachable from on-disk data, and it is the repository's own
rule — prefer explicit errors and honest states over silent fallback — applied
to the one path where a panic is survivable. A field report of "Report read
failed" is currently undiagnosable: nothing in the session, the frame or stderr
holds the panic.

The alternative candidates were a wider panic-surface ratchet (the 253 sites
`reducer-panic-sites-2026-10-27.md` leaves in `app/scope_review`,
`app/batch_scan`, `app/threats`, `app/relationships` and `app/lessons`) and the
open `report.sarifport` destination string from the 2026-10-11 TUI audit. The
ratchet widening prevents no live defect; the destination string could not be
localized from the code as it now stands, and the Report surface has changed
since that audit, so it needs a reproduction before a patch.

## The fix

`kuzushi_core::recovered_panic` gains the account and the means to pass it:

- `RecoveredPanic { message, location }`, with `Display` as
  `panicked: <message> at <location>` (the location omitted when absent), and
  `from_payload` for the disclosure a caught payload alone supports.
- `record(payload, location)` for a process hook to hand over what it saw.
  Ignored outside a boundary, where the panic is fatal and the hook discloses
  it itself.
- `catch_disclosed`, which clears any account no boundary read, runs the body
  through the existing `catch`, and on a panic prefers the hook's account over
  the payload. The six boundaries that only need the payload keep `catch`.

`install_terminal_panic_hook` records on both recovered dispositions —
`LeaveToBoundary`, which prints nothing, and `ChainOnly`, where stderr may not
be where the operator is looking. The fatal branch is unchanged.

`caught_read` returns `Result<_, RecoveredPanic>`.
`ViewHydrationFailure`'s `reason` is private behind two constructors, so the
distinction is one the type enforces: `unexplained` for a read that returned
nothing or was canceled, `panicked` for one a boundary caught. Its `message`
method is the single place the surface's own guidance and the recovered panic
are combined, and the nine recorders call it instead of their fixed strings. A
`ViewHydrationMessage::Failed` now carries the whole failure rather than
rebuilding it on receipt, and a hydration worker thread that panics outside
`caught_read` reports the message its join payload carries.

A panic message is arbitrary text from the panicking code, so the reason is
clipped to 160 characters before it reaches a pane.

## What is not claimed

No live panic was reproduced; `PanicReader` in
`app/view_hydration/tests.rs` is the fixture, as it was before this change.
The six boundaries that still use `catch` — job workers, report export, and
the four run-lifecycle subscribers — disclose exactly what they disclosed
before; only the view-hydration boundary's messages change. The job-worker
message is byte-identical: `worker_panic_message` now reads its text from
`RecoveredPanic::from_payload` instead of a local copy of the same downcast,
which removes the duplicate rather than changing the string.

Nothing is written to the session transcript. The transcript is a separate
surface with its own redaction discipline, and this change keeps the
disclosure on the surface whose data went missing.

## Verification

On this tree:

- `cargo test -p kuzushi-core --lib recovered_panic` — 10 passed / 0 failed.
  The three new honesty cases (a hook's account preferred over the payload, an
  unread account not explaining the next panic, an account recorded outside a
  boundary dropped) fail against the prior module, which had no account at all.
- `cargo test -p kuzushi-tui --lib` — 5397 passed / 0 failed / 10 ignored.
- `cargo clippy --workspace --all-targets --locked -- -D warnings` clean;
  `cargo fmt --all -- --check` clean; `git diff --check` clean.
- `pnpm verify:quick:summary` `"ok": true`, over the same ten steps that were
  `"ok": true` on `f583e60` before these edits.

`cargo test --workspace --locked` is not green on this container and was not
before this change: the tmux-driven `kuzushi-bdd-tui` journeys miss their
render deadline here, as recorded in
`reducer-panic-sites-2026-10-27.md`.
