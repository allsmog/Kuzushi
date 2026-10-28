# A recovered panic tore down the live terminal (2026-10-28)

## The defect

`install_terminal_panic_hook`
(`crates/kuzushi-tui/src/app/runtime/render_plain_scripted_session.rs`) treated
every panic as the shell's last act: it consumed the terminal guard, ran
`rollback_terminal_mode` and chained to the previous hook.

`std::panic::catch_unwind` does not stop the process panic hook. The hook runs
on the panicking thread *before* the unwind reaches the boundary that recovers,
so the hook also fired for the panics the shell is deliberately built to
survive:

- `spawn_job_worker` (`app/jobs/ticket.rs`) catches a worker panic and turns it
  into `ticket.fail(worker_panic_message(..))`, which the operator reads in the
  shell.
- `caught_read` (`app/view_hydration/runtime.rs`) catches an artifact reader's
  panic and reports a `ViewHydrationFailure` per key, so a malformed
  `.kuzushi` artifact cannot end the session.
- the report-export worker (`app/report_export/worker.rs`) catches a panic and
  returns `stopped_receipt(..)`.
- `notify_item_subscriber`, `announce_durable_range`,
  `notify_derivative_subscriber` and `report_delivery_fault`
  (`kuzushi-core/src/run_lifecycle/persistence/`) catch a panic in a committed
  run-item, durable-range or fault subscriber — the shell's own event fan-out —
  and turn it into a `RunItemDeliveryFault`.

In each case the boundary recovered and the shell kept running, but by then the
hook had already disabled mouse capture, bracketed paste and focus reporting,
left the alternate screen, shown the cursor and disabled raw mode, and the
chained hook had written its message into the frame. The operator was left with
a shell that keeps drawing into the normal screen while the tty line discipline
owns the keyboard: nothing the shell renders is reachable, and `Ctrl+C` kills
the process rather than requesting cancellation.

## Why it ranked highest

It inverts the purpose of the four recovery boundaries the repository already
built, and it is reachable from on-disk data: a view-hydration reader panicking
on a malformed artifact is the case `caught_read` exists for. It is also the
counterweight to the pane-facing panic ratchet (#343, #345, #349) — that gate
removes panic sites because a panic reaches the operator, and this is the path
by which a panic that was supposed to be contained reached them anyway.

## The fix

`kuzushi_core::recovered_panic` is a new module holding a thread-local
boundary-depth counter, a `catch` that marks the thread for the duration of its
body, and `in_boundary()` for a hook to read. The counter is thread-local, so a
panic on any other thread is still read as fatal; it is a counter rather than a
flag so leaving a nested boundary does not clear the outer one. All seven
in-process recovery boundaries above now run their bodies through `catch`.

The hook's decision is the pure `panic_disclosure(recovered, terminal_armed)`:

| recovered | terminal armed | disclosure         |
| --------- | -------------- | ------------------ |
| no        | either         | `RestoreAndChain`  |
| yes       | yes            | `LeaveToBoundary`  |
| yes       | no             | `ChainOnly`        |

A fatal panic is unchanged. A recovered panic with no terminal of ours engaged
(headless `run`, plain, scripted) still reaches stderr. A recovered panic under
a live terminal leaves both the terminal and the frame alone, because the frame
is the operator's only output surface and the recovering boundary reports the
failure through the shell's own surfaces.

## What is not claimed

The `LeaveToBoundary` branch drops the panic payload text from stderr. That
text was already unreadable in this case — it was written into an alternate
screen whose cells Ratatui's next diffed frame overwrites — so nothing
operator-visible is lost. The job-worker boundary already carries the payload
into its operator-facing failure; the view-hydration and report-export
boundaries disclose the failure without the payload, exactly as they did
before this change. Carrying that text into the session transcript is a
follow-up, not a regression.

`kuzushi-cpg`'s two `catch_unwind` sites (`engine.rs:22`, `engine.rs:139`) and
`kuzushi-mcp-treesitter`'s (`tools.rs:1598`) are deliberately untouched: they
run in MCP server processes, which install no terminal hook.

## Verification

On this tree:

- `cargo test -p kuzushi-core --lib recovered_panic` — 5 passed / 0 failed.
- `cargo test -p kuzushi-tui --lib panic_disclosure` — 3 passed / 0 failed.
- `cargo test -p kuzushi-tui --lib terminal_panic_guard` — 1 passed / 0 failed.
  With the hook reverted to its prior body and the same test, the added
  assertions fail — the reproduction is the test.
- `cargo fmt --all -- --check` clean; `cargo clippy --workspace --all-targets
  --locked -- -D warnings` clean; `pnpm verify:quick:summary` `"ok": true`.

`cargo test --workspace --locked` is not green on this container and was not
before this change: the tmux-driven `kuzushi-bdd-tui` journeys miss their
render deadline here, as recorded in
`docs/assessments/reducer-panic-sites-2026-10-27.md`.
