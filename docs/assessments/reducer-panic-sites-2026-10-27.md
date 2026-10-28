# The panic ratchet stopped at the renderer boundary, October 27, 2026

`boundary_lints::tests::pane_facing_code_stays_free_of_unaudited_panic_sites`
is green on `a9061da0`, and has been since
[#345](pane-panic-sites-2026-10-24.md) closed the fifth comparison site. It is
green because it only looks at three directories. Its own rationale — "a panic
here tears down the raw-mode terminal" — is just as true of the reducers in
`app/`, which it never reads.

## What was observed

Adding the four reducer subtrees to `PANIC_SCAN_DIRS` on `a9061da0` names
thirteen unaudited production panic sites:

```
app/state_transitions/map_text_keys.rs                     6
app/background_events/.../runtime_event_drains.rs          3
app/state_transitions/view_keybindings.rs                  1
app/state_transitions/picker_keys.rs                       1
app/runtime/terminal_event_queue.rs                        1
app/tool_runner/run_tool/events_and_results.rs             1
```

Every keystroke reaches `state_transitions`, every background job event reaches
`background_events`, every tool outcome reaches `tool_runner`, and every queued
terminal event reaches `runtime`. A panic in any of them leaves the terminal in
raw mode exactly as a panic in `renderer` does, so the ratchet's remedy —
return a degraded view — applies unchanged.

None of the thirteen is reachable on today's code. Each holds for a reason
stated somewhere other than where the panic is:

- `handle_map_text_key` unwraps `map_run_config().text()`. Its guard
  `map_text_editor_owns_key` admits a second case —
  `self.map_scope_picker_open()` — under which `text()` is `None`. What keeps
  the unwrap honest is that the dispatcher in `picker_keys.rs` re-checks
  `text().is_some()` before calling it, two files from the unwrap. The guard
  that shares the function's name does not prove its precondition.
- The two `activity_mut().expect("activity checked above")` drains check
  `activity()` and then unwrap it again after an intervening `?` on a
  filesystem read.
- `restore_run_focus_origin` unwraps `completion.origin` because
  `should_restore` happened to test `origin.is_some_and(...)`.
- `cycle_planning_current_row` takes a row id from the cursor, mutates the
  picker, and then re-finds the row by that id.
- `named_tool_terminal`'s `unreachable!` arm depends on four variants being
  matched by name in a caller's earlier arms.
- `char::from_digit(index, 10).unwrap()` over `1..=4`, and
  `VecDeque::remove(index).expect(...)` on an index produced one line above,
  are both locally true and both still panic sites by the ratchet's pattern.

The point is not that any of them fires today. It is that nothing stops the
next edit to a key handler or a drain from moving the condition that holds
them, and no gate would notice.

## What changed

`PANIC_SCAN_DIRS` gains `app/state_transitions`, `app/background_events`,
`app/tool_runner`, and `app/runtime`. All thirteen sites are removed
structurally; `AUDITED_PANIC_SITES` gains no entry.

- `map_text_keys` binds `text()` and `field` through `let`-else, hoisting
  `editing_field` above the document-picker branch so the field state is read
  once. A paste that finds no editor now refuses the capture instead of
  reporting an insertion that did not happen.
- `should_restore` becomes `restorable_origin`, returning
  `Option<RunFocusOrigin>`, so the decision and the value it implies are one
  expression. The two drains bind their session through `let`-else.
- `named_tool_terminal` returns `Option<NamedToolTerminal>`;
  `persist_terminal_tool_run` turns the impossible case into an
  `anyhow::bail!` rather than a panic or a mislabeled terminal row.
- `cycle_planning_current_row` clones the cycled row before mutating the
  picker and reads the disposition from it.
- The actor digits are literal `'1'..'4'`, and the coalescing slot is removed
  with `and_then`.

The remaining `app/` subtrees hold 253 more sites of the same class. They are
not in this change: `app/scope_review`, `app/batch_scan`, `app/threats`,
`app/relationships` and `app/lessons` each want their own pass, and a
thirteen-site diff is reviewable where a 266-site one is not.

## What is not claimed

No live panic was reproduced, because none of the thirteen is reachable. The
change is a gate widening plus the structural work it demands, not a bug fix.
Behavior is intended to be unchanged everywhere except the refused paste
capture and the bailed result-bearing terminal, both of which replace a panic.

## Verification

On this tree: the ratchet green over all seven directories; `cargo test -p
kuzushi-tui --lib` 5199 passed / 0 failed;
`cargo clippy --workspace --all-targets --locked -- -D warnings` clean;
`cargo fmt --all -- --check` clean; `pnpm verify:quick:summary` `"ok": true`;
`pnpm test` 419 passed / 0 failed; the risk proxy over 7 changed code files.

`cargo test --workspace --locked` does not pass on this host, and did not
before this change. `kuzushi-bdd-tui --test onboarding` reports 51 scenarios
(32 passed, 19 failed) on this tree and the identical 51 scenarios (32 passed,
19 failed) on `a9061da0` with these edits stashed. Every failure is the same
shape — `timed out after 3s waiting for status segment ...; footer was
`<not rendered>`` — so the tmux-driven journeys are missing their render
deadline on this container rather than reporting a logic defect. The failure is
recorded here as a host limitation, not as a receipt this change earned.

Hosted CI runners have not started since 2026-10-08, so none of this is
confirmed by GitHub Actions; the `quality-gauntlet` job on
[#348](https://github.com/allsmog/Kuzushi/pull/348) still fails in three
seconds without reaching checkout. All receipts above are local.
