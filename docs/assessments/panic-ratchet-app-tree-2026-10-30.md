# Pane-facing panic ratchet over the whole `app` tree — 2026-10-30

## The gap

`crates/kuzushi-tui/src/boundary_lints.rs` keeps pane-facing code free of
unaudited `unwrap`/`expect`/`panic!`/`unreachable!` sites, because a panic
there reaches the operator through the raw-mode terminal. It scanned
`renderer`, `ui_view_models`, `commands` and four named `app/` subtrees:
`state_transitions`, `background_events`, `tool_runner`, `runtime`.

`app/` has 57 subtrees and 47 loose modules. The other 53 subtrees were
outside the scan, including the two that #351 and #356 established are
reachable from on-disk data — `app/view_hydration`, which parses
`.kuzushi` artifacts, and `app/view_state`, which folds them into the
workbench cache. Naming subtrees one at a time also meant a new subtree
joined the scan the day someone remembered it, not the day it was added.

Scanning the whole tree found one reachable panic and one silent exemption
hazard, described below.

## Ranked, and why this one

Ten candidates were weighed from this tree (CI green on `main`, no open
PRs, no `TODO`/`FIXME` in Rust, `pnpm verify:quick:summary` `"ok": true`
on `d86f59a`):

1. **This change.** A reachable reducer panic plus 34 subtrees and 43
   modules of coverage that was already earned and not locked in.
2. `app/effect_runtime.rs` — twelve `unreachable!` arms that fire when the
   category router and one of its sub-matches drift. Routing a stray effect
   to an honest notice is its own change; recorded as backlog.
3. `app/batch_scan` (125 sites), `app/scope_review` (40), `app/threats`
   (20) — the large audit backlog, each its own PR.
4. `app/source_review` (14) and `app/relationships/` (15) — form-state
   `unwrap`s one frame from their guard.
5. `finish_findings_refresh` drops a pending read that is no longer current
   without reporting anything, so an operator-initiated refresh can end in
   silence. Needs a reachability proof first; left alone here.
6. `app/session_state.rs` — `#[cfg(test)]` helpers inside an `impl` block
   that the column-0 region rule cannot strip. Either audit them or teach
   the region rule about attributed items; the latter widens coverage and
   belongs in its own change.
7. `verify_consensus::representative_pass` / `highest_confidence_pass` —
   `max_by` over confidence with no tie-break, so the representative pass is
   input-order dependent. Deterministic, but arbitrary.
8. `pnpm test` is red on a fresh container until `pnpm install` runs
   (`yaml` is imported by `scripts/workflow-semantics.test.mjs`).
   Environmental, not a repository defect.
9. SARIF `kuzushiCurrentCheckoutApplicability` is a hardcoded
   `"not_assessed"` in five writers — documented as intentional in
   `docs/modules.md`, so honest, but it is duplicated policy.
10. Issue #172 (TUI operator-experience audit) and #85 (AI-triage
    governance policy) remain open and are larger than one PR.

(1) ranked first because it is the only candidate that both fixes a
reachable operator-visible crash and prevents the same class from
reappearing across 34 subtrees, in under 400 diff lines.

## The reachable panic

`defer_findings_refresh` built its pending read with

```rust
target: self.target_owned().expect("explicit target checked before deferral"),
```

Two of its three callers do check. `EffectRuntime` gates on
`can_defer_findings_refresh`, which requires `target().is_some()`.
`restore_linked_findings`
(`app/state_transitions/linked_findings.rs:84`) does not: it restores a
saved navigation origin and defers a passive refresh unconditionally. With
no active target — the state `Esc` on the target picker leaves the shell in
— that `expect` fired in a reducer that owns the terminal.

A findings read is target-scoped, so a deferral without one has nothing to
read, and nothing failed either. It now returns early without recording a
read failure, and names the missing target only when the operator asked for
the refresh (`announce`). `record_findings_read_failure` is deliberately not
called: it would assert a read that was never attempted, and it clears the
active campaign batch report as a side effect.

Two further sites in the same file were sound but written as
invariant-`unwrap`s one statement from their guard; both are now expressed
directly (`as_mut()` through `if let`, and `take()` with the pending read
put back when it belongs to another request).

`app/relationships.rs::handle_relationship_note_key` reached into
`router.relationships.note` twice with `.unwrap()`. Its caller does guard,
so no panic was reachable; the field edit is now one `edit_relationship_note`
helper that drops the keystroke if the note has closed.

## The silent exemption

`PANIC_SCAN_EXCLUDED_DIRS` is matched with `starts_with` on the path
relative to `src/`. A bare `app/relationships` entry therefore also exempts
the sibling module `app/relationships.rs` — a file that is scanned, and
whose name eight of these subtrees share with a loose module. The first
draft of this change hid the two sites above exactly that way. Every
directory entry now ends in `/`, and the reason is recorded beside the
constant.

## Coverage

`PANIC_SCAN_DIRS` is now `renderer`, `ui_view_models`, `commands`, `app`.
`PANIC_SCAN_EXCLUDED_DIRS` carries two test-support paths and an explicit
audit backlog of 19 subtrees and 2 modules. Net: 34 subtrees and 43 loose
modules newly scanned, plus every subtree added to `app/` from now on.

`every_excluded_panic_scan_path_exists` fails when an excluded path no
longer exists, so a renamed subtree cannot leave the scan through an
exemption that can never fail, and the backlog can only be retired by
deleting its entry.

## What is not claimed

The 19 backlogged subtrees and `app/effect_runtime.rs` are not audited and
not safer than before; they are now written down. Two `unreachable!` arms
are audited in rather than removed — `hydration_group`'s cache-group
classification, where a wrong default decides eviction, and the reader's
unassigned-key arm, which `caught_read` already recovers and discloses — and
both remain panics on a code-change path.

No live terminal teardown was reproduced. The reachability of the
`defer_findings_refresh` panic is proved by test, not by observation: both
new tests in `app/findings/refresh_background/tests.rs` panic with
`explicit target checked before deferral` against the prior tree.

## Verification

On this tree:

- `cargo test -p kuzushi-tui --lib boundary_lints` — 11 passed / 0 failed,
  including the widened scan and the new exclusion-freshness test. Appending
  a throwaway `unwrap` to `app/jobs/mod.rs`, a newly covered subtree, fails
  it; the entry was removed again.
- `cargo test -p kuzushi-tui --lib refresh_background` — 24 passed / 0
  failed, 2 of them new.
- `cargo test -p kuzushi-tui --lib` — see the PR body.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo fmt --all -- --check`, `git diff --check`,
  `pnpm verify:quick:summary` — see the PR body.

`pnpm verify:quick:summary` was `"ok": true` on `d86f59a` before these
edits, once `pnpm install` had run.
