# Control-map reading — September 9

The control map now provides six reading rows at 40×12, preserves complete key labels and descriptions, and puts the originating view's controls first. Its title reports the visible document range. Rendering, paging and scroll limits use the same geometry; top, tail and resize checks exercise real reducer/render paths. Closing it preserves the originating Activity run and Output position.

Trace and Investigation now share Replay's existing notice-owned Escape label. An error is dismissed on the first Escape; the next Escape returns from the reader. Focused drafts retain their existing clear-before-back behavior. The change does not alter notice ownership or authorization.

## Verification

- Focused TUI groups pass: Keymap 20, Prove detail 9, prompt 156 (one ignored), Activity reader 11, chrome layout 15 and Replay 33. Groups overlap. Five new Keymap tests cover complete long/remapped bindings, all 50 fixture actions, compact geometry, return with a held draft, and tail/overscroll/resize. Two new Prove-detail tests exercise error dismissal and success-notice back behavior.
- `cargo build --locked --workspace` passes. Tested native SHA-256: `5507ba1cf339562950c966b1f3ca193fe4675ebe2e5e96a96f0baee676b1445f`. Seven preexisting dead-code warnings remain.
- All ten quick checks pass; receipt finished `2026-09-09T18:11:25.787Z`. Normal CRAP-risk passes. The worktree is dirty and the receipt reports drift; 18 explicit source hashes supplement it. This is not a clean release or a full Rust-suite receipt. Final prose/recipe changes follow the quick gate and receive separate content checks.
- Sequential J54 at 40×12 (`20260909-111217`) and 80×24 (`20260909-111328`) each has 26 machine passes and four director-reviewed checkpoints. All 74 compact document rows and all 52 wide rows occur in the captures. Output before/after closing the map is byte-identical at 40 columns; at 80 columns only the elapsed-time header changes. Both show the actual Trace error, its dismissal, and subsequent back navigation.

Earlier J54 runs `20260909-110954` and `20260909-111114` retain partial evidence: the initial Output capture preceded its repaint, and the compact recipe did not capture every final page before jumping to the tail. The recipe now waits for visible scroll movement and records every page. No production change was needed for that capture timing issue.

## Limits and next work

A wrapped two-line section heading can still end one page before its first action. The overlap retains all content, but section grouping is partial; the older no-dangling-heading regression does not cover every wrapped heading placement. Some static control-map copy still needs a broader semantic audit. The failed-run detail also retains a preexisting exact-zero-cost label on an unavailable-usage record.

These are local missing-helper failures, with no successful new provider request or empirical proof. Four failures add eight run/result files; all 54 prior run/result files, source files, workflow ledgers, proof events, operator config and dependency hashes are preserved. No proof result was selected, and no files were staged, committed or pushed.

The immediate next work is actual execution of the canary reproduction, Fix, re-verification and Report. A separate local Linux VM is being prepared because the current proof runner requires Linux bubblewrap. A successful Linux journey would not establish native macOS proof support. The broad interaction checklist remains open.

Evidence root: `~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/control-map-reading/`; source hashes, quick receipt, test logs, preservation checks and retained text/ANSI journeys are stored there. Review is director self-review, not an independent review.
