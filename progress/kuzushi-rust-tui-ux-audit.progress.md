# Kuzushi Rust TUI UX Audit Progress

Stage: Rust TUI UX audit findings implementation
Active story: RTUI-003 Unify Keybind Footer With Actual Hotkeys
Status: completed

## Checklist

- RTUI-001 Repair Plain Mode Command Feedback: passed.
- RTUI-002 Add Viewport State For Long Views: passed.
- RTUI-003 Unify Keybind Footer With Actual Hotkeys: passed.
- RTUI-004 Expose Aliases And Examples In Help: passed.
- RTUI-005 Stabilize Async Agent Tests: passed.
- RTUI-006 Wrap Important Plain Output Instead Of Truncating: passed.

## Iteration Log

- RTUI-003: Added shared Rust TUI view-keybinding descriptors consumed by both
  the key handler and footer renderer. Findings now advertises `j/k/g/G`,
  `PgUp/PgDn`, and `Enter` when findings are active; ModuleRun advertises
  `1..4` actor drill-in plus `p` or `r` only when pause/resume is available.
  Validation passed: `cargo test -p kuzushi-tui keybind`,
  `cargo test -p kuzushi-tui renderer::tests`, and
  `cargo fmt --all --check`.
- RTUI-001: Scripted/plain shell output now renders one strict plain command
  result block per submitted command. Each block includes the submitted command,
  new log entries from that command, and the resulting view snapshot, preserving
  no ANSI, no box drawing, and width-safe lines. Regression coverage now
  includes `/nope`, `/quit`, `/help` followed by `/quit`, and `/back` as an
  unchanged-view command at both TUI helper and CLI cutover levels. Validation
  passed: `cargo test -p kuzushi-tui plain`,
  `cargo test -p kuzushi-cli --test cutover_cli plain`, and
  `cargo fmt --all --check`.
- RTUI-005: Replaced the fake ask test's sleep/poll loop with a test-only
  bounded `recv_timeout` helper over the existing agent worker channel. The
  test still proves immediate `AgentChat` running state before draining and
  final answered state after the worker event. Diagnostics now include timeout,
  disconnected-worker, UI state, and recent log context. Validation passed:
  `cargo test -p kuzushi-tui app::tests`,
  `cargo test -p kuzushi-tui ask_dispatches_agent_question_through_explicit_runtime -- --nocapture`,
  `cargo test -p kuzushi-tui app::tests` again, and
  `cargo fmt --all --check`.
- RTUI-004: `/help` now renders parser-backed aliases/examples from
  `ShellCommandSpec.aliases` in TUI help and strict plain help. Featured
  examples include `scan .`, `use semgrep`, `run .`, `findings`,
  `open F-0001`, and `model 1`; category-sampling tests prove representative
  aliases appear in `/help` without advertising removed TypeScript/Ink
  commands. Validation passed: `cargo test -p kuzushi-tui help`,
  `cargo test -p kuzushi-tui commands::tests`, and
  `cargo fmt --all --check`.
- RTUI-006: Strict plain output now wraps non-table guidance/help lines instead
  of applying blanket truncation. Plain help uses a full command/alias/examples
  layout, while table-cell truncation remains limited to table-like rows. Added
  tests for wrapped context, workspace, and help guidance. Validation passed:
  `cargo test -p kuzushi-tui plain`,
  `cargo test -p kuzushi-cli --test cutover_cli plain`, and
  `cargo fmt --all --check`.
- RTUI-002: Added deterministic viewport offsets for Help, Tools, expanded
  Modules, History, and KB. Findings now renders a cursor-centered visible
  window, keeps the cursor row visible after j/k/g/G/PgUp/PgDn, and Enter opens
  the cursor-visible finding from the rendered list. Footer copy now advertises
  PgUp/PgDn scrolling on scrollable views. Validation passed:
  `cargo test -p kuzushi-tui viewport`,
  `cargo test -p kuzushi-tui renderer::tests`, and
  `cargo fmt --all --check`.
