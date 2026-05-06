# Rust TUI UI/UX Audit

Date: 2026-05-06
Scope: Rust `ratatui` shell only: `crates/kuzushi-tui`, the Rust CLI shell
handoff, command/help truth, plain-mode accessibility, renderer behavior, and
existing Rust TUI tests.

## Summary

The Rust TUI is in materially better shape than a raw migration shell: command
grammar is centralized, the shell avoids decorative box dashboards, startup
guidance names real first-run commands, abort language is honest, stable finding
aliases are covered, and strict plain-mode tests already enforce no ANSI or box
drawing.

The biggest remaining UX risks are operational rather than cosmetic:

1. Plain/scripted mode can hide command feedback, including errors and exit
   acknowledgements.
2. Long routed views are clipped with no viewport, so help/tools/findings can be
   unreachable in a normal terminal.
3. The keybind footer has drifted from the actual hotkeys.
4. `/help` hides supported aliases and examples that materially improve
   discoverability.
5. One async agent test is timing-sensitive under the full TUI app test suite.

## Findings

### F1 - High: plain/scripted mode hides command feedback

Plain mode is the accessibility and low-bandwidth surface, but command results
that live only in the transcript are dropped from rendered output.

Evidence:

- `run_plain_shell` submits each command and prints only `render_plain_app`
  after the command; it does not print the command or the new log entries
  produced by that command (`crates/kuzushi-tui/src/app.rs:4687`).
- Unknown commands only call `self.log("error", ...)`
  (`crates/kuzushi-tui/src/app.rs:661`).
- `render_plain_lines` renders the current `ShellView` and has no transcript/log
  section (`crates/kuzushi-tui/src/renderer.rs:229`).

Validation:

```sh
printf '/nope\n/quit\n' | cargo run -q -p kuzushi-cli -- --plain shell --target /private/tmp/kuzushi-tui-audit
```

Observed output rendered the catalog twice. It did not show the unknown-command
error or the exit acknowledgement, even though both are logged in app state.

Impact:

- Screen-reader users cannot reliably tell whether a command succeeded, failed,
  or exited.
- Scripted/plain output is hard to correlate because snapshots are printed
  without the command that caused them.
- Error-path work already present in `ShellApp` is lost on the mode that most
  needs explicit text.

Recommended fix:

- Add a plain command-result renderer that prints `> <command>`, then new log
  entries since the command began, then the view snapshot when useful.
- Include at least the last 3-5 transcript lines for plain mode even when no
  command is supplied.
- Add tests for `/nope`, `/quit`, `/set`, and an unchanged-view command from
  `History` or `Help`.

### F2 - High: long views are clipped with no scroll/viewport model

Status: fixed by RTUI-002 on 2026-05-06. Help, Tools, expanded Modules,
Findings, History, and KB now render deterministic viewports; Findings keeps
the cursor-visible row in view and Enter opens that visible row. Validation
passed: `cargo test -p kuzushi-tui viewport`,
`cargo test -p kuzushi-tui renderer::tests`, and `cargo fmt --all --check`.

The renderer clamps the main view to available terminal height, but routed views
build full line lists and `render_lines` draws from the top with no offset.

Evidence:

- `render_app` computes `max_view_height` and clamps `view_height`
  (`crates/kuzushi-tui/src/renderer.rs:53`).
- `render_lines` renders the supplied lines directly with no scroll offset
  (`crates/kuzushi-tui/src/renderer.rs:2589`).
- `/help` emits every command row (`crates/kuzushi-tui/src/renderer.rs:1368`).
- `/findings` emits every finding row, plus detail/evidence rows
  (`crates/kuzushi-tui/src/renderer.rs:1006`).
- Findings cursor/PageUp/PageDown state exists
  (`crates/kuzushi-tui/src/app.rs:3835`), but the renderer does not slice around
  `findings_cursor`.

Impact:

- In a typical 24-row terminal, `/help`, `/tools`, expanded `/modules`, and
  non-trivial `/findings` lists can be partially unreachable.
- `j/k/g/G/PageUp/PageDown` can move the findings cursor to an off-screen row,
  leaving the operator with no visual confirmation before pressing Enter.

Recommended fix:

- Add viewport state for scrollable views, starting with Help, Tools, Modules,
  Findings, History, and KB.
- For findings, render a window centered on `findings_cursor`; PageUp/PageDown
  should update cursor and visible range together.
- Add footer hints for `↑/↓` or `j/k`, `PgUp/PgDn`, and `Enter` only on views
  where those keys work.
- Add 24-row renderer tests with more rows than fit, asserting the selected row
  remains visible after cursor movement.

### F3 - Medium: keybind footer does not match actual hotkeys

The keybind footer is helpful, but several high-value hotkeys are either hidden
or advertised in command form rather than key form.

Status: Fixed by RTUI-003 on 2026-05-06. The Rust TUI now uses shared
view-keybinding descriptors for both state transitions and footer hints, so
Findings advertises `j/k/g/G`, `PgUp/PgDn`, and `Enter` when findings are
active, while ModuleRun advertises `1..4` actor drill-in plus `p` or `r` only
when pause/resume is available.

Evidence:

- `ShellApp::view_keybindings` is the shared source for Findings, Threat, and
  ModuleRun view hotkeys (`crates/kuzushi-tui/src/app.rs:1746`).
- `handle_view_hotkey` and `apply_view_hotkey` execute those descriptor actions
  (`crates/kuzushi-tui/src/app.rs:4168`,
  `crates/kuzushi-tui/src/app.rs:4184`).
- The footer renderer consumes the same descriptors through
  `push_view_keybindings` (`crates/kuzushi-tui/src/renderer.rs:2700`,
  `crates/kuzushi-tui/src/renderer.rs:2850`).
- Tests prove the advertised Findings and ModuleRun descriptors trigger real
  state transitions and render the expected footer hints
  (`crates/kuzushi-tui/src/app.rs:9055`,
  `crates/kuzushi-tui/src/app.rs:9247`,
  `crates/kuzushi-tui/src/renderer.rs:4232`,
  `crates/kuzushi-tui/src/renderer.rs:4266`,
  `crates/kuzushi-tui/src/renderer.rs:4290`).

Original impact:

- Operators are less likely to discover the efficient keyboard path.
- The footer can suggest typing a command (`actor 1`) when the implementation
  actually handles a bare digit hotkey.

Resolution:

- Shared descriptors now drive both `handle_view_hotkey` and `keybindings`.
- Footer hints use literal bare keys (`1..4`, `p`, `r`, `j/k/g/G`,
  `PgUp/PgDn`, `Enter`) for bare-key actions.
- Validation passed: `cargo test -p kuzushi-tui keybind`,
  `cargo test -p kuzushi-tui renderer::tests`, and
  `cargo fmt --all --check`.

### F4 - Medium: `/help` hides aliases and examples

Status: fixed by RTUI-004.

The command catalog stores aliases, but the help renderer only shows the primary
command and description.

Evidence:

- `ShellCommandSpec` includes aliases such as `/h`, `/m`, `/f`, `q`,
  `auth codex`, `findings export <path>`, and `?text`
  (`crates/kuzushi-tui/src/commands.rs:122`).
- `help_lines` renders only `spec.command` and `spec.description`
  (`crates/kuzushi-tui/src/renderer.rs:1379`).

Validation:

```sh
printf '/help\n/quit\n' | cargo run -q -p kuzushi-cli -- --plain shell --target /private/tmp/kuzushi-tui-audit
```

Observed help output showed grouped commands, but not the aliases that are
already accepted by the parser.

Impact:

- The fastest commands remain hidden from new users.
- Parser/help drift is harder for maintainers to spot because aliases are not
  user-visible.

Recommended fix:

- Add an alias/example column in help, width-aware for TUI and wrapped for
  plain mode.
- For dense terminals, show one or two high-value aliases inline and push the
  rest into a `help <command>` detail view later if needed.
- Add a help test that samples aliases from each category and asserts they are
  visible somewhere in `/help`.

Resolution:

- Rust `/help` now renders an alias/example column from
  `ShellCommandSpec.aliases` and a compact examples row for `scan .`,
  `use semgrep`, `run .`, `findings`, `open F-0001`, and `model 1`.
- TUI and strict plain help paths have width-safe tests, including alias samples
  from every command category and negative checks for removed TypeScript/Ink
  command advertising.

### F5 - Medium: full app test suite has a timing-sensitive async agent test

The complete TUI app test target exposed a flaky async-agent state assertion.

Validation:

```sh
cargo test -p kuzushi-tui app::tests
```

Historical observed result: 105 tests passed and
`app::tests::ask_dispatches_agent_question_through_explicit_runtime` failed
because `agent.running` was still `true`.

The same test passed when run alone:

```sh
cargo test -p kuzushi-tui ask_dispatches_agent_question_through_explicit_runtime -- --nocapture
```

Evidence:

- Agent questions spawn a worker thread (`crates/kuzushi-tui/src/app.rs:1488`).
- The test waits up to roughly 500ms by repeatedly calling
  `drain_background_events` (`crates/kuzushi-tui/src/app.rs:7363`).
- Background events are consumed via `try_recv` and clear `agent_rx` only after
  `agent.running` flips false (`crates/kuzushi-tui/src/app.rs:1076`).

Impact:

- CI can become noisy even when the user-facing behavior is correct.
- A timing-sensitive assertion can mask real regressions in agent-mode status
  rendering or abort handling.

Recommended fix:

- Make the test deterministic by using a longer bounded wait helper, a channel
  completion barrier, or serializing the fake bridge tests.
- Assert the intermediate `running` state separately from final completion so a
  slow worker failure gives a clear diagnostic.

RTUI-005 resolution:

- The fake ask test now uses a test-only bounded `recv_timeout` helper on the
  existing agent worker channel instead of the sleep/poll loop.
- The test asserts immediate `AgentChat` running state before any drain, then
  separately asserts final answered state after the worker event is applied.
- Timeout and disconnected-worker failures include `AgentChat` state and recent
  log context. Agent failures still flow through `AgentEvent::Failed` and are
  asserted as failures rather than being masked.

### F6 - Low: strict plain output over-truncates important help and guidance

Plain output enforces line width, which is correct for low-bandwidth mode, but
it truncates instead of wrapping important instructions.

Evidence:

- `render_plain_lines` applies `fit` to every line
  (`crates/kuzushi-tui/src/renderer.rs:247`).
- Validation output truncated command shapes and guidance, for example
  `workspace export findings <...` and long context instructions ending in
  `context-s...`.

Impact:

- The mode intended for accessibility can omit the end of command examples,
  paths, and next-step text.

Recommended fix:

- Keep the 80-column guarantee, but wrap plain-mode command and guidance lines
  instead of truncating them.
- Reserve truncation for table cells where full detail is available in a nearby
  detail command.

## What Is Working Well

- Rust CLI cutover is cleanly separated from retained TypeScript/Ink references.
- Command specs are centralized and tested against parser route coverage.
- Renderer tests cover core views, narrow catalog rendering, strict plain output,
  stable aliases, empty states, model onboarding, abort states, and run routing.
- First-run copy names real commands: `scan`, `scan .`, `findings`,
  `context build`, and `model`.
- Abort language avoids claiming a process was killed when only an abort request
  has been issued.

## Implementation Roadmap

### 1. Repair Plain Mode Feedback

- Change `run_plain_shell` to track `before_log_len`, submit the command, drain
  events, then render a command result block:
  - `> <command>`
  - new log lines since `before_log_len`
  - view snapshot when the command changed view or the command explicitly asks
    for a view
- Ensure `/quit`, unknown commands, unsupported commands, and no-op commands all
  produce visible plain output.
- Add tests in `crates/kuzushi-tui` and `crates/kuzushi-cli/tests/cutover_cli.rs`
  for unknown command, quit, help followed by quit, and history-view error.

### 2. Add Viewport State For Long Views

- Introduce scroll/viewport state on `ShellApp` for generic long views and a
  cursor-coupled findings viewport.
- Implement `PageUp`, `PageDown`, `Home`/`End` or `g`/`G` consistently where
  the footer advertises them.
- Add 24-row `TestBackend` cases for `/help`, `/tools`, `/modules`, and
  `/findings` with more rows than fit.

### 3. Unify Hotkey Hints With Handlers

- Create a small hotkey descriptor per routed view and use it from both
  `handle_view_hotkey` and `keybindings`.
- Correct the running footer to advertise `1..4 actor`, `p pause`, `r resume`
  when available.
- Correct findings footer to advertise `j/k`, `PgUp/PgDn`, and `Enter`.

### 4. Improve Help Discoverability

- Render aliases/examples from `ShellCommandSpec.aliases`.
- Add category-specific examples for the highest-traffic flows:
  `scan`, `use semgrep`, `run .`, `findings`, `open F-0001`, `model`.
- Add tests that `/help` displays sampled aliases from every category.

### 5. Stabilize Async Agent Tests

- Replace the 500ms loop in the fake ask test with a deterministic wait helper
  or a completion channel.
- Keep a separate assertion that the UI enters `AgentChat` immediately, then a
  separate completion assertion after the worker is known to have returned.

## Validation Run

Commands run during this audit:

```sh
cargo test -p kuzushi-tui renderer::tests
cargo test -p kuzushi-tui commands::tests
cargo test -p kuzushi-cli --test cutover_cli plain_flag_forces_line_oriented_shell_output
cargo test -p kuzushi-cli --test cutover_cli plain_env_aliases_are_line_oriented_for_screen_reader_mode
cargo test -p kuzushi-tui ask_dispatches_agent_question_through_explicit_runtime -- --nocapture
cargo test -p kuzushi-tui app::tests
cargo test -p kuzushi-tui app::tests
cargo fmt --all --check
printf '/help\n/quit\n' | cargo run -q -p kuzushi-cli -- --plain shell --target /private/tmp/kuzushi-tui-audit
printf '/modules\n/use semgrep\n/options semgrep:scan\n/tasks\n/quit\n' | cargo run -q -p kuzushi-cli -- --plain shell --target /private/tmp/kuzushi-tui-audit
printf '/workspace\n/context\n/kb\n/history\n/nope\n/quit\n' | cargo run -q -p kuzushi-cli -- --plain shell --target /private/tmp/kuzushi-tui-audit
printf '/nope\n/quit\n' | cargo run -q -p kuzushi-cli -- --plain shell --target /private/tmp/kuzushi-tui-audit
```

Results:

- Renderer tests: 27 passed.
- Command parser/catalog tests: 5 passed.
- Plain flag CLI test: passed.
- Screen-reader env plain-mode CLI test: passed.
- Single fake-ask async test: passed.
- Full `app::tests`: passed twice; latest run on this worktree reported 110
  passed.
- Rust format check: passed.
- Scripted plain validation exposed missing error/exit feedback in plain output.
