# Kuzushi TUI UX Audit

**Branch:** `claude/investigate-tui-ux-NqMt1`
**Method:** tmux-driven black-box + source review.
**Binary:** `./target/debug/kuzushi shell` (Rust native CLI; the `bin/kuzushi-rs.mjs` wrapper resolves to this binary).

## Auth path used

Kuzushi exposes Claude via Anthropic OAuth through:
- In-shell verb: `auth login anthropic` — shells out to `node scripts/pi-agent-core-bridge.mjs --oauth-login anthropic` and writes `~/.kuzushi/oauth-credentials.json`.
- Then `model 5` (Claude Sonnet 4.6) or `model 6` (Claude Opus 4.7).
- There is **no `kuzushi shell --model claude-oauth` flag**; model selection is in-shell. The CLI `kuzushi auth ping anthropic` validates credentials.
- For this audit, OAuth is **unconfigured** in the sandbox (no `~/.kuzushi/oauth-credentials.json`, no `ANTHROPIC_API_KEY`). That is itself a real first-run state and is exercised below.
- The CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR provided by the harness is for the parent claude-code agent, not Kuzushi's bridge — it cannot be reused.

The shell intentionally still works without auth for static-scanner flows. Many UX issues below are precisely about how the TUI fails when auth is needed but absent.

## Method

1. `tmux new-session -d -s kuzushi -x 120 -y 40`
2. `tmux send-keys -t kuzushi './target/debug/kuzushi shell' C-m`
3. `tmux capture-pane -t kuzushi -p` after each interaction.
4. Resize between passes with `tmux resize-window -t kuzushi -x <w> -y <h>` to test viewport behaviour.

---

## Pass 1 — startup, help, empty states (timestamp: 2026-05-07T01:58Z)

**tmux setup:**
- `tmux new-session -d -s kuzushi -x 120 -y 40`
- `tmux send-keys -t kuzushi './target/debug/kuzushi shell' C-m`

### P1-1 — `[PgUp/PgDn] scroll` keybind hint is a lie for Help, Catalog, Tools, History, KB, ModuleRun, Story, Threats. **[P0 — fixed]**

Expected: PageDown scrolls the visible view per the keybind footer.

Actual: For these views, `viewport_lines(..., area.height, app.help_scroll)` (resp. `tools_scroll`, `modules_scroll`, `history_scroll`, `kb_scroll`) reads dedicated `*_scroll` fields, but `page_down_current_view` calls `scroll_down(...)` which only mutates `app.scroll_offset`. The dedicated fields are reset to 0 on entry and never advance. Catalog has 35 modules (`module showing 35 module(s)` log line) but the visible viewport caps at OFFENSE+INTEL groups (~21 lines); GOVERNANCE and DEFENSE are unreachable.

Repro:
```
help          # scroll into HELP view
PageDown      # nothing changes
```
Same for `modules` then `PgDn`.

Source: `crates/kuzushi-tui/src/renderer.rs:204,219,221,227,231` use the dedicated scroll fields; `crates/kuzushi-tui/src/app/state_transitions.rs:443-464` only updates `scroll_offset`.

Fix: route page-down/page-up to the matching dedicated field per view.

### P1-2 — Status footer says `catalog` while you're in HELP/TOOLS/etc. **[P1 — fixed]**

The bottom status footer shows the focused module or "catalog" instead of the actual `shell_view`. After typing `help` you see:
```
mode:shell · target:none · ctx: missing · catalog
```
…even though the visible view is HELP. Same for TOOLS, FINDINGS (when the user has no focused module), CONFIG, RUNS. This breaks orienting users in deep navigation.

Source: `crates/kuzushi-tui/src/renderer.rs:1968-1970` chooses `focused_module || "catalog"`.

Fix: show the real view label (`help`, `tools`, etc.). Use focused_module only when the view is module/module-run.

### P1-3 — Two near-identical "first finding" hints stack at startup. **[P3]**

Top of catalog view shows `▸ NEXT First finding: run \`scan .\`, then \`findings\`.`. The transcript footer also shows ` · first-run First finding: run \`scan .\`, then \`findings\`.`. Same string twice. The second one is permanent until cleared.

Fix: drop one (the transcript copy), or rotate the hint after first execution.

### P1-4 — Compact help log line is silently truncated mid-token. **[P2 — fixed]**

The startup `help` log message:
```
/scan, /run <tool>, /ask <question>, ?text, /workspace, /context build, /tasks, /options [tool], /auth login ope
```
…is cut at `/auth login ope`. The transcript prints exactly one terminal-width column, then drops. There is no overflow indicator (`…` / `+more`), and the user cannot scroll the log line. They learn no more about commands than what's truncated.

Source: `crates/kuzushi-tui/src/app.rs:521-526` builds an indefinitely long help string. Renderer trims to width.

Fix: shorten the boot message to a discoverable hint (`type help for full command list`) or wrap it.

### P1-5 — Header reads `KUZUSHI · CATALOG · kuzushi shell`. **[P3]**

The third segment is a tautology — we already know it's the shell because we're in the kuzushi shell. The space is better used for version, target name, or model.

### P1-6 — Catalog "drop" of view title means user typed `help` but title still says `KUZUSHI · CATALOG`. Wait, actually it changes. **[ok]**
After verification, `KUZUSHI · CATALOG` is replaced with `───── HELP ─────`. Top header `module catalog` is still stuck though (see P1-2).

### P1-7 — `▸ NEXT Run sast against the active target — Full SAST pipeline: ...` hint is cut with `...`. **[P3]**
Truncating at 88 chars per `short_sentence(..., 88)` is fine when terminal is wider than 88 chars, but on width=120 we should be using more characters. `short_sentence` is fixed-width; it doesn't pass `area.width`.

Source: `crates/kuzushi-tui/src/renderer.rs:355-356` — `short_sentence(&module.metadata().description, 88)`.

### P1-8 — Top header sees `module catalog` not just `catalog`. **[P3]**
The phrase is slightly tautological (`module catalog`) and inconsistent with the bottom status (`catalog`). Pick one.

### P1-9 — Top header has cost `$0.0000`. **[P3]**
4 decimal places at $0.0000 is meaningless boilerplate. Hide cost when `session_cost_usd == 0` and target is none.

### P1-10 — Initial transcript already includes `system / startup / first-run / help` rows; that's 4 log entries before the user's first action. **[P3]**
Most TUIs (Claude Code, Codex CLI, Aider) start with at most one welcome line. This is noisy.


## Pass 2 — Auth, OAuth flow, navigation, error states (timestamp: 2026-05-07T02:00Z)

### P2-1 — Subprocess output corrupts the TUI canvas. **[P0 — fixed]**

`auth login anthropic` shells out to `node scripts/pi-agent-core-bridge.mjs --oauth-login anthropic` with `Stdio::inherit()`. The bridge writes the OAuth URL and (when a browser cannot launch) a Node stack trace directly to stdout/stderr. The result on a 120×40 tmux pane:

```
backend pi-agent-core─────────────────────────────────────────────────
provider unconfigured                          d>] focus module  ·  …
oauth openai-codexdmissing;9anthropicemissingse_type=code&redirect_uri…
   3r:openai-codex:gpt-5.5NTxhigh  OAuth missing
   4atopenai-codex:gpt-5.5-minixihighodOAuthemissingild_process:285:19)
```

i.e. every ratatui-row is overwritten in place, but the bridge's stdout text is interleaved per-cell so the canvas becomes unreadable. The TUI does not toggle the alternate screen, so the bridge's text persists after raw mode is re-enabled (`crates/kuzushi-tui/src/app.rs:2611-2622`). The next ratatui frame's cell-diff updates only changed cells, so the bridge's bytes survive forever.

This makes the entire "no browser reachable; paste the redirect URL fragment" recovery path unusable.

Source: `crates/kuzushi-tui/src/app.rs:2611-2622` (`handle_auth_login_command`).

Fix options (we go with the first):
1. **Force a full clear+redraw on raw-mode re-enable.** Cheapest, preserves the existing inherit-stdio interactive UX of the bridge.
2. Pipe the bridge's stdout/stderr and surface the URL/error inside the log.
3. Move to alternate screen permanently and route the bridge through a shell-out screen.

### P2-2 — OAuth bridge dies hard when no browser is reachable. **[P1]**

In headless containers the bridge calls `spawn('xdg-open', URL)`; if that fails it crashes with an unhandled `ENOENT` and an unactionable `auth login exited with exit status: 1. Next: auth status`. The URL is dumped above in the trace but the user has no way to copy it cleanly.

Fix: bridge should fall back to printing a "open this URL on a different machine" line + "paste callback code here:" prompt (it already supports paste-fallback per the visible "If the browser cannot reach the local callback, paste the final redirect URL or code#state fragment." hint, but the failure happens before the prompt is shown).

Out of scope for this Rust-TUI audit — file as a node bridge bug.

### P2-3 — `findings` silently sets `target` to `.` if none is set. **[P2]**

Repro: start `kuzushi shell` with no `--target`, type `findings`. The target jumps from `none` → `./Kuzushi` (cwd) without any "set target to ." log entry. The user looking at the header `target none → target ./Kuzushi` sees a phantom assignment.

Source: `crates/kuzushi-tui/src/app.rs:3991-4000` `open_store -> current_workspace -> "."` and silently writes back to `self.target`.

Fix: log the implicit target assignment ("target ./Kuzushi (implied from cwd)") or refuse to load findings until the user runs `target .`.

### P2-4 — `auth` is a misleading verb. **[P2]**

Typing `auth` opens the CONFIG view (with the model picker), not an "auth status" panel. Users who type `auth` to check OAuth status see a model menu and a small line buried in CONFIG. The verb's own help text is `show env/OAuth status without secrets` which suggests a focused screen.

Fix: split — make `auth` show an auth-only summary view with provider OAuth + env-var status; keep model selection in `model`/`config`.

### P2-5 — MODELS table column alignment is broken. **[P2 — fixed]**

The header row uses fixed alignment:
```
                #               model           effort          auth
>  1  openai:gpt-5.5  xhigh  OPENAI_API_KEY missing
```
…rows separate columns with single spaces, header uses tabs/wide padding. Numbers don't line up with `#`, names don't line up with `model`, etc. Fix is a small render alignment change.

Source: `crates/kuzushi-tui/src/renderer.rs` config_lines / models_table.

### P2-6 — Selected-model arrow `>` is hard to read on the catalog. **[P3]**

`>  1  openai:gpt-5.5` — the `>` is rendered as `Span::raw` inside a styled cell. With a dense palette it disappears. A filled triangle ▶ or reverse-styled row would be clearer.


## Pass 3 — keyboard ergonomics, cursor, escape, resize (timestamp: 2026-05-07T02:01Z)

### P3-1 — Visual cursor does not follow `app.cursor`. **[P0 — fixed]**

Repro at width 120:
```
type "abcdef"
press Left Left
```
The internal `app.cursor` is decremented and a subsequent keypress is correctly inserted between `d` and `e`, but the **rendered cursor highlight does not move** — the styled cell stays after `f`. ANSI capture confirms only the trailing position is reverse-video styled regardless of `app.cursor`.

Source: `crates/kuzushi-tui/src/renderer.rs:2031` calls `prompt_segments(&prompt, &app.input, area.width as usize, " ")` without passing `app.cursor`. Inside `prompt_segments` (line 2914-2949) the function hard-codes:
```rust
let cursor = input_chars.len();   // line 2926 — always end-of-input
```

So the visible cursor highlight is always at the end of the input regardless of where the operator's logical cursor is. This silently breaks Home/End, ←/→, Ctrl-A/E/B/F navigation: the editing logic works, but the user can't see where they're typing without inserting a probe character. For an interactive shell this is a serious confidence killer.

Fix: thread `app.cursor` through `prompt_segments`; window-slide based on the supplied cursor.

### P3-2 — `Esc` immediately wipes a partially typed command with no undo. **[P2]**

Repro:
```
type a long carefully-built command, accidentally hit Esc
```
The whole input vanishes (`KeyCode::Esc => self.clear_input()` at `crates/kuzushi-tui/src/app/state_transitions.rs:330-332`). There is no recovery: arrow-up returns history, not the last draft. Compare to readline / Claude Code where Esc dismisses popups but preserves the line.

Fix: bind Esc to "dismiss popups / clear status" only, or stash the cleared draft in `history_draft` and restore on the next Esc press.

### P3-3 — No Tab cycling between completion candidates. **[P3]**

`Tab` after `use ` completes to `agentic-sast`. Pressing Tab again does nothing — no second candidate, no popup with options, no Shift+Tab to go back. For a 35-module catalog this is a missed affordance.

### P3-4 — `kill_to_start` (Ctrl-U) goes from cursor to BOL only. **[P3]**

Most readline-y shells make Ctrl-U kill the entire line (independent of cursor). With Kuzushi:
```
type "abc def ghi"
Ctrl-A   (cursor → start)
Ctrl-U   (no-op because cursor already at start)
```
This is technically POSIX but breaks the ⟨any-time-clear⟩ muscle memory of bash/zsh's emacs binding. Either (a) match readline `unix-line-discard` semantics (kill from cursor to BOL — what Kuzushi already does), but ensure C-x C-u or just `clear-line` is bound. Currently there is **no full-line kill keybind**.

Fix: add Ctrl-X Ctrl-U or Ctrl-Shift-U as full-line kill, or just make Ctrl-U kill the whole line as bash/zsh defaults do.

### P3-5 — Ctrl+C arming text appears in red overlay but log only says nothing about it. **[P3]**

When Ctrl-C is armed, the status bar correctly flips colour and shows "Ctrl+C again to exit" (good). But there's no log entry, so if a user briefly looks away they miss the cue. Adding a one-line transcript entry "↩ Ctrl+C armed (2s)" would help.

### P3-6 — Resizing the terminal: keybind footer drops messages without a scroll affordance. **[P2]**

```
tmux resize-window -t kuzushi -x 60 -y 40
```
At width 60, the keybind footer truncates to:
```
[Tab] complete  ·  [modules] browse  ·  [use <id>] focus
```
the rest of `[scan] / [Ctrl+C]` is lost without ellipsis. At width 40 the status bar/header collapses similarly. There is no fallback to a 2-line keybind footer or rotating tip. **Fix:** clip with an ellipsis or split into two rows.

### P3-7 — Catalog hint `Quickstart: quickstart · Context: context build · Runtime: model` reads weird. **[P3]**

It looks like noun:verb pairs but `Quickstart: quickstart` is odd phrasing. Better: `quickstart for first-run · context build for local indexing · model to pick a model`.


## Pass 4 — error states, invalid input, scan failures, quickstart (timestamp: 2026-05-07T02:03Z)

### P4-1 — Quickstart prints 8 lines to a 2-row transcript and only the last 2 are visible. **[P1]**

Repro:
```
quickstart
```
The screen switches to HELP and 8 transcript log entries are added (`Welcome to kuzushi!`, then 5 numbered steps, a Ctrl+O hint, and a "first-finding path" line). Outside of `ModuleRun`, the transcript area is hard-coded to **2 rows** (`crates/kuzushi-tui/src/renderer.rs:29-35`). The user only sees:
```
 · quickstart Press Ctrl+O to toggle the live event timeline.
 · quickstart Exact first-finding path: scan -> findings
```
Six of the eight lines never reach the screen. The transcript is not scrollable.

Source: `crates/kuzushi-tui/src/app.rs:2343-2366` writes log lines that the renderer drops.

Fix options:
1. Make `quickstart` a dedicated `ShellView::Quickstart` that uses the full view area (preferred — also enables an interactive wizard later).
2. Bump the transcript area height for the few frames after a quickstart-emit.
3. Make the transcript scrollable (orthogonal but useful).

### P4-2 — Catalog hides ~10 modules without telling the user. **[P2]**

`kuzushi modules` lists 35 modules. The shell catalog only categorises 27 into OFFENSE/INTEL/GOVERNANCE/DEFENSE buckets via `catalog_module_category` (`crates/kuzushi-tui/src/renderer.rs:2570-2592`); modules whose `kind` doesn't fit (`catalog`, `classifier-gate`, `config`, `deep-audit`, `findings`, `patch`, `router`, `smoke`, `triage`, `verify`, `workspace`, `vendor-assessment`, `shinsa`) silently drop into "GOVERNANCE/DEFENSE" via the kind fallback — but at default 40-row height the GOVERNANCE and DEFENSE blocks are below the fold and PgDn is broken (P1-1), so the user can never see them.

Combined with P1-1, the operator literally cannot discover ~10 modules from inside the shell.

### P4-3 — `[A]` glyph in `tasks` view is unexplained. **[P2]**

`/tasks` lists scanner tasks with state column `[x]` (selected) or `[A]` (advanced). There is no legend, no key explaining what `[A]` means, and the keybind footer does not list `/task toggle`. Operators have no way to discover the difference between `[x]` and `[A]` without reading source.

Source: `crates/kuzushi-tui/src/renderer.rs` `sast_tasks_lines` — needs a legend row.

### P4-4 — Scan failure error message is silently truncated. **[P2]**

After `scan .` with no semgrep installed:
```
✗ error semgrep: could not find scanner binary "semgrep". Install Semgrep (for example `pipx install semgrep` or `brew
```
…the line ends mid-word; the `or brew install semgrep` continuation is invisible. Same in transcript and module-run progress panel. The actual user-actionable hint (`pipx install semgrep` or `brew install semgrep`) is partially clipped.

Fix: wrap long error messages on word boundaries; the renderer's `fit` truncates instead.

### P4-5 — `unknown command "doctor"` recommends `/ask <question>`. **[P2]**

The user types `doctor` (a real `kuzushi doctor` subcommand). The shell rejects with:
```
unknown command "doctor". Free-form chat is explicit only. Next: /ask <question> or help
```
The hint suggests "ask the agent" — wrong for an operator who wants the doctor diagnostics. A better message lists `kuzushi doctor` as the CLI verb that does this and points at `auth`/`config` for in-shell health checks.

### P4-6 — Empty-target `findings` flips the global target without notice. **[P2 — duplicate of P2-3]**

(see Pass 2)

### P4-7 — Cost field eats the entire top-header tail at width=120. **[P2]**

Top header at width 120:
```
KUZUSHI  mode:shell · target ./Kuzushi · 0 findings · ctx ✓ present · module context · model unconfigured · cost $0....
```
`cost $0.0000` is 12 chars and at the end; once the segments before it use ~108 chars, the cost gets cropped to `cost $0....`. Showing 4 zeros at start-up is wasteful; collapsing to `cost —` or `cost $0` (or omitting until non-zero) frees ~6 chars and the header can fit `model unconfigured` without truncation.


---

## Fixes Implemented in this Branch (claude/investigate-tui-ux-NqMt1)

| Issue | Severity | File(s) | Test |
|-------|----------|---------|------|
| **P3-1** Visual cursor highlight didn't follow `app.cursor` | P0 | `crates/kuzushi-tui/src/renderer.rs` `prompt_segments` accepts `cursor_index`; call site passes `app.cursor` | `prompt_segments_highlight_follows_app_cursor` |
| **P1-1** PageUp/PageDown didn't scroll Help/Catalog/Tools/History/KB | P0 | `crates/kuzushi-tui/src/app/state_transitions.rs` `page_up_current_view`/`page_down_current_view` route to per-view fields; `is_scrollable_view` includes Catalog when expanded | `page_keys_scroll_view_offset` (extended) |
| **P1-2** Status footer always read `catalog` instead of the actual view | P1 | `crates/kuzushi-tui/src/renderer.rs` new `view_status_segment` helper called from status footer | `view_status_segment_reflects_actual_view_not_focused_module` |
| **P2-1** OAuth bridge stdout corrupted the TUI canvas | P0 | `crates/kuzushi-tui/src/app.rs` `handle_auth_login_command` clears the screen and sets `force_full_redraw`; `run_shell_with_plain` calls `terminal.clear()` to invalidate ratatui's diff buffer before the next draw | covered by manual TUI verification |
| **P1-4** Boot help log line was a 200+ char unreadable truncated wall | P2 | `crates/kuzushi-tui/src/app.rs` constructor — replaced with `type help for commands · ? <text> to ask · scan to start` | n/a |
| **P2-5** MODELS table columns didn't align (header tabs vs row spaces) | P2 | `crates/kuzushi-tui/src/renderer.rs` new `aligned_header`/`aligned_row` helpers called from MODELS table | covered by manual TUI verification |

All fixes preserve the existing architecture (no new abstractions introduced beyond the two `aligned_*` row helpers).

### Test results
- `cargo test -p kuzushi-tui` → **169 passed, 1 pre-existing sandbox-only failure** (`run_command_dispatches_patch_through_pi_agent_core_bridge_and_persists` fails on the unmodified main branch too, due to `git commit` requiring a signing service this sandbox lacks).
- `cargo test --workspace --lib` → green (run in background during fix work).

### Manual retest

1. Boot — transcript is 4 lines instead of 5; the boot `help` line fits on one row.
2. `help` then `PageDown` — scrolls down to OPTIONS/TASKS/CONTEXT/KB groups.
3. `PageUp` walks back. Same with `modules` (catalog) — GOVERNANCE and DEFENSE blocks now reachable.
4. `auth` — MODELS table columns aligned cleanly.
5. `auth login anthropic` — no longer corrupts the canvas. Bridge stack trace flashes briefly before the redraw, then a clean `✗ error anthropic OAuth login exited with exit status: 1. Next: auth status` log line.
6. Type `abcdef`, press `Left Left` — visible cursor highlight moves from after `f` to between `d` and `f` (highlights `e`). Same for `Ctrl+A` (highlights `a`).
7. Status footer in any view now reflects the view: `help`, `tools`, `findings`, `threats:stride`, `tasks`, `config`, `run`, `kb`, etc., instead of the stuck `catalog` label.

