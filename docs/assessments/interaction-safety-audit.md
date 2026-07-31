# Interaction-safety audit — approval gate & cancellation

> Historical audit. Its two-stage idle Ctrl+C assessment is superseded:
> Ctrl+C/Ctrl+D now exit immediately when idle, cancel without exiting while
> work is active, and wait when cancellation is already pending.

Read-only audit of the Rust Ratatui shell (`crates/kuzushi-tui`). Scope: reflexive
keystrokes that can authorize a sensitive run or destroy in-flight work. No files were
edited.

## A. Approval prompt

The gate is `PendingConfirm`, stored on `advisory.pending_confirm` and minted by
`confirm_gate_for_tool(...)` before dispatch
(`app/tool_runner/run_tool/dispatch.rs:182`, `:196`). Key handling for the pending
confirm runs as a modal, *before* back-navigation: `handle_modal_key` →
`handle_shared_modal_key` → `handle_confirm_or_budget_key` → `handle_confirm_key`
(`app/state_transitions/key_dispatch.rs:92`, `:161`, `:173`, `:224`).

### Enter — safe (does not authorize)

`handle_confirm_key` looks up an action via `confirm_key_action(key.code)`. Enter maps
to **no action**; it falls to `confirm_key_is_consumed_without_action`, which returns
`true` only to *swallow* the keystroke (`confirmation_keys.rs:9-22`, `:55-57`;
dispatch at `key_dispatch.rs:228-233`). So Enter neither approves nor denies nor submits
the prompt line behind the gate. This is the desired behavior — there is **no**
"Enter = allow once" footgun. Test: `pending_confirm_enter_is_consumed_without_approval`
(`app/tests.rs:11795`) asserts the confirm stays pending, the input buffer is untouched,
and the allowlist stays empty.

Authorization requires an explicit, labeled character: `y` allow once, `Y` allow +
remember, `n` deny once, `N` deny + remember (`confirmation_keys.rs:24-53`). The dialog
renders `tool`, `target`, actor/rationale, and the literal legend
`y allow once · Y remember · n deny once · N deny + remember`
(`ui_view_models/confirm_dialog.rs:69-88`), so "this will run X" is on screen. Labeling
is adequate.

Two secondary observations (not footguns, but worth noting):
- The footer legend lists `Esc back` (`confirm_dialog.rs:107`) even though Esc **denies
  once** (see below). The label understates the consequence.
- Keyboard approval records the decision but does **not** re-launch the tool:
  `apply_confirm_key_action` calls `resolve_confirm(...)` and discards its return
  (`key_dispatch.rs:239-241`; `resolve_confirm` at `app/approval/label.rs:53`). With `y`
  (allow once, not remembered) nothing is added to the allowlist, so re-issuing the
  command re-triggers the gate — "allow once" never actually runs it once. Only `Y`
  (remember) makes a re-issue pass. Safe direction (under-authorization), but the "once"
  label is misleading.

### Esc — safe (explicitly denies, guarded against fall-through)

`confirm_key_action(KeyCode::Esc)` returns `outcome:false, remember:false`
(`confirmation_keys.rs:10-15`), i.e. **deny once**. Because `handle_confirm_key` returns
`true` (handled) whenever a confirm is pending (`confirm_key_ready` gate at
`key_dispatch.rs:235-237`), the Esc is consumed at the modal layer and **never reaches
back-navigation**. So Esc cannot silently leak past the gate by popping the view. Test:
`pending_confirm_esc_denies_once_without_navigation` (`app/tests.rs:11819`) asserts the
view is unchanged, the confirm is cleared, and the log shows "denied once". This is the
correct pending-confirm guard.

`DestructiveVerb` gates are refused unconditionally: `allows_yes()` is false and
`resolve_confirm` early-returns without running even on `y`
(`app/approval/label.rs:21-23`, `:53-65`).

**Verdict (A): sound.** Enter is inert, Esc denies-and-consumes, approval keys are
explicit and labeled. Fix only the cosmetics: relabel the footer `Esc deny` (not
`back`), and either make `y` add a one-shot allowlist entry that actually launches the
run or rename it so "once" isn't a false promise.

## B. Cancellation and runaway processes

### Can a live run be canceled from inside the TUI? Yes — two entry points.

1. `Ctrl+C` (and `Ctrl+D`) → `is_quit_chord` (`quit_chord.rs:3-6`) →
   `control_key_action` → `reduce_quit_chord` (`control_keys.rs:31-32`,
   `exit_requests.rs:150`).
2. The `cancel` verb (aliases `c`, `/c`, `stop`, `/stop`) →
   `ShellCommand::Cancel` → `ShellEffect::CancelActiveJobs`
   (`commands/shell_command_specs/mod.rs:140`, `session.rs:29-30`;
   `command_router/command_effects.rs:483`).

Both converge on `cancel_active_jobs_effect` → `request_active_abort()`
(`exit_requests.rs:20-33`), which fans out to scan/tool/agent/plan/threat aborts. Each
abort cancels the job token via `cancel_job_or_token` → `ScanCancellation::cancel()`
and sets an `abort_requested` flag (`exit_requests.rs:35-148`, `:236-241`).

### Is cancel a single reflexive keystroke that destroys work with no confirm?

Inside the **Activity view, no.** Its keymap has no cancel key: `Tab` pane focus,
`V` verbose, `Space` feed-pause, `x` **reset view**, `[`/`]` deck, `f` findings, `o`
open, `Enter` focus task (`view_keybinding_groups.rs:4-45`). Crucially `x` only resets
presentation — `reset_activity_view` logs "reset Activity view state; run preserved"
and touches nothing on the worker (`view_hotkey_actions.rs:554-561`). `Esc` in Activity
is back-navigation only; it leaves the view but does not cancel the run. So there is no
bare-letter footgun in Activity. (Note: `CLAUDE.md` claims uppercase `C` "arms
cancellation" in Activity — that binding does **not** exist in the current keymap;
the doc is stale.)

The one single-press cancel is **`Ctrl+C` while work is running**: `reduce_quit_chord`
takes the `has_abortable_work()` branch first and cancels immediately, with no confirm
(`exit_requests.rs:150-153`, `:165-171`). Test:
`ctrl_c_during_active_scan_requests_abort_without_arming_exit` (`app/tests.rs:10761`).
This matches universal terminal convention and it is a *modified* chord, not a reflexive
letter, and the abort is cooperative (findings already persisted), so the blast radius is
"lose the in-flight scan's remaining progress," not data corruption. Acceptable, but
given a scan can represent many minutes of work, an "arm then confirm" on the *first*
Ctrl+C during a run (mirroring the idle-exit arm) would be the safer mapping. The design
already protects the adjacent case: a second Ctrl+C after an abort is pending does **not**
quit — it logs "abort already requested… type `quit` to force exit" and waits
(`exit_requests.rs:173-186`; test `second_ctrl_c_after_scan_abort_request_keeps_waiting`,
`app/tests.rs:10807`).

### Does Ctrl+C exit cleanly (single vs double), and are children reaped?

**Exit is two-stage and correct.** At idle, the first Ctrl+C arms a 2-second window and
logs "press Ctrl+C again within 2s to exit (any other key cancels)"; it does not quit
(`exit_requests.rs:155-163`, `:266-272`; test `first_ctrl_c_at_idle_arms_without_quitting`,
`app/tests.rs:7290`). Any non-chord key disarms (`key_dispatch.rs:258-262`). The second
Ctrl+C within the window emits `RequestShellQuit`. Quit expands to
`RequestExitAbort → WaitForAbortCleanup → FinishShellQuit`
(`effect_runtime.rs:18-22`): abort tokens are cancelled, then the loop waits up to
**200 ms** for workers to report terminal, then quits regardless
(`exit_requests.rs:243-253`).

**Child-process reaping is uneven:**

- **Scanner subprocesses (semgrep/etc.) are reliably reaped.** They run in their own
  process group (`configure_scanner_process_group` sets `setpgid`, `try_wait.rs:65-74`)
  and are registered in the cancellation's child registry. `ScanCancellation::cancel()`
  synchronously `killpg(SIGKILL)`s every registered group
  (`scan_cancellation.rs:23-32`, `kill_managed_child` at `try_wait.rs:38-50`). This kill
  is immediate, so scan children die even if the 200 ms exit deadline elapses.

- **LangGraph bridge processes (agent / plan / threat / agentic tools) are cooperative
  and can orphan.** The bridge child is only killed when its own polling loop observes
  the token: `kill_cancelled_bridge` checks `is_cancelled()` and then `child.kill()`
  (`kuzushi-openai/.../bridge_process.rs:180-212`). That is an **immediate-child kill,
  not a process-group kill**, and it only fires if the worker thread reaches the poll
  before the shell exits. The abort log strings say so explicitly: "process kill not
  confirmed" / "waiting for LangGraph to return" (`exit_requests.rs:52-53`, `:113`,
  `:127`, `:141`). On a fast double-Ctrl+C, a bridge still mid-call can be left running
  past the 200 ms deadline, and any **grandchildren it spawned** (e.g. `joern --server`,
  `codeql`) are not in the killed child's group so they orphan regardless.

- **`joern --server` is reaped only via `Drop` of the MCP server's handle**
  (`kuzushi-mcp-joern/.../auto_spawn.rs:39-44`), which is tied to the MCP-server
  process's lifetime, not to the TUI's cancel/exit. If the MCP-server process is itself
  a bridge grandchild that orphans (above), its `Drop` never runs and joern survives.

Std `Child` has no kill-on-drop, and `FinishShellQuit` performs no final sweep, so
anything still alive at exit stays alive.

**Verdict (B):** In-TUI cancel works and the Activity view is free of reflexive-key
footguns; the two-stage exit is correct. The real risk is runaway **agent/LLM bridge
process trees**: cancellation there is cooperative + immediate-child-only, bounded by a
200 ms exit wait, so a bridge and its joern/codeql grandchildren can survive shell exit.

### Minimal safe mappings

- Give agent/plan/threat/tool bridges the same treatment as scanners: spawn under a
  process group and `killpg(SIGKILL)` from the token's `cancel()` so teardown does not
  depend on the worker polling in time.
- On `FinishShellQuit`, after the 200 ms grace, do a final registry sweep that kills any
  still-registered child groups before the process exits (belt-and-suspenders for the
  deadline case).
- Consider "arm then confirm" for the first Ctrl+C *during a long run* (not just at
  idle), since discarding an in-progress scan/agent run is the highest-consequence
  single keystroke in the app.
- Cosmetic: relabel the confirm footer `Esc deny` (currently `back`), and reconcile the
  stale `CLAUDE.md` note about Activity `C`-to-cancel.

## Key table — everything that can end or discard work

| Key / verb | Where | Effect | Confirms? | Assessment |
|---|---|---|---|---|
| `Enter` | Approval gate | Consumed, no-op | n/a (inert) | Safe — cannot authorize |
| `y` / `Y` | Approval gate | Allow once / allow+remember | Explicit char, labeled | Safe (but `y` doesn't actually launch) |
| `n` / `N` | Approval gate | Deny once / deny+remember | Explicit char | Safe |
| `Esc` | Approval gate | **Deny once**, consumed (no fall-through) | No prompt, but denies | Safe — guarded |
| `Ctrl+C` (work running) | global | Cancel active jobs (cooperative abort) | **No** | Convention-OK; arm-then-confirm would be safer |
| `Ctrl+C` #1 (idle) | global | Arm 2s exit window | Yes (arms) | Safe — two-stage |
| `Ctrl+C` #2 (idle, ≤2s) | global | Quit (abort→200ms wait→exit) | Yes (confirms arm) | Safe |
| `Ctrl+C` (abort pending) | global | Logs "type quit to force"; keeps waiting | Yes (refuses) | Safe |
| `Ctrl+D` | global | Same as Ctrl+C chord | Same as above | Safe |
| `cancel` / `c` / `stop` | command line | Cancel active jobs | No (explicit command) | Safe — intentional |
| `x` | Activity view | Reset presentation only, "run preserved" | n/a | Safe — does not touch work |
| `Esc` | Activity view | Back-navigation only | n/a | Safe — does not cancel run |
| `quit` | command line | Force exit | No (explicit command) | Safe — intentional |
