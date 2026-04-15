# Kuzushi Shell Fixup — Agentic Handoff Prompt

Use this prompt to hand off shell UX fixes to an agent. Copy the entire content below.

---

## Context

Kuzushi (`src/copilot/shell.ts`, `src/ui/components/CopilotShell.tsx`, `src/ui/App.tsx`) has a copilot shell that is functionally broken in many ways. The module system and tool dispatch work (`src/modules/`, `src/copilot/core.ts`), but the interactive UX — the thing users actually see and touch — is full of bugs, missing features, and half-finished integrations.

The shell was built incrementally across many iterations and has accumulated significant technical debt. Below is a complete audit of every issue. Fix them in priority order.

## Architecture Reminder

- **Ink owns the terminal.** All UI goes through `src/ui/App.tsx` → `UIStore` (`src/ui/state.ts`). Never use raw `console.log` or `readline` for interactive output.
- **UIMode controls what renders.** `"shell"` renders `CopilotShell`. `"running"` renders PipelineIndicator/StatusFooter/ResultLine. `"summary"` renders ScanSummary. `"preflight"` renders SetupWizard/ConfigConfirm/CredentialPrompt.
- **The shell has two layers:** Local commands (help, modules, tools, use, back, scan, target, exit) are handled in `handleLocalCommand()` without the LLM. Natural language falls through to `AgentSession.query()`.
- **Tool execution** goes through `CopilotCore.executeTool()` which passes `ToolExecutionContext` (including `uiStore`) to the tool's `execute()` method.
- **The scan pipeline** (`runPipeline` in `src/cli/commands/scan.ts`) accepts a `uiStore` parameter. When provided, it calls `registerAllWorkers(bus, { uiStore })` and the report-worker writes to the store, which the Ink components render reactively.

## Critical Files

- `src/copilot/shell.ts` — Shell backend: command handling, AgentSession, mode transitions, tool execution
- `src/ui/components/CopilotShell.tsx` — Ink shell component: conversation rendering, input handling
- `src/ui/App.tsx` — Main Ink app: mode-based conditional rendering
- `src/ui/state.ts` — UIStore, UIState, ShellState, UIMode definitions
- `src/modules/core-sast.ts` — sast:scan tool (passes uiStore to runPipeline)
- `src/copilot/core.ts` — CopilotCore: module lifecycle, tool dispatch
- `src/copilot/run.ts` — Headless run executor (for `kuzushi run`)
- `src/ui/setup.ts` — Preflight flows: SetupWizard, ConfigConfirm, CredentialPrompt
- `src/ui/repl.ts` — REPL command handler (/skip, /pause, /focus)
- `src/ui/components/PipelineIndicator.tsx` — Pipeline stage tree (already works in scan mode)
- `src/ui/components/StatusFooter.tsx` — Elapsed time, cost, model display
- `src/ui/components/ResultLine.tsx` — Individual finding result display

## Priority 1: Broken Core UX

### P1.1 — Focused module prompt missing in Ink component

`CopilotShell.tsx` hardcodes `"> "` as the prompt. It should read `shell.focusedModule` and render `"kuzushi/sast> "` when focused. The state is already updated in `shell.ts` line 112 — the component just ignores it.

### P1.2 — Agent response text is silently dropped

In `shell.ts`, the `case "assistant"` handler (around line 153) extracts text blocks but does nothing with them. The comment says "Don't append yet." This means the LLM's reasoning, explanations, and partial responses are completely lost — users only see the final `result` text. Fix: accumulate assistant text and either stream it live or append it to history.

### P1.3 — Mode transition from scan back to shell is fragile

When `sast:scan` runs from the shell, the pipeline sets UIMode to `"running"`, then to `"summary"` when done. The code in `resolveToolExecution` (line ~570) checks if mode changed and sets it back to `"shell"` after a 500ms delay. Problems:
- 500ms is arbitrary and might be too short for summary rendering
- Only works for direct tool execution, not agent queries that trigger scans
- The shell's `ShellState` (history, focusedModule, etc.) might be lost when mode transitions to "running" since `App.tsx` only renders `CopilotShell` when mode is "shell"

**Fix:** The pipeline completion handler in `runPipeline` should detect that it was launched from shell mode and transition back. Or: subscribe to `pipeline:complete` events in the shell and handle the transition there. Either way, preserve `ShellState` across mode transitions.

### P1.4 — Config/credentials flow doesn't work in shell

The scan command (`src/cli/commands/scan.ts`) runs `isFirstRun()`, `runSetupWizard()`, `runConfigConfirmation()`, and `runCredentialPrompt()` before launching the pipeline. The shell skips ALL of these. If a user has no API key, they get "No agent session available" with no way to fix it from within the shell.

**Fix:** On shell startup, check `hasAnthropicCredentials()` (from `src/ui/setup.ts`). If missing, trigger the credential prompt via `store.setPreflight({ kind: "credentials", ... })`. The Ink app already renders CredentialPrompt when preflight is set — just wire it up.

### P1.5 — Ctrl+C during a running scan may not interrupt cleanly

The CopilotShell component calls `shell.onExit()` and `exit()` on Ctrl+C. But if `asyncExecute()` is mid-flight (running `runPipeline`), the pipeline subprocess may orphan. The shell should:
1. If processing, send abort signal (via `AbortController`) to the running tool
2. If not processing, exit normally

## Priority 2: Missing Inherited UX

### P2.1 — Scan should render through existing Ink pipeline UI

When `scan .` runs from the shell, the user should see the SAME scan UI as `kuzushi scan .` — the PipelineIndicator stage tree with spinners, StatusFooter with elapsed/cost, ResultLine for each triage result, AgentActivity for tool calls. The `uiStore` is now passed through to `runPipeline()` (done in v0.12.0), but verify it actually works: does the Ink app transition to "running" mode? Does the stage tree render? Does it transition back to "shell" when done?

### P2.2 — /skip, /pause, /focus commands during scans

The REPL (`src/ui/repl.ts`) supports `/skip <fingerprint>`, `/focus <path>`, `/pause`, `/resume` during scan mode. These should work from the shell too. When mode transitions to "running", the CommandInput component should activate (it already does in scan mode — check that App.tsx wires it up). When mode returns to "shell", the shell prompt should return.

### P2.3 — Command history navigation (Up/Down arrows)

The Ink shell doesn't support pressing Up to recall previous commands. Maintain a command history array and navigate it with arrow keys in the `useInput` handler.

### P2.4 — Welcome banner should be a proper Ink component, not history entry

The welcome message is appended as a history entry which scrolls away. It should render as a `<Static>` banner at the top (like the scan mode Banner component), so it's always visible above the conversation.

## Priority 3: Polish

### P3.1 — Spacing and visual hierarchy

- Add `marginTop={1}` between different types of entries (input → output → input)
- Help text needs consistent indentation and spacing between sections
- Module/tool lists need blank lines between entries
- The welcome banner needs breathing room

### P3.2 — Non-TTY readline fallback completeness

The readline shell should:
- Print the welcome message on startup
- Show the focused module in the prompt (`kuzushi/sast> `)
- Support the same `workspace` command as the Ink shell
- Handle all the same local commands identically

### P3.3 — Tool output formatting consistency

All formatters (`formatHelp`, `formatModuleList`, `formatTools`, `formatModuleInfo`, `formatWelcome`) should use a shared style:
- 2-space indent for body text
- Blank line before and after each section
- Consistent alignment for label: value pairs

### P3.4 — Agent assistant text should stream or display

When the AgentSession sends `assistant` messages with text content, those should render in the conversation — either streamed character-by-character or appended as output entries. Currently they're silently dropped.

## Priority 4: Robustness

### P4.1 — Shell state preservation across mode transitions

When mode goes from "shell" → "running" → "summary" → "shell", the `ShellState` should be preserved. Currently the `shell` property on UIState might get cleared or overwritten during transitions. Verify it persists.

### P4.2 — AbortController for tool execution

`ToolExecutionContext.signal` exists but nothing passes an AbortController. Create one per tool execution so Ctrl+C can abort.

### P4.3 — Session creation error handling

If `runtime.createSession()` throws (e.g., bad API key format, network error), the shell should catch it and show a helpful message, not crash.

### P4.4 — History persistence

Save shell history to `.kuzushi/shell-history.json` on exit, load on startup. Cap at 1000 entries.

## Dead Code to Remove

- The `case "assistant"` block in shell.ts that does nothing (fix it or remove the comment)
- `src/copilot/run.ts` has `executeRun()` which creates its own CopilotCore — the shell no longer uses it for tool execution (uses `core.executeTool` directly). `executeRun` is still used by the `kuzushi run` CLI command, so don't delete it, but verify it's not called from shell code.

## Verification

After fixing, these scenarios should all work:

```
kuzushi                           # enters shell with welcome banner
> help                            # shows commands with proper spacing
> modules                         # lists modules with spacing
> use sast                        # prompt changes to "kuzushi/sast> "
> scan .                          # transitions to running mode, shows PipelineIndicator
                                  # stage tree renders, StatusFooter shows elapsed/cost
                                  # when done, transitions back to shell mode
> back                            # prompt returns to "> "
> sast:scan .                     # same as above, direct tool invocation
> What vulns are in this repo?    # goes to AgentSession, shows assistant text
> Ctrl+C                          # cleanly interrupts if processing, exits if idle
```

Non-TTY:
```
printf "help\nmodules\nscan .\nexit\n" | kuzushi 2>/dev/null
# Should show clean output for each command
```

Run `pnpm typecheck && pnpm test` after every change.
