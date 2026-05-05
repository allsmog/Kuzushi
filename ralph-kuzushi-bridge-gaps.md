# Ralph Loop Prompt: Kuzushi Rust Bridge Gaps

You are working in `/Users/operator/VibeCode/open-sourced/kuzushi`.

The Rust/pi-agent-core migration is complete, but some operator-facing shell affordances from the legacy TypeScript/Ink shell were not fully re-exposed in the Rust shell. This prompt is only for bridging those gaps.

Do not restart the Rust migration. Do not start whitebox-static work. Do not delete Ink/React files as part of this prompt unless a specific bridge task has a Rust replacement, tests, and a retention/deletion note. The goal is to make sure useful legacy behavior exists in Rust before final cleanup.

## Mission

Bridge the practical gap between the migrated Rust product path and the helpful legacy operator surfaces:

- `show options`, `/show options`, `/options`, `show advanced`, `show missing`
- typed option specs, scoped datastore behavior, `set`, `setg`, `unset`, `unsetg`
- SAST task selection: `/tasks`, `/task block|allow|toggle|mode|reset`
- focused-module knowledge base / attachments: `/kb`, `attachments`, `attach`, `detach`, `reparse`
- artifact knowledge DB search and indexing for context, threat-model/Randori, X-Ray, Carlini, and other module artifacts
- `/context`, `/context build`, `/context regen <slice>`, and context snapshot display
- workspace import/export/status flows where they matter to CLI operators
- `/auth`, `/provider`, `/backend`, `/cost`, `/ask`, `/history`, `/clear`, `/load`, `/resume`, `/pause`, and related help/completion behavior

This is a Rust bridge, not an Ink preservation project. Use legacy TypeScript as a behavioral reference only.

## Current Repo Facts To Verify

Re-check these files before implementing because line numbers may drift:

- Rust shell parser currently routes only a compact command set in `crates/kuzushi-tui/src/commands.rs:48-118`.
- Rust shell help omits options, task picker, KB, auth, context, history, and load commands in `crates/kuzushi-tui/src/renderer.rs:591-609`.
- Rust core `ToolDescriptor` currently stores only `name`, `description`, and `headless`, with no option schema in `crates/kuzushi-core/src/modules.rs:62-67`.
- Rust config is intentionally small in `crates/kuzushi-core/src/config.rs:8-14`.
- Legacy TS command catalog includes `/options`, `/set`, `/tasks`, `/task`, `/auth`, `/provider`, `/backend`, `/cost`, `/context`, `/workspace`, `/kb`, `/load`, `/clear`, and `/history` in `src/copilot/shell-commands.ts:165-339`.
- Legacy TS shell routes bare `options`, `show options`, and `set` before dispatcher in `src/copilot/shell.ts:5666-5671`.
- Legacy TS shell implements `kb`, `tasks`, `options`, `show-options`, and `set` bare routes in `src/copilot/shell.ts:5779-5860`.
- Legacy typed options/datastore are in `src/copilot/options.ts:1-14`, with table rendering in `src/copilot/options.ts:331-370`.
- Legacy artifact KB storage is SQLite FTS under `.kuzushi/artifact-kb.sqlite3` in `src/modules/_shared/artifact-kb/store.ts:16-24`.
- Legacy threat-model KB storage is SQLite under `.kuzushi/threat-model-kb.sqlite3` in `src/modules/threat-model/kb-index.ts:17-21`.
- Legacy UI snapshots prove the operator expected `tasks`, `show options`, and `/context build` affordances in `tests/ui/__snapshots__/component-snapshots.test.tsx.snap`.

If investigation contradicts these facts, record the corrected fact in `RALPH_RUST_BRIDGE_GAPS_PROGRESS.md` with file and line references.

## Ralph Rules

Each iteration must:

1. Inspect `git status --short`.
2. Read or create `RALPH_RUST_BRIDGE_GAPS_PROGRESS.md`.
3. Pick the highest-priority incomplete BG task below.
4. Implement one coherent Rust slice.
5. Add focused Rust tests/snapshots where feasible.
6. Run the smallest relevant checks first.
7. Update `RALPH_RUST_BRIDGE_GAPS_PROGRESS.md` with:
   - task attempted
   - files changed
   - tests/checks run
   - result
   - remaining work
   - blockers or repo facts that contradicted this prompt
8. Commit only after checks pass.
9. Push the branch after each successful commit.
10. Exit unless all bridge-gap tasks are complete.

Do not output `<promise>KUZUSHI_BRIDGE_GAPS_COMPLETE</promise>` until every BG task is complete, relevant checks pass, and `RALPH_RUST_BRIDGE_GAPS_PROGRESS.md` says there is no remaining bridge-gap work.

If any work remains, output a concise next-task summary and continue in a later iteration.

## Hard Rules

- Rust remains the primary product path.
- Do not reintroduce Ink/React into the CLI runtime.
- Do not delete TypeScript/Ink references until their useful behavior is ported to Rust or intentionally retained with a documented reason.
- Do not invent fake commands. Every help entry must route or explicitly say it is not implemented.
- Do not weaken runtime/model enforcement or no-silent-model-fallback behavior.
- Do not make network calls in tests.
- Do not add a network-only vector DB dependency.
- Prefer SQLite FTS/local deterministic indexing for the knowledge DB unless an existing local vector implementation is already available.
- If embeddings/vector search are added, put them behind a trait and make the default local/offline path deterministic.
- Do not leak credentials into subprocess envs.
- Do not break non-TTY, CI, piped, or plain output.
- Keep UI dense, terminal-first, and operator-oriented.
- Preserve `.kuzushi/v2/` state compatibility.

## Checks

Use focused checks per task. Before final bridge completion, run:

```sh
cargo fmt --all
cargo test --workspace
cargo build --workspace
pnpm check
pnpm typecheck
pnpm build
pnpm test:e2e
pnpm build:native
pnpm verify:pack
```

`pnpm check` may print existing warnings while exiting successfully. Treat the exit code as the gate unless the active task is cleaning warnings.

## Task Backlog

### BG-001: Bridge-Gap Progress File And Command Parity Audit

Create `RALPH_RUST_BRIDGE_GAPS_PROGRESS.md`.

Acceptance:

- Progress file lists current Rust shell commands and legacy TS commands.
- Each legacy command is classified as:
  - port now
  - already covered by Rust command
  - intentionally removed
  - deferred with reason
- Include file/line references for parser/help facts.
- Add a Rust test or snapshot that encodes the intended Rust shell command surface.

### BG-002: Rust Tool Option Metadata

Add a Rust option metadata model that can represent legacy `OptionSpec` enough to render and validate tool options.

Acceptance:

- Rust core has an `OptionSpec` or equivalent with name, type, description, required, advanced/evasion flag, default, enum choices, and validation/coercion basics.
- `ToolDescriptor` or a companion registry API exposes option specs for visible tools.
- Existing tool descriptors remain backward compatible for JSON serialization or tests are updated intentionally.
- Tests cover bool, int, float, path/string, enum, required missing, defaults, and invalid values.

### BG-003: Rust Datastore And Option Precedence

Port the practical datastore behavior used by `set`, `setg`, `unset`, and tool execution.

Acceptance:

- Rust shell can store session/global/workspace/module option values or an explicitly chosen subset with documented scope semantics.
- Option precedence is deterministic and tested.
- Set options affect subsequent `/run`, focused-module run, and `scan` paths where applicable.
- Persistent scope writes to a v2-compatible file only after explicit user command.
- No model fallback is introduced through option precedence.

### BG-004: `show options` / `/options` / `set` Operator Surface

Implement the options UX in Rust.

Acceptance:

- These commands route in Rust shell:
  - `options`
  - `/options`
  - `show options`
  - `/show options`
  - `show options <tool>`
  - `show advanced`
  - `show missing`
  - `set <key> <value>`
  - `/set <key> <value>`
  - `setg`, `unset`, and `unsetg` if the datastore supports those scopes
- Options view/table is readable at 80 columns.
- Unknown options show the closest valid option names and the next command.
- Tests cover focused-module default tool selection and explicit tool selection.
- Help includes these commands only after they route.

### BG-005: SAST Task Picker And Task Options

Port the SAST task picker semantics from legacy `/tasks` and `/task`.

Acceptance:

- Rust shell routes `/tasks`, `tasks`, `/task block <id>`, `/task allow <id>`, `/task toggle [id]`, `/task mode auto|manual|toggle`, and `/task reset`.
- Task state maps to the Rust `sast:scan` input or scan engine task selection.
- Task options appear in `show options` for `sast:scan`.
- Manual/auto modes are tested.
- Unknown task IDs show valid IDs and do not mutate state.
- Shell snapshots cover task list and footer/key hints.

### BG-006: Knowledge Base Attachments View

Port focused-module KB attachment management.

Acceptance:

- Rust shell routes `/kb`, `kb`, `attachments`, `attach <path-or-url>`, `detach <id>`, and `reparse <id>` for supported modules.
- Supported modules at least include `context`, `threat-model`, `carlini-threat-hunt`, and `x-ray` if their artifacts exist in Rust.
- Attachment storage is local under `.kuzushi/v2/` or a documented compatible `.kuzushi/<module>/attachments.json` path.
- File attachments are path-safe and reject traversal.
- URL attachments are metadata-only unless an explicit offline fetch/import path exists.
- Tests cover add/list/detach/reparse and first-entry view load from disk.

### BG-007: Artifact Knowledge DB / Search

Bridge the artifact knowledge DB behavior into Rust.

Acceptance:

- Rust has a local knowledge DB abstraction for indexed artifact chunks.
- Default implementation is local/offline SQLite FTS or equivalent deterministic search.
- It can index context snapshots, threat-model/Randori artifacts, X-Ray artifacts, Carlini outputs, and run summaries where available.
- It records source path, module id, run id, content hash, title, summary, body, refs, metadata, and indexed time.
- Search returns stable ranked snippets with source refs.
- Tests cover index, re-index, search, stale source hash, and missing DB.
- If a vector/embedding backend is introduced, it is optional, local/offline by default, and hidden behind a trait. Do not require network embeddings.

### BG-008: Use Knowledge DB In Agentic Rust Tools

Make Rust agentic modules able to consume indexed knowledge without bespoke TS tools.

Acceptance:

- `ToolExecutionContext` or runtime prompt builders can retrieve relevant KB snippets for a module/task.
- At least two modules use the shared KB path, preferably `carlini-threat-hunt` and `x-ray` or `threat-model`.
- Prompt context clearly labels KB snippets as retrieved local artifacts.
- Tests prove missing KB degrades clearly and does not fail the tool.

### BG-009: Context Commands

Port Rust shell context commands beyond raw `run context:build`.

Acceptance:

- Rust shell routes `/context`, `context`, `/context build`, `/context regen <slice>`, and `/context status`.
- `/context` shows current `.kuzushi/context-snapshot.json` or the Rust v2 equivalent if present.
- `/context build` dispatches `context:build` and writes the expected artifact.
- Unsupported slices return an actionable message.
- Tests cover no target, existing snapshot, build path, and regen alias behavior.

### BG-010: Workspace Import/Export And Status

Bridge practical workspace flows that operators used from the TS dispatcher.

Acceptance:

- Rust CLI/shell exposes workspace status and at least one export path for findings or workspace evidence.
- If SARIF/kz-bundle/markdown import/export are not fully ported, document exact gaps and add command stubs that fail actionably.
- Help never advertises unsupported import/export without a clear "not yet" message.
- Tests cover no workspace and export to a temp path.

### BG-011: Auth, Provider, Backend, Model, And Cost Commands

Bridge the configuration helpers operators expect.

Acceptance:

- Rust shell routes `/auth`, `/provider`, `/backend`, `/model`, and `/cost` or gives accurate replacements.
- `/model` remains no-silent-fallback safe.
- `/backend` honestly reports only supported Rust backends unless more exist.
- `/auth` never prints secrets and either writes supported config/credential files or tells the exact env var/config path.
- `/cost` reports known run/session cost or says cost accounting is unavailable/stubbed.
- Tests cover unconfigured model, set model, provider/backend display, and no secret leakage.

### BG-012: Ask/Agent Chat Contract

Bridge explicit agent ask behavior.

Acceptance:

- Rust shell supports `/ask <question>`, `ask <question>`, and `?text` if these are intended compatibility routes.
- Bare unknown prose remains deterministic and does not silently route to the model.
- Agent mode is visible in prompt/status while a question is active.
- Tests cover `/ask`, `ask`, `?question`, lone `?`, and unknown prose.

### BG-013: History, Clear, Load, Resume/Pause, Story

Port or intentionally account for the remaining high-value shell utilities.

Acceptance:

- `/history` and `/clear` work in Rust shell.
- `/load <specifier>` either loads modules if Rust supports it or fails with a precise "dynamic module loading not supported in Rust yet" message.
- `/resume`, `/pause`, and `/story` either work or are documented as intentionally absent with replacements.
- Help/completion and tests match the implemented behavior.

### BG-014: Completion And Help Parity

Update completions and help after bridge commands land.

Acceptance:

- Completion includes slash commands, bare aliases, module IDs, tool IDs, option names, task IDs, finding aliases, run IDs, and config keys where state is available.
- Help is grouped by operator workflow:
  - navigation
  - run/scan
  - options/tasks
  - context/KB
  - findings/evidence
  - auth/config/model
  - session
- Drift tests fail if help advertises a command that parser does not route.

### BG-015: Plain/Non-TTY Bridge Output

Ensure bridged features work outside the Ratatui shell.

Acceptance:

- Options, tasks, KB listing, context status, workspace status, and config/model commands have a plain output path or clear CLI equivalent.
- Strict plain output has no ANSI or box drawing.
- Tests cover at least options table, KB list, and context status in plain mode.

### BG-016: Final Bridge Gate

Acceptance:

- `RALPH_RUST_BRIDGE_GAPS_PROGRESS.md` says no bridge gaps remain.
- `rg -n "show options|/options|/kb|/tasks|/task|/context|/auth|/cost|/history|/load" README.md crates tests` shows Rust docs/tests for the bridged behavior, not only legacy TS references.
- Full checks pass.
- Commit and push the final bridge-gap state.

Only after BG-001 through BG-016 are complete, output:

```text
<promise>KUZUSHI_BRIDGE_GAPS_COMPLETE</promise>
```

## Suggested Ralph Command

Run this from the repo root:

```sh
cd /Users/operator/VibeCode/open-sourced/kuzushi

RALPH_CODEX_ARGS='-c model=gpt-5.5 -c model_reasoning_effort=xhigh' \
ralph \
  --prompt-file ./ralph-kuzushi-bridge-gaps.md \
  --agent codex \
  --model gpt-5.5 \
  --tasks \
  --max-iterations 12
```
