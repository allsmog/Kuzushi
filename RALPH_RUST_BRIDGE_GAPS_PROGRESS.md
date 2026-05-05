# Ralph Rust Bridge Gaps Progress

Stage: 1 - Rust Bridge Gaps
Active story: BG-003 - Rust Datastore And Option Precedence

## Current Rust Shell Command Surface

Parser facts:

- `ShellCommand` variants live in `crates/kuzushi-tui/src/commands.rs:5`.
- `parse_command` accepts both slash and bare forms by stripping one leading `/` at `crates/kuzushi-tui/src/commands.rs:38`.
- Routed Rust verbs are defined in the `match verb` table at `crates/kuzushi-tui/src/commands.rs:48`.
- Runtime dispatch is handled in `ShellApp::handle_command` at `crates/kuzushi-tui/src/app.rs:128`.
- Rust startup help text is logged at `crates/kuzushi-tui/src/app.rs:106` and `crates/kuzushi-tui/src/app.rs:130`.
- Rust TUI help rendering is in `crates/kuzushi-tui/src/renderer.rs:591`.
- Keybind hints are in `crates/kuzushi-tui/src/renderer.rs:790`.

Current routed Rust commands:

| Command | Parser route | Help advertised | Notes |
| --- | --- | --- | --- |
| `help`, `/help`, `/h`, `?` | `Help` | yes | `/help advanced` is not routed. |
| `back`, `/back` | `Back` | yes | Legacy `/b` and bare `b` are not routed. |
| `modules`, `/modules` | `Modules` | yes | Legacy `/m` and bare `m` are not routed. |
| `tools`, `/tools` | `Tools` | no startup, yes help view | Lists Rust registry tools. |
| `findings`, `/findings`, `f`, `/f` | `Findings` | yes | Opens current findings. |
| `open <id>`, `/open <id>` | `Open` | yes | Requires an id. |
| `scan [target]`, `/scan [target]` | `Scan` | yes | Runs configured Rust scanners. |
| `model [id]`, `/model [id]` | `Model` | yes | Session-level assignment only; no provider/backend UX yet. |
| `config`, `/config` | `Config` | yes | Status view only. |
| `use <module>`, `/use <module>` | `Use` | yes | Focuses a Rust built-in module. |
| `tune`, `/tune`, `t`, `/t` | `Tune` | yes | Placeholder view. |
| `threats [summary|dfd|stride|stories|scope|edit|1..5]` | `Threat` or `ThreatEditor` | yes | No `regen` or `ask` route. |
| `prompts`, `/prompts` | `Prompts` | yes | Placeholder prompt editor view. |
| `prompt <raw>`, `/prompt <raw>` | `Prompt` | implied by prompts | Logs raw prompt action. |
| `actor <n>`, `/actor <n>` | `Actor` | no help view, legacy catalog yes | Opens actor detail. |
| `show runs`, `/show runs` | `ShowRuns` | yes | Current-session run view only. |
| `show aliases [prefix]`, `/show aliases [prefix]` | `ShowAliases` | no help view, legacy catalog yes | Logs alias filter, then findings view. |
| `show prompts`, `/show prompts` | `Prompts` | no help view, legacy catalog yes | Routed as prompt editor. |
| `since <ref>`, `/since <ref>` | `Since` | no help view, legacy catalog yes | No git diff scope yet. |
| `replay <run>`, `/replay <run>` | `Replay` | yes | Renders artifact paths. |
| `trace <run>`, `/trace <run>` | `Trace` | yes | Renders artifact paths. |
| `plan <text>`, `/plan <text>` | `Plan` | no help view | Logs plan goal only. |
| `run [tool] [json]`, `/run [tool] [json]` | `RunTool` | yes | Tool dispatch via Rust registry. |
| `quit`, `/quit`, `exit`, `/exit`, `q`, `/q` | `Quit` | yes as `quit` | `/exitj` is not routed. |

## Legacy TypeScript Command Surface

Legacy catalog facts:

- Catalog entries are in `src/copilot/shell-commands.ts:45`.
- Legacy default/advanced/dev visibility is defined at `src/copilot/shell-commands.ts:342`.
- Known verb collection and aliases are in `src/copilot/shell-commands.ts:410`.
- Bare routes are defined at `src/copilot/shell.ts:5707`.
- Slash routes are defined at `src/copilot/shell.ts:5977`.
- The legacy router explicitly prevents silent prose-to-agent fallback at `src/copilot/shell.ts:5631`.
- Option primitives and datastore behavior are in `src/copilot/options.ts:22` and `src/copilot/options.ts:177`.
- Attachment KB routing is in `src/copilot/shell.ts:6633`.
- Artifact KB SQLite FTS storage is in `src/modules/_shared/artifact-kb/store.ts:22`.
- Threat-model KB SQLite FTS storage is in `src/modules/threat-model/kb-index.ts:103`.

Legacy command classifications:

| Legacy command or family | Classification | Rust status and reason |
| --- | --- | --- |
| `/help`, `/h`, bare `help` | already covered | Rust routes core help; advanced grouped help remains BG-014. |
| `/quickstart`, bare `quickstart` | deferred | First-run/startup guidance belongs with Stage 2 UX-005 after bridge primitives exist. |
| `/modules`, `/m`, bare `modules`, bare `m` | partially covered | Rust covers `/modules` and bare `modules`; `/m`/`m` remain BG-014 completion/help parity. |
| `/tools`, bare `tools` | already covered | Rust lists registry tools. |
| `/use <module>`, bare `use <module>` | already covered | Rust validates focused module against built-ins. |
| `/scan [target]`, bare `scan [target]` | already covered | Rust scan path exists. Options/task selection still BG-003/BG-005. |
| `/back`, `/b`, bare `back`, bare `b` | partially covered | Rust covers `/back` and bare `back`; aliases remain BG-014. |
| `/actor <n>`, bare `actor <n>` | already covered | Rust routes to actor-detail view. |
| `/findings`, `/f`, bare `findings`, bare `f` | already covered | Rust routes findings view. |
| `/findings export ...` | port now | Needed for BG-010 workspace/export status. |
| `/open <F-NNNN>` | already covered | Rust opens by id/fingerprint prefix; alias stability remains later bridge/UX work. |
| `/tune`, `/t`, bare `tune`, bare `t` | already covered | Rust routes a tune view, but legacy controls are not yet bridged. |
| `/story`, bare `story` | port now | Required by BG-013 as work-or-document-absence. |
| `/since <ref>` | partially covered | Rust parses and logs; real changed-file scope is deferred to UX/diff work unless needed by Stage 3 PR mode. |
| `/plan`, `/yes`, `/no`, bare planner prose | deferred | Rust `plan` logs only. Keep out of model routes until BG-012/UX-007 decides ask/planner contract. |
| `/prompts`, `/prompt edit/show/diff/reset`, `/show prompts` | partially covered | Rust parses placeholders; full prompt override editing deferred unless final bridge gate requires it. |
| `/show runs`, `/runs`, `/replay`, `/trace` | partially covered | Rust has run/replay/trace views with current artifact paths; persisted DB/JSONL parity is not complete. |
| `/resume`, `/pause` | port now | Required by BG-013 as work-or-precise-absence. |
| `/show aliases` | partially covered | Rust parses; alias table behavior remains BG-014/UX-012. |
| `/options`, bare `options`, `show options`, `show advanced`, `show missing` | port now | Required by BG-004 and depends on BG-002/BG-003. |
| `/set`, bare `set`, `setg`, `unset`, `unsetg` | port now | Required by BG-003/BG-004. |
| `/tasks`, `/task block/allow/toggle/mode/reset` | port now | Required by BG-005. |
| `/config`, `/config raw|get|set|path|advanced` | port now | Basic Rust config view exists; raw/get/set/path are needed for BG-011/BG-014. |
| `/auth`, `/auth import-from-config` | port now | Required by BG-011; must never print secrets. |
| `/provider`, `/backend`, `/model`, `/cost` | port now | Required by BG-011; Rust `/model` is shallow and must preserve no-silent-fallback enforcement. |
| `/ask <question>`, bare `ask <question>`, `?text`, lone `?` | port now | Required by BG-012; lone `?` is currently help, `?text` is unknown. |
| `/target <path>`, bare `target <path>` | port now | Needed as supporting state for context/workspace commands. |
| `/context`, `/context build`, `/context regen <slice>`, bare `context ...` | port now | Required by BG-009. Legacy `/context edit` may be deferred or replaced. |
| `/workspace <id>` and workspace status/list/export surfaces | port now | Required by BG-010, with unsupported formats failing actionably. |
| `/threats` core views and `1..5` | already covered | Rust routes core views. |
| `/threats regen`, `/threats ask`, threat patch accept/reject | deferred | Useful but not in the Stage 1 bridge acceptance list; revisit after KB/context parity. |
| `/kb`, bare `kb`, `attachments`, `attach`, `detach`, `reparse` | port now | Required by BG-006. Legacy supports `context`, `threat-model`, and `carlini-threat-hunt`; Rust prompt asks for `x-ray` where artifacts exist. |
| Artifact KB and threat-model KB search | port now | Required by BG-007/BG-008. |
| `/load <specifier>` | port now | Required by BG-013 as load-or-precise-dynamic-loading-absence. |
| `/clear`, `/history` | port now | Required by BG-013. |
| `info <module-or-tool>`, `search <query>`, `browse` | deferred | Useful discovery affordances, but not in BG-002 through BG-016 acceptance. Revisit after required bridge commands. |
| Vendor-only `clear scope` | intentionally removed | Vendor assessment is not called out in Rust bridge scope; keep absent unless Rust vendor workspace becomes primary. |
| Prompt-editor local `edit/show/diff/reset/set` | deferred | Depends on whether prompt editor remains a Rust feature after options/config parity. |
| SAST-task local `toggle/block/allow/mode/reset` | port now | Required as focused-view aliases by BG-005. |

## Stage 1 Checklist

- BG-001 Bridge-gap progress file and command parity audit: complete in iteration 1.
- BG-002 Rust tool option metadata: complete in iteration 2.
- BG-003 Rust datastore and option precedence: pending.
- BG-004 `show options` / `/options` / `set`: pending.
- BG-005 SAST task picker and task options: pending.
- BG-006 Knowledge base attachments view: pending.
- BG-007 Artifact knowledge DB / search: pending.
- BG-008 Use knowledge DB in agentic Rust tools: pending.
- BG-009 Context commands: pending.
- BG-010 Workspace import/export and status: pending.
- BG-011 Auth, provider, backend, model, and cost commands: pending.
- BG-012 Ask/agent chat contract: pending.
- BG-013 History, clear, load, resume/pause, story: pending.
- BG-014 Completion and help parity: pending.
- BG-015 Plain/non-TTY bridge output: pending.
- BG-016 Final bridge gate: pending.

## Iteration Log

### Iteration 1 - BG-001

- Task attempted: create the Stage 1 bridge progress file, audit current Rust and legacy TS shell command surfaces, classify legacy commands, and add a Rust parser surface regression test.
- Files changed:
  - `RALPH_RUST_BRIDGE_GAPS_PROGRESS.md`
  - `crates/kuzushi-tui/src/commands.rs`
- Tests/checks run:
  - `cargo fmt --all`
  - `cargo test -p kuzushi-tui commands::tests`
- Result: complete. The progress/audit file now lists Rust and legacy shell command surfaces with parser/help references and bridge classifications. The Rust parser tests now lock routed commands and the current high-priority bridge-gap commands.
- Remaining work: BG-002 through BG-016.
- Blockers or repo facts that contradicted this prompt:
  - Worktree already contained unrelated `package.json` and `pnpm-lock.yaml` modifications moving Ink/React to dev dependencies. This iteration did not touch those files.
  - No prior `RALPH_RUST_BRIDGE_GAPS_PROGRESS.md` file existed.
  - Commit/push is blocked in this sandbox: `git add RALPH_RUST_BRIDGE_GAPS_PROGRESS.md crates/kuzushi-tui/src/commands.rs` failed because Git could not create `.git/index.lock` (`Operation not permitted`), and a direct `touch .git/codex-write-test` failed with the same permission error. The working tree changes are ready but unstaged.

### Iteration 2 - BG-002

- Task attempted: add Rust tool option metadata and validation/coercion basics for visible tool descriptors.
- Files changed:
  - `crates/kuzushi-core/src/modules.rs`
  - `RALPH_RUST_BRIDGE_GAPS_PROGRESS.md`
- Tests/checks run:
  - `cargo fmt --all`
  - `cargo fmt --all --check`
  - `cargo test -p kuzushi-core option`
  - `cargo test -p kuzushi-core modules::tests::catalog_tool_serialization_keeps_core_descriptor_fields`
  - `cargo test -p kuzushi-tui commands::tests`
- Result: complete. Rust `ToolDescriptor` now carries optional typed `OptionSpec` metadata with `string`, `bool`, `int`, `float`, `path`, and `enum` kinds, plus required/default/choices/advanced/evasion fields. Declared tool inputs are coerced and required/default values are applied before dispatch while undeclared keys remain allowed for compatibility. Visible high-value tools now expose option specs through `catalog:tools`, and tests cover bool/int/float/path/string/enum coercion, required missing, defaults, invalid values, and descriptor serialization compatibility.
- Remaining work: BG-003 through BG-016.
- Blockers or repo facts that contradicted this prompt:
  - The unrelated staged `package.json` and `pnpm-lock.yaml` changes are still present and were not touched by this iteration.
  - The first commit attempt failed because the Husky pre-commit hook tried to run `lint-staged`, but `lint-staged` is not installed in the current environment.
