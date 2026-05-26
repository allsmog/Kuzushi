<img src="kuzushi.png" alt="Kuzushi" width="200" />

# Kuzushi

Kuzushi is an evidence-backed repository security workbench.

It does not try to be another generic coding assistant. It scans real
codebases, preserves evidence, ranks likely vulnerabilities, and helps teams
move from suspicion to verification to remediation.

Use Kuzushi when you need more than "AI says this looks wrong": you need a
finding, the code path behind it, the current proof state, and a defensible
next action.

The primary operator path is the native Rust CLI and Ratatui shell. The npm
`kuzushi` binary, plus the shorter `kz` alias, invokes that native CLI through
`bin/kuzushi-rs.mjs`.

## Product Focus

Kuzushi's current product is deliberately narrower than its long-term research
roadmap: local-first repository security investigation for serious AppSec and
product-security operators. The core contract is evidence, not chat:

1. build or refresh repository context;
2. scan with deterministic and model-backed tools;
3. persist findings, traces, proof state, and run artifacts;
4. inspect one finding's evidence and current proof level;
5. choose the next action: suppress, verify, patch, or report.

Roadmap surfaces such as binary exploitation, broad pentest automation,
governance packs, and defensive operations should reinforce that evidence
workflow before they become primary product surfaces.

## Install

```bash
npm install -g kuzushi
kuzushi --help
kz --help
```

From a source checkout:

```bash
pnpm setup
pnpm dev -- --help
pnpm build:native
node bin/kuzushi-rs.mjs --help
```

The published `kuzushi` command resolves `native/<platform>-<arch>/kuzushi`,
and the published `kz` alias resolves `native/<platform>-<arch>/kz`; both then
fall back to local Cargo build outputs for the invoked name. Set
`KUZUSHI_NATIVE_BIN` to point the wrapper at a specific binary.

## Quick Start

This is the golden path. It is the workflow new operators should try before
touching advanced modules or deferred plugin-backed tools.

```bash
# Check config, local state, scanners, and the pi-agent-core bridge.
kuzushi doctor --target .

# Build the repository context snapshot used by shell and model-backed tools.
kuzushi --target . run context:build --input '{}'

# Run the standard native scan path with deterministic CI-style progress.
kuzushi scan . --mode standard --ci

# Inspect persisted findings.
kuzushi findings --target . --limit 10

# Inspect one finding's evidence, proof state, verification, and next action.
kuzushi finding F-0001 --target .

# Render a markdown PR/security review summary from persisted findings.
kuzushi pr-comment --target . > kuzushi-report.md
```

Fresh native state is stored under `.kuzushi/v2/`; scan, shell, and headless
run summaries remain under `.kuzushi/runs/<runId>/`.
`kuzushi doctor --target .` runs a Rust preflight over config, writable state,
findings DB openability, optional scanner binaries, and the pi-agent-core
bridge without printing credential values.

To see the workflow without real provider credentials or LLM spend, run the
deterministic fixture:

```bash
examples/first-wow/run.sh
```

It scans a tiny vulnerable app through a demo-only Semgrep fixture, persists
findings in a temporary copy of the app, prints `findings`, and writes a
markdown PR comment report path.

## Native CLI

```text
kuzushi [--target <path>] [--plain] [command]
kz [--target <path>] [--plain] [command]
```

Bare `kuzushi` starts the shell with the `kuzushi>` prompt; bare `kz` starts
the same shell with the compact `kz>` prompt.
Use `--plain` or `KUZUSHI_PLAIN=1` to force line-oriented output with no ANSI
escapes, animation, or box drawing. `KUZUSHI_SCREEN_READER=1` and
`KUZUSHI_LOW_BANDWIDTH=1` are aliases for the same strict plain shell mode.
The interactive shell leaves normal terminal text selection/copy available by
default. Set `KUZUSHI_MOUSE_CAPTURE=1` only if you want mouse-wheel handling
inside the TUI and your terminal still gives you a selection modifier.

| Command | Purpose |
| --- | --- |
| `kuzushi shell [--target <repo>]` | Start the Ratatui shell. |
| `kuzushi scan <repo> [--mode standard\|whitebox-static] [--tasks a,b] [--triage] [--json] [--ci]` | Run the Rust SAST umbrella executor and persist findings. |
| `kuzushi findings --target <repo> [--severity high,critical] [--verdict true_positive] [--name text] [--file-path path] [--limit 50] [--json]` | List persisted findings. |
| `kuzushi finding <F-0001\|fingerprint-prefix> --target <repo> [--json]` | Inspect one finding's evidence, proof state, verification summary, patch result, and next action. |
| `kuzushi runs list [--status completed,failed]\|show <runId>\|trace <runId>\|diff <a> <b>\|prune --target <repo>` | Inspect, compare, or prune replayable summaries, result artifacts, and trace JSONL under `.kuzushi/runs/<runId>/`. |
| `kuzushi suppress <F-0001> --target <repo> --reason <text> [--days 90]` | Record an expiring, evidence-backed suppression; findings remain visible in audit/report output. |
| `kuzushi suppressions --target <repo>` | List suppression memory and the audit store path. |
| `kuzushi permissions [--target <repo>]` | Show the current model fallback, approval, headless-run, and sandbox policy summary. |
| `kuzushi pr-comment --target <repo> [--repo owner/name] [--run-url url] [--git-sha sha]` | Render persisted findings as a markdown PR/security review comment. |
| `kuzushi modules [--json]` | List visible native modules. |
| `kuzushi tools [--json]` | List visible executable tool descriptors. |
| `kuzushi doctor [--target <repo>] [--json]` | Check config, local state, findings DB openability, scanner binaries, bridge readiness, and model/auth setup. |
| `kuzushi run <module:tool> --input '<json>' [--option key=value]` | Execute one explicit tool through the Rust registry. Use global `--target` for workspace-backed tools; `run .` is shell-only focused-module shorthand. |
| `kuzushi mcp <server>` | Run a local MCP server over stdio. |
| `kuzushi auth` | Print auth diagnostics; interactive provider login is handled inside `kuzushi shell`. |
| `kuzushi config show` | Print effective config. |
| `kuzushi config init [--force]` | Write the default global config. |
| `kuzushi config path` | Print the global config path. |

Examples:

```bash
kuzushi doctor --target . --json
kuzushi scan . --mode standard --tasks semgrep,secret-scan --json
kuzushi scan . --tasks agentic-sast --triage --json
kuzushi findings --target . --severity high,critical --limit 10
kuzushi finding F-0001 --target .
kuzushi runs list --target .
kuzushi runs list --target . --status failed,partial
kuzushi runs diff run-a run-b --target . --json
kuzushi runs prune --target . --older-than-days 30 --keep-last 20 --dry-run
kuzushi permissions --target .
kuzushi pr-comment --target . --repo allsmog/Kuzushi > kuzushi-report.md
kuzushi --target . run context:build --input '{}'
kuzushi --target . run semgrep:scan --input '{"config":"p/default"}'
kuzushi --target . run semgrep:scan --option config=p/default --input '{}'
kuzushi --target . run findings:list --input '{"severity":["high"],"limit":10}'
kuzushi --target . run triage:run --input '{"fingerprints":["abc123"]}'
```

Agentic tools require an explicit model. Set it in config or with
`KUZUSHI_MODEL=provider:model`, for example:

```bash
kuzushi config init
KUZUSHI_MODEL=openai:gpt-4.1 kuzushi scan . --tasks agentic-sast --json
```

Kuzushi does not silently choose a fallback model. If a runtime-backed tool has
no explicit model or an incompatible model/provider pair, startup or dispatch
fails with an actionable error.

## Options And Config

Tool behavior is driven by typed tool descriptors. Shell `set`/`setg`,
headless `run --option`, and `scan` flags all converge on the same canonical
preparation path before registry dispatch. Unknown keys fail unless the tool
declares a compatibility alias.

Precedence is global options, workspace options, session options, then
explicit JSON input. That means `--input` wins over `--option` when both set
the same canonical key.

| Surface | Purpose |
| --- | --- |
| `show options [tool]` | Inspect accepted option names, aliases, types, defaults, and current values. |
| `set <key> <value>` | Set a shell-session option for the focused tool. |
| `setg <key> <value>` | Persist a global option in `~/.kuzushi/v2/options.json`. |
| `kuzushi run <tool> --option key=value` | Apply a one-shot session option before `--input` is merged. |
| `kuzushi scan ...` | Compile scan flags into canonical `sast:scan` input. |

Persistent state lives in `~/.kuzushi/v2/options.json` and
`<target>/.kuzushi/v2/options.json`. Config remains separate for model,
runtime, bridge, budget, and approval policy. See
[docs/operator-control-surfaces.md](docs/operator-control-surfaces.md).

## Rust Shell

The shell routes slash commands and their bare equivalents through the Rust
command parser. Help is grouped by workflow; `?` opens help, while `?text`,
`ask <question>`, and `/ask <question>` are explicit agent-chat routes.
Unknown prose does not silently dispatch to a model.
Piped shell output automatically uses the same strict plain renderer as
`--plain`.

| Command | Purpose |
| --- | --- |
| `/help` | Show grouped shell help. |
| `/modules`, `/tools`, `/use <module>`, `/back` | Browse modules/tools, focus a module, and step back. |
| `/run <tool> [json]`, `run . [json]`, `/scan [target]` | Dispatch a tool or start the native scan path. In the shell, `run .` resolves to the focused module's primary tool; from a terminal use `kuzushi run <module:tool>`. |
| `/ask <question>`, `ask <question>`, `?text` | Ask an explicit agent question with the configured model. |
| `/options [tool]`, `show options [tool]`, `show advanced [tool]`, `show missing [tool]` | Inspect typed Rust tool options and missing required values. |
| `/set <key> <value>`, `setg <key> <value>`, `/unset <key>`, `unsetg <key>` | Set or clear session/global option values for subsequent runs and scans. |
| `/tasks`, `/task block <id>`, `/task allow <id>`, `/task toggle [id]`, `/task mode auto\|manual\|toggle`, `/task reset` | Configure SAST task selection for `sast:scan` and shell scans. |
| `/context`, `/context build`, `/context status`, `/context regen <slice>` | View or rebuild the local context snapshot. |
| `/kb [module]`, `attachments`, `attach <path-or-url>`, `detach <id>`, `reparse <id>` | Manage local `.kuzushi/v2/` KB attachments; URL attachments are metadata-only. |
| `/workspace`, `workspace export findings <path>`, `findings export <path>` | Show workspace state and export findings as JSON or JSONL. |
| `/findings`, `/open <alias-or-fingerprint>`, `/show aliases [prefix]` | Load findings and open deterministic aliases such as `F-0001`. |
| `/show runs`, `/replay <runId>`, `/trace <runId>`, `/since <git-ref>` | Inspect replayable run artifacts and diff-scoped findings. |
| `/threats [dfd\|stride\|stories\|scope\|summary\|1..5]`, `/threats regen`, `/threats ask <question>` | Switch threat-model views or request a reviewable threat-model patch. |
| `/auth`, `/auth login <provider>`, `/provider`, `/backend`, `/model [choice]`, `/cost`, `/config`, `/permissions` | Show credential status without secrets, select explicit models, and report known cost/config/approval state. |
| `/history`, `/clear`, `/load <specifier>`, `/pause`, `/resume [runId]`, `/story` | Session utilities and precise replacement messages for unsupported legacy live-control paths. |
| `/prompts`, `/prompt <verb>`, `/tune`, `/actor <n>`, `/plan <english>` | Prompt, tuning, transcript, and planner surfaces. |
| `/quit`, `exit`, `/exit`, `/exitj` | Exit. |

## Built-In Modules

`kuzushi modules` is the source of truth for the visible native registry. The
current built-ins are:

| Module | Primary tools |
| --- | --- |
| `module-recommender` | `module-recommender:recommend` |
| `context` | `context:build` |
| `sast` | `sast:scan` |
| `semgrep` | `semgrep:scan` |
| `codeql` | `codeql:scan` |
| `agentic-sast` | `agentic-sast:scan` |
| `offense-review` | `offense-review:threat-hunt` |
| `taint-iris` | `taint-iris:hunt` |
| `taint-iris-next` | `taint-iris-next:dataflow-plan`, `taint-iris-next:source-sink-trace`, `taint-iris-next:finding-review` |
| `triage` | `triage:run` |
| `verify` | `verify:finding` |
| `patch` | `patch:finding` |
| `findings` | `findings:list` |
| `threat-model` | `threat-model:build`, `threat-model:read`, `threat-model:methodologies` |
| `randori` | `randori:pasta`, `randori:threat-model` |
| `x-ray` | `x-ray:run`, `x-ray:read` |
| `dep-hygiene` | `dep-hygiene:check` |
| `secret-scan` | `secret-scan:scan` |
| `license-scan` | `license-scan:scan` |
| `sbom-scan` | `sbom-scan:scan` |
| `variant` | `variant:lift-pattern`, `variant:hunt` |
| `ndiff` | `ndiff:fetch-cve`, `ndiff:extract-fix-pattern`, `ndiff:hunt-variants` |
| `iac-scan` | `iac-scan:scan` |
| `catalog` | `catalog:modules`, `catalog:tools` |
| `config` | `config:show` |
| `workspace` | `workspace:status`, `workspace:export-findings` |

Internal DAG modules such as `context-lite`, `pipeline`, and `systems-hunt`
stay hidden from `kuzushi modules`; `systems-hunt:*` entries are internal DAG
nodes selected through `sast:scan`, not public catalog tools. Deferred
compatibility modules are also hidden from the public catalog and shell
completions, but remain executable by exact tool name for operators who opt
into them: `carlini-threat-hunt`, `chrome-rce`, `prompt-armor`, `pwn`,
`recon`, `shinsa`, `tob`, `uaf-hunt`, `vendor-assessment`, and `vuln-scout`.

## External Dependencies

Native deterministic tools run without an LLM: `module-recommender`,
`context`, `findings`, `dep-hygiene`, `secret-scan`, `license-scan`, `sbom-scan`,
`iac-scan`, and local artifact readers.

`license-scan` checks package manifest license declarations, top-level
repository `LICENSE`/`COPYING` consistency, and SPDX source headers that
disagree with manifest licenses. Set `requireSourceSpdxHeaders` on
`license-scan:scan` to require SPDX headers on source files.

`sbom-scan` extracts first-party npm, Cargo, and Python dependency inventory
with package URLs, SHA-256 digests for recognized lockfiles, npm package-lock
dependency edges, and CycloneDX/SPDX JSON projections in the tool result.

Subprocess-backed tools require the operator to install or configure binaries:

| Tool | Dependency |
| --- | --- |
| `semgrep:scan` | `semgrep`, or pass `{"binary":"/path/to/semgrep"}`. |
| `codeql:scan` | CodeQL CLI, or pass `{"binary":"/path/to/codeql"}`. |
| Deferred `recon:nmap` | `nmap`, or pass a binary override. |
| Deferred `recon:subdomain`, deferred `recon:http-fingerprint`, online `ndiff:fetch-cve` | `curl`, unless using offline/local input. |

pi-agent-core-backed tools require Node, `@earendil-works/pi-agent-core`,
`@earendil-works/pi-ai`, a configured model, and provider credentials. A custom
bridge should be supplied through `runtime.agent_bridge_command` in config;
`KUZUSHI_AGENT_BRIDGE` is kept as a compatibility/bootstrap override.

Deferred plugin-backed wrappers also require exact tool invocation plus
explicit plugin roots:

| Module | Preferred option | Compatibility env var |
| --- | --- | --- |
| `vuln-scout` | `pluginRoot` | `KUZUSHI_VULN_SCOUT_PLUGIN` |
| `tob` | `pluginRoot` | `KUZUSHI_TOB_SKILLS_DIR` |
| `shinsa` | `pluginRoot` | `KUZUSHI_SHINSA_PLUGIN` |
| `prompt-armor` | `pluginRoot` | `KUZUSHI_PROMPT_ARMOR_PLUGIN` |

Missing subprocesses, models, bridges, or plugin roots fail explicitly. They do
not silently succeed and they do not substitute a different model.

## Artifacts And State

| Path | Produced by |
| --- | --- |
| `~/.kuzushi/v2/config.toml` | `kuzushi config init` |
| `.kuzushi/v2/config.toml` | Optional project override |
| `~/.kuzushi/v2/options.json` | persisted global tool options from shell `setg` |
| `.kuzushi/v2/options.json` | optional project/workspace tool option overrides |
| `.kuzushi/v2/findings.sqlite3` | scan, shell, and run-mode tool persistence |
| `.kuzushi/v2/attachments.json` | Rust shell KB attachments |
| `.kuzushi/v2/artifact-kb.sqlite3` | Local artifact knowledge search index |
| `.kuzushi/context-snapshot.json` | `context:build` |
| `.kuzushi/threat-model.json` | `threat-model:*`, `randori:*`, and threat-model readers |
| `.kuzushi/latest` | latest completed, partial, failed, skipped, or running run id |
| `.kuzushi/runs/<runId>/run.json` | canonical run metadata, status, cost, LLM audit, and artifact list |
| `.kuzushi/runs/<runId>/events.jsonl` | tool lifecycle events |
| `.kuzushi/runs/<runId>/trace.jsonl` | ordered trace steps for replay and activity views |
| `.kuzushi/runs/<runId>/context.json` | run-scoped context snapshot or explicit skipped marker |
| `.kuzushi/runs/<runId>/attack-surface.json` | run-scoped attack-surface snapshot or explicit skipped marker |
| `.kuzushi/runs/<runId>/threat-model.json` | run-scoped threat-model snapshot or explicit skipped marker |
| `.kuzushi/runs/<runId>/recommendations.json` | run-scoped recommendation snapshot or explicit skipped marker |
| `.kuzushi/runs/<runId>/findings.json` | normalized finding snapshot or explicit skipped marker |
| `.kuzushi/runs/<runId>/proof.json` | proof-state snapshot or explicit skipped marker |
| `.kuzushi/runs/<runId>/failures.json` | bounded failure handoff context, empty when no failure is recorded |
| `.kuzushi/runs/<runId>/report.md` | generated or placeholder Markdown report; promoted from `reportMarkdown`/`report_markdown` and `data.reportMarkdown`/`data.report_markdown` output aliases |
| `.kuzushi/runs/<runId>/artifacts.json` | canonical artifact manifest for the run |
| `.kuzushi/runs/<runId>/input.json` | prepared tool input for direct tool runs |
| `.kuzushi/runs/<runId>/result.json` | tool result envelope for direct tool runs |
| `.kuzushi/runs/<runId>/report.sarif` | optional SARIF report promoted from `reportSarif`/`report_sarif` and `data.reportSarif`/`data.report_sarif` output aliases |
| `.kuzushi/runs/<runId>/summary.json` | legacy compatibility mirror of `run.json` |
| `.kuzushi/runs/<runId>/triage.jsonl` | `sast:scan --triage` and post-scan triage |
| `.kuzushi/runs/<runId>/verify.jsonl` | `sast:scan` with verify/auto-patch inputs |
| `x-ray/` | `x-ray:run` |
| `.kuzushi/vendor-assessment/` | vendor assessment tools |
| `.prompt-armor/` | PromptArmor deterministic config/report tools |

Machine-readable run schemas live under `schemas/run.*.schema.json` and ship
through the npm subpath `kuzushi/schemas/*`. They document the canonical
camelCase artifact fields and the snake_case aliases accepted by Rust readers,
including `runId`/`run_id`, `startedAtUnix`/`started_at_unix`,
`promptHash`/`prompt_hash`, and `agentThreadContext`/`agent_thread_context`.

See [docs/rust-migration-status.md](docs/rust-migration-status.md) for the
module-by-module cutover ledger, intentional removals, artifact compatibility
notes, and TypeScript retention audit.

## Development

```bash
pnpm setup
cargo fmt --all
cargo test --workspace
cargo build --workspace
pnpm test:e2e
pnpm verify:pack
```

Useful package scripts:

| Script | Purpose |
| --- | --- |
| `pnpm dev -- <args>` | Run the native Rust CLI from source. |
| `pnpm build:native` | Build and stage the native binary for npm packaging. |
| `pnpm build` | Compile retained TypeScript library exports. |
| `pnpm test` | Run retained TypeScript unit/reference tests. |
| `pnpm test:rust` | Run `cargo test --workspace`. |
| `pnpm test:e2e` | Run the native smoke test. |
| `pnpm quality:crap-risk` | Gate changed production Rust/JS/TS code with the CRAP-risk < 7 proxy. |
| `pnpm doctor` | Run source-checkout development diagnostics; use `kuzushi doctor` for Rust CLI preflight. |
| `pnpm check:docs` | Guard port-contract docs, public docs/workflows, stale Rust CLI command examples, and retired TS runtime imports. |
| `pnpm export:source [path]` | Create a clean source tarball from tracked files with local state excluded. |

## TypeScript Retention

The old TypeScript/Ink CLI is no longer the npm runtime path:

- `bin.kuzushi` and `bin.kz` point to `bin/kuzushi-rs.mjs`.
- The `kuzushi-ts` npm bin is removed.
- The `dev:ts` package script and `scripts/kuzushi-dev` source CLI helper are
  removed.
- The source-only `src/cli.ts shell` route now exits with a Rust replacement
  message; the TypeScript/Ink shell implementation has been deleted.
- The old `dist/cli*` TypeScript CLI build outputs are excluded from the npm
  tarball.

Retained TypeScript is classified as one of:

- Published library/API surface: `dist/`, `kuzushi/modules`, and
  `kuzushi/testing`.
- Reference implementation for migration parity: legacy `src/modules/`,
  `src/agents/`, scanner normalization, and report helpers.
- Non-visual UI support code: `UIStore`, CI/plain-text output helpers,
  formatting helpers, and migration/reference fixtures. There is no retained
  TypeScript/Ink interactive TUI.

Do not add new runtime CLI behavior in TypeScript. New product execution paths
belong in `crates/kuzushi-core`, `crates/kuzushi-cli`, `crates/kuzushi-tui`,
or `crates/kuzushi-openai`.
