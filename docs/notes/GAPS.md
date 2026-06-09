# Kuzushi — Product / Feature Gap Analysis

_Snapshot: 2026-04-17 against v0.16.0 on `main`. GAPs 1–6 and 8 have been addressed in this branch; GAP 7 deferred. See the [Status](#status-2026-04-17) section below for per-gap deltas; the original audit follows._

## Status (2026-04-17)

| Gap | Title | Status | Landed in this branch |
|-----|-------|--------|-----------------------|
| 1 | Module ecosystem framing | ✅ Done | Built-in wrappers `randori`, `vuln-scout`, `tob`; docs restructured; `--load package:` detects Claude Code plugins and redirects. |
| 2 | Module-author SDK | ✅ Done | `kuzushi/modules` + `kuzushi/testing` subpath exports; `kuzushi create-module` scaffolder (three templates); MCP HTTP Streamable transport. |
| 3 | CI last-mile | ✅ Done | `--junit <path>`, explicit exit codes (0/1/2/3) documented in `scan --help`, `kuzushi runs list|show`, reference workflow at `.github/workflows/kuzushi-reference.yml`, SSE schema + `examples/sse-client.mjs`. |
| 4 | CLI ergonomics | ✅ Done | `.addHelpText("after", ...)` examples on every subcommand; stack traces surface under `--debug` / `KUZUSHI_DEBUG=1`; `CliCommandError.details` rendered as bullets. |
| 5 | Onboarding | ✅ Done | `kuzushi init` scaffolds `.kuzushi/config.json` + `.env.example`; `kuzushi doctor` (TS) runs preflight and surfaces results; `kuzushi config explain [key]` documents every user-tunable key; `kuzushi config validate --preflight` runs env + binary checks. |
| 6 | Observability | ✅ Done (scoped) | `KUZUSHI_LOG_FORMAT=json` switches logger to structured JSON lines with redaction preserved. OTel deferred per product direction; cost aggregation exposed via `kuzushi runs show --costs`. |
| 7 | Auth / multi-tenant | ⏸ Deferred | Single-user design intentional. Revisit only if team/enterprise positioning changes. |
| 8 | Test coverage unevenness | ✅ Done (targeted) | New suites: `tests/copilot/execute-tool.test.ts` (dispatch, governance deny, cost/audit), `tests/cli/preflight.test.ts`, `tests/report-junit.test.ts`, JSON-format logger cases. 1779/1780 tests passing (1 pre-existing skip). |

### Roadmap modules shipped since the audit

| Module | Status | Ships as |
|--------|--------|----------|
| `shinsa` | ✅ Shipped | Built-in module wrapping `shinsa-plugin` — ISO 27001 Annex A + NIST SP 800-53 Rev 5. Tools: `shinsa:scan`, `shinsa:quick-check`, `shinsa:nist-scan`, `shinsa:nist-quick-check`, `shinsa:frameworks`. |
| `prompt-armor` | ✅ Shipped | Built-in module wrapping `promptarmor-plugin` — LLM red teaming. Tools: `prompt-armor:scan`, `prompt-armor:analyze`, `prompt-armor:attack`, `prompt-armor:diff`, `prompt-armor:report`, `prompt-armor:config`. Network commands gated on `authorized: true`. |
| `blackbox`, `pwn`, `honeypot`, `yokai`, `pentest`, `revgraph` | ⏳ Plugins exist (`allsmog/blackbox-claude-plugin`, `allsmog/pwn-claude-plugin`, `allsmog/Sasoi`, `allsmog/yokai`, `allsmog/mcp-pentest`, `allsmog/revgraph`) but not yet wrapped into built-in CopilotModules. Candidates for the next batch. |

The body below is the original audit — preserved verbatim so PR reviewers can diff claim vs. delivery.

---

_As of 2026-04-17, against v0.16.0 on `main`._

This document captures an audit of Kuzushi's current product surface, what actually works end-to-end, where the implementation diverges from what the README and VISION advertise, and what to fix. It exists so the team has a durable reference alongside the code — update it as gaps close or new ones emerge.

---

## Executive summary

Kuzushi's **core SAST pipeline is production-grade** and the `scan` / `shell` / `run` execution modes all work. The honest list of loadable `CopilotModule`s, however, is much shorter than the README implies — four, not twelve — and the ergonomics around CI integration, onboarding, and module authorship lag the underlying engine.

The three highest-impact fixes, ranked by leverage:

1. **Stop conflating module types in the docs** and ship `CopilotModule` wrappers so `randori`, `vuln-scout`, and `tob` capabilities are reachable from `shell` and `run`, not only from the `scan` pipeline. (GAP 1)
2. **Finish the last mile of CI integration** — JUnit, streaming SARIF, explicit exit codes, a reference GitHub Actions workflow. (GAP 3)
3. **Polish the CLI first-contact experience** — per-command `--help` examples, richer error context, a real `kuzushi init` and surfaced `doctor` subcommand. (GAPs 4 + 5)

The rest (module-author SDK, observability, multi-tenant auth, test coverage evenness) is real but deferrable.

---

## What works today (baseline)

- **Three execution modes, all real.** `shell` (Ink REPL), `scan` (DAG SAST pipeline), `run` (headless single-tool).
- **`sast` module is the reference implementation.** `src/modules/core-sast.ts` exposes 11 tools (`sast:scan`, `sast:semgrep`, `sast:codeql`, `sast:triage`, `sast:verify`, `sast:patch`, `sast:findings`, `sast:context`, `sast:threat-hunt`, `sast:taint-iris`, plus `sast:agentic`) with graceful `ToolResult` errors, option merging, preset handling, and cost tracking.
- **Two additional in-tree modules.** `n-day-diff-hunter` (3 tools) and `variant-hunter` (2 tools). Thin but functional.
- **External CopilotModule package.** `@kuzushi/augur` — the only `@kuzushi/*` dep that is a real `CopilotModule` export.
- **MCP bridge (stdio transport).** `src/modules/mcp-bridge.ts` wraps MCP tools as module tools.
- **Ink UI** (`src/ui/`) — setup wizard, credential prompt, shell, progress/spinners, threat-model editor.
- **Event bus + audit trail + governance enforcer** (`src/bus/`, `src/governance/`) — scope policy, action tier, budget tracking, cost events.
- **Persistence.** SQLite-backed workspaces + scan checkpoints; inflight cache keyed on git HEAD SHA.
- **Report formats.** SARIF, JSON, CSV, JSONL, Markdown.

---

## GAP 1 — Module ecosystem framing

### Current state

The README and VISION list a module catalog (`sast`, `randori`, `vuln-scout`, `augur`, `blackbox`, `pwn`, `honeypot`, `yokai`, `prompt-armor`, `shinsa`, `revgraph`, plus `tob-skills`) as if all are peer `CopilotModule`s callable via `module:action` from shell/run. In reality:

| Name | Installed? | Loadable as `CopilotModule`? |
|---|---|---|
| `sast` | builtin | ✅ Yes |
| `variant-hunter` | in-tree | ✅ Yes |
| `n-day-diff-hunter` | in-tree | ✅ Yes |
| `@kuzushi/augur` | npm | ✅ Has `main: index.js` exporting `CopilotModule` |
| `@kuzushi/randori-plugin` | npm | ❌ **Claude Code plugin** (`commands/`, `agents/`, `skills/`, `hooks/`, `CLAUDE.md`) — no JS main |
| `@kuzushi/tob-skills` | npm | ❌ Claude Code plugin collection under `plugins/` |
| `@kuzushi/vuln-scout` | npm | ❌ Claude Code plugin under `whitebox-pentest/` |
| `blackbox`, `pwn`, `honeypot`, `yokai`, `prompt-armor`, `shinsa`, `revgraph` | not installed | ❌ Don't exist in any form |

**Important nuance:** the three Claude Code plugin packages **are** used intentionally. They're invoked from dedicated SAST pipeline tasks:
- `src/agents/tasks/threat-modeling/randori.ts` + `resolve-randori.ts`
- `src/agents/tasks/vuln-scout/vuln-scout.ts` + `resolve-vuln-scout.ts`
- `src/agents/tasks/tob-audit/tob-audit.ts` + `resolve-tob-plugin.ts`

Each task spawns a Claude Code subprocess with the plugin loaded and collects artifacts/findings. This is not vaporware — it is architecture that the docs fail to explain.

### Consequences

1. **Docs mislead.** A reader expects `kuzushi run randori:pasta` to work; it doesn't, because `randori` isn't a `CopilotModule`.
2. **Shell/run can't reach these capabilities.** Interactive users have no way to invoke PASTA threat modeling or whitebox pentest outside a full `kuzushi scan` invocation with the right task filter.
3. **`kuzushi shell --load package:@kuzushi/randori-plugin` fails confusingly.** `src/copilot/core.ts:loadPackageModule` expects a `CopilotModule` export; the resulting error message doesn't point users at the right thing.
4. **Never-shipped modules are advertised as current features.** `blackbox`, `pwn`, `honeypot`, `yokai`, `prompt-armor`, `shinsa`, `revgraph` are listed in README without any "roadmap" framing.

### Proposed fix

**Recommended (hybrid):**
1. **Docs honesty pass.** Restructure README and VISION into three explicit buckets: (a) built-in CopilotModules, (b) external CopilotModule packages (just `augur`), (c) Claude Code plugins consumed by the SAST pipeline. Remove or clearly mark as "not yet shipped" the modules that don't exist.
2. **Thin CopilotModule wrappers.** Ship `src/modules/core-randori.ts`, `core-vuln-scout.ts`, `core-tob.ts` that expose the respective plugin capabilities as `randori:*`, `vuln-scout:*`, `tob:*` tools. Each wrapper reuses the existing `resolve-*.ts` helper and extracts the Claude-subprocess invocation from the pipeline task into a shared runner (no duplication, no behavior change for `scan`).
3. **Friendlier `--load package:` error.** Detect `.claude-plugin/plugin.json` in a loaded package and throw a message pointing the user at `builtin:<id>` instead.

Alternatives considered:
- _Port features into native TS_ — too expensive, and loses the Claude-Code-plugin surface that already works.
- _README-only fix_ — closes the trust gap but still leaves shell/run users unable to reach the functionality.

### Pointer

Full implementation plan for GAP 1 is tracked in the project plan file (`/home/node/.claude/plans/ok-so-i-need-joyful-grove.md`).

---

## GAP 2 — Module-author SDK

### Current state

- `package.json` `exports` only publishes `.` and `./package.json`. There is no `kuzushi/modules` subpath export for `CopilotModule` / `ModuleTool` / `ToolExecutionContext` types, and no `kuzushi/testing` helper for mock contexts.
- No scaffolder (`kuzushi create-module <id>`) — module authors hand-craft `module.manifest.json` + TS boilerplate.
- MCP bridge (`src/modules/mcp-bridge.ts:53-57`) supports stdio only; HTTP/SSE throws. Cuts off a large swath of remote MCP servers.
- Module-requirement checks are shallow — `src/modules/loader.ts:95-96` has "for now, trust that binaries are documented" rather than `which()` checking.
- Docs stop at the one-file starter in CLAUDE.md section 11 — no testing recipes, no mock-context examples.

### Proposed fix

1. Add subpath exports in `package.json`: `"./modules"` → public types, `"./testing"` → mock-context factory.
2. Implement `kuzushi create-module <id> [--template offense|defense|intel]` in `src/cli.ts`. Scaffold manifest + TS + vitest skeleton.
3. Finish the MCP HTTP/SSE transport (high leverage — every MCP server becomes reachable without us writing code).
4. Add async `which()` checks for binaries declared in `module.manifest.json`.
5. Write a short "Building modules" doc page covering: types, testing patterns, packaging, publishing.

---

## GAP 3 — CI last-mile

### Current state

Works: SARIF export (`src/report-sarif.ts`), exit codes, quality gates, `--no-ui`, `--json`, SSE streaming server (`--stream`, `--stream-port`).

Missing:

- **No JUnit XML** output. Most CI runners aggregate JUnit for test results.
- **SARIF is not streamed.** Findings accumulate in memory until end-of-scan; OOM risk on large monorepos.
- **No reference `.github/workflows/kuzushi.yml`** in the repo.
- **Exit codes undocumented.** Today both "findings present" and "crash" can exit 1; users can't differentiate in CI.
- **SSE stream has no example consumer.** The event schema lives in `src/bus/events.ts`, but there's no doc on how to subscribe or what the events look like over the wire.
- **No `kuzushi runs list`.** `--resume [runId]` works, but listing resumable runs requires hand-querying SQLite.

### Proposed fix

1. Add `--junit report.xml` output (map findings → JUnit `<testcase>` schema with severity-as-failure).
2. Rework SARIF writer to stream findings as they arrive; document a `--sarif-stream` option.
3. Define exit codes in `src/cli/errors.ts` and document in `kuzushi scan --help`:
   - `0` clean, `1` findings present, `2` config/auth error, `3` crash.
4. Publish `.github/workflows/kuzushi.yml` template (PR comments, SARIF upload to code-scanning).
5. Document the SSE event shape and ship a `scripts/sse-client-example.mjs`.
6. Add `kuzushi runs list` + `kuzushi runs show <runId>`.

---

## GAP 4 — CLI ergonomics

### Current state

- Commander-based CLI in `src/cli.ts` with `--help` on every subcommand — but **zero usage examples**. A new user typing `kuzushi scan --help` sees an option dump.
- Error handling routes through `src/cli/errors.ts:wrapCliAction`, but the `CliCommandError.details` field is rarely populated. Most failures land as single-line messages; stack traces only surface under `KUZUSHI_DEBUG=1`.
- Non-TTY headless scans run **silently**. Pipeline events exist in `src/bus/events.ts` but aren't rendered to stdout when Ink is disabled.
- `kuzushi config validate` runs only lightweight schema checks. The expensive validation (API keys, scanner binaries, DB writability) happens at scan start — users wait ~10s before failing.

### Proposed fix

1. Add `.addHelpText('after', ...)` examples to every subcommand in `src/cli.ts`.
2. Populate `CliCommandError.details` in the major failure paths (config, credential, scanner-missing) and render as bullets.
3. Add a `--progress` flag (default-on in TTY) that renders bus events as plain-text stdout lines in `--no-ui` mode.
4. Make `kuzushi config validate` actually dry-run the preflight (env vars, `which()` on scanner binaries, DB writeability).

---

## GAP 5 — Onboarding

### Current state

- Setup wizard (`src/ui/setup.ts:44-83`) works in TTY. Non-TTY runs skip setup entirely; CI gets no validation.
- **No `kuzushi init` command.** `config get|set|unset|validate` exist, but no command bootstraps `.kuzushi/` and walks a new user through first-time auth.
- **Credentials fail silently in non-TTY** if `ANTHROPIC_API_KEY` is unset — the dialog can't render, so the run just dies with no instruction on which env vars to set.
- **No `kuzushi config --explain`** to enumerate valid keys with defaults. Users must grep source.
- `scripts/doctor.sh` exists but isn't surfaced as a CLI subcommand.

### Proposed fix

1. Add `kuzushi init` — creates `.kuzushi/config.json` with sensible defaults, writes `.env.example`, prints provider-key instructions.
2. On non-TTY with missing credentials, fail fast with a message enumerating the exact env vars to set.
3. Promote `scripts/doctor.sh` to `kuzushi doctor` (or port to TS). Have it check binaries, env, DB writability, cache dir.
4. Add `kuzushi config --explain` listing every key with default + type.

---

## GAP 6 — Observability

### Current state

- `src/logger.ts` sinks to `console.error` only. Level controlled by `KUZUSHI_LOG_LEVEL`, defaults to `warn`. Has useful API-key redaction (`sk-ant-`, `sk-`, `key-`, `AIza`).
- No OpenTelemetry / trace IDs / spans. Cross-module correlation requires reading the SQLite audit trail by hand.
- Audit trail records per-tool (`src/copilot/core.ts:159-163, 187-203`), but cost events and governance decisions live in separate structures — no unified run-level report.
- `ToolResult.costUsd` is tracked but there's no `kuzushi runs show <runId> --costs` breakdown.

### Proposed fix (low priority)

1. `KUZUSHI_LOG_FORMAT=json` → structured JSON log lines.
2. Opt-in OTel exporter (`KUZUSHI_OTEL_ENDPOINT`) wrapping tool dispatch + DAG task boundaries.
3. `kuzushi runs show <runId> --costs` (overlaps GAP 3 item 6).

---

## GAP 7 — Auth / multi-tenant

### Current state

Deliberately single-user / single-tenant:
- No team/org model, no SSO, no RBAC.
- API keys stored plaintext in `.kuzushi/config.json` (warned at `src/cli.ts:52-56` but not blocked).
- Credentials read ad-hoc from `process.env` inside tasks, not through a central `CredentialProvider`.

### Proposed fix (only if positioning changes)

Matches current positioning (MIT, OSS, local SQLite, individual or small team). If team/enterprise becomes a target:
1. OS keychain integration (`keytar` or native) for API keys; warn but don't block plaintext.
2. Central `CredentialProvider` interface on `ToolExecutionContext` so tasks stop reading `process.env` directly.
3. Later: multi-user workspaces, SSO, RBAC.

---

## GAP 8 — Test coverage unevenness

### Current state

- 178 test files, ~39.6K lines (includes fixtures).
- Well-covered: `src/agents/` (54 tests — triage, variant-analysis, PoC executor, exploit chains), root-level scoring/store/config (37 tests), discovery (11 tests).
- Thin: modules registry (4 tests, all registry mechanics — no tool-dispatch coverage), copilot (3 tests), cli (5 tests).
- **No dedicated tests** for `CopilotCore.executeTool` error paths, `ModuleRegistry.resolveTool` negative cases, `n-day-diff-hunter` or `variant-hunter` tools, or governance post-execution (budget exhaustion mid-run).

### Proposed fix

1. Module dispatch suite: duplicate-ID rejection, `init` failure rollback, `disposeAll` ordering, `headlessOnly` filter, unknown-tool errors.
2. Tool-level tests for the two thin in-tree modules.
3. Governance test for budget exhaustion triggering during a multi-step tool call.

---

## Recommended prioritization

By impact-per-hour, highest first:

| # | Item | Gap | Est. |
|---|---|---|---|
| 1 | Docs honesty pass on README + VISION | 1 | 1h |
| 2 | CLI `--help` examples + error-context bullets | 4 | 3–4h |
| 3 | JUnit + explicit exit codes + GH Actions template | 3 | 4–6h |
| 4 | MCP HTTP/SSE transport + SDK subpath exports | 2 | 1–2d |
| 5 | `randori` / `vuln-scout` / `tob` CopilotModule wrappers | 1 | 2–3d |
| 6 | `kuzushi init` + surface `doctor` as subcommand | 5 | 1d |
| 7 | Module dispatch test suite expansion | 8 | 1d |
| 8 | Structured logging + OTel | 6 | defer |
| 9 | Auth / multi-tenant | 7 | defer unless positioning changes |

Items 1 and 5 form the GAP 1 implementation plan currently queued for execution.
