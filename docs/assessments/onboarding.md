# Operator Onboarding Assessment

Status: Rust-current assessment. Earlier retired-shell findings have been
translated to the Rust CLI/TUI surfaces under `crates/kuzushi-cli` and
`crates/kuzushi-tui`; deleted shell paths are not implementation targets.

Goal: someone with the README open should be running their first useful scan
in under 5 minutes.

This document is the audit. Status of fixes is tracked at the bottom.

## 1. README walkthrough — friction points

The README's `## Quick Start` section is the canonical first-five-minutes
path. Stepping through it as a new operator surfaces the following friction:

| # | Step | Issue |
|---|------|-------|
| 1 | `npm install -g kuzushi` | OK. Node 22+ is mentioned but only inside the `## Quick Start` paragraph; people who skim straight to the codeblock at the top of the page miss it. |
| 2 | `kuzushi` | The Rust shell welcome and help surfaces now point first-time operators at `scan .`, `findings`, and `/quickstart`; keep this covered in `crates/kuzushi-cli/src/presentation/terminal.rs` and `crates/kuzushi-tui/src/ui_view_models/help.rs`. |
| 3 | Credentials | Auth and model checks now route through Rust config/auth surfaces and explicit model selection. Keep missing-credential copy actionable without implying a fallback model. |
| 4 | `kuzushi scan /path/to/your/repo` | Rust scan mode takes explicit `--mode standard` or `--mode whitebox-static`; the README first-five-minutes path now uses `kuzushi scan . --mode standard --ci`. |
| 5 | Scanner prerequisites | Rust preflight and scanner failures should stay actionable when optional binaries such as Semgrep or CodeQL are absent. |

Other friction (outside the headline path):

- `## Quick Start (Contributors)` is **labeled identically** to the user
  Quick Start. New operators sometimes follow `pnpm setup` thinking it's the
  intended path.
- The list of provider env vars (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
  `GEMINI_API_KEY`/`GOOGLE_API_KEY`) is buried inside a `<details>` block —
  invisible to anyone scanning the page.
- There is no single "first 5 minutes" section. The README is reference
  material first, runbook second.

## 2. Top onboarding fixes — confidence-ranked

| # | Fix | Confidence | Where |
|---|-----|------------|-------|
| 1 | Add a "First 5 minutes" section at the very top of the README that hard-pins: install → set `ANTHROPIC_API_KEY` → `kuzushi scan .` | high | README.md |
| 2 | Bare `kuzushi` welcome message: keep concrete next-step lines for `scan .`, `findings`, and shell help. | high | `crates/kuzushi-cli/src/presentation/terminal.rs` |
| 3 | `/help` should print **`scan .`**, **`/use sast`**, and `/quickstart` through the Rust command catalog. | high | `crates/kuzushi-tui/src/commands/shell_command_specs/` + `crates/kuzushi-tui/src/ui_view_models/help.rs` |
| 4 | Catalog view should keep a recommended-first path for `sast` and show invocation-oriented module rows. | high | `crates/kuzushi-tui/src/ui_view_models/catalog.rs` |
| 5 | API-key/auth errors should tell operators to use `kuzushi auth` or explicit provider credentials without choosing a fallback model. | high | `crates/kuzushi-cli/src/adapters/auth_*` + Rust config loading |
| 6 | `Unknown config key: <name>` should point at documented config explanation/listing. | high | `crates/kuzushi-cli/src/application/config.rs` |
| 7 | `Run not found: <id>` (`runs show`) should point at `kuzushi runs list`. | high | `crates/kuzushi-cli/src/application/runs.rs` |
| 8 | Pre-scan estimate: surface an honest cost or budget signal before model-backed scan work starts. | medium | deferred until calibration exists |
| 9 | `/quickstart` slash verb should print a first-run path backed by the Rust command specs. | high | `crates/kuzushi-tui/src/commands/shell_command_specs/navigation.rs` + `crates/kuzushi-tui/src/ui_view_models/help.rs` |
| 10 | README Configuration block hides env vars in `<details>`. Lift `ANTHROPIC_API_KEY` to the top-level "First 5 minutes" section. | high | README.md |

## 3. Error-message audit — worst-current → proposed

| Current | Proposed |
|--------|----------|
| `${envVar} is not set.` (preflight) | `${envVar} is not set. Get an Anthropic API key at https://console.anthropic.com/settings/keys, then export it (export ${envVar}=sk-…), pass --api-key, or run \`kuzushi auth\` to save it.` |
| `Unknown config key: ${key}` (`config get/unset`) | `Unknown config key: "${key}". Run \`kuzushi config explain\` to list documented keys.` |
| `Run not found: ${id}` (compareRuns, runs show) | `Run not found: "${id}". Run \`kuzushi runs list\` to see available run ids.` |
| `No tasks registered.` (`task list`) | `No tasks registered. Built-in modules expose tasks via \`kuzushi scan\`. If you ran \`task list\` against an external repo, ensure the module is loaded with --load.` |
| `No runs database at ${dbPath}.` (`runs show` without a prior run) | `No runs database at ${dbPath}. Run \`kuzushi scan .\` first to create one.` (The `runs list` path already says this; make `runs show` consistent.) |

These are local error strings that name the failed field and tell the
operator the exact next command to run. None of them silently substitute a
default; all of them route through the existing `CliUsageError` exit-2 path.

## 4. /help completeness vs. CLAUDE.md verb tables

Cross-checking Rust `ShellCommandSpec` entries against CLAUDE.md §"Operator
verbs":

| CLAUDE.md verb | In catalog? | Notes |
|----------------|-------------|-------|
| `/modules`, `/tools`, `/use`, `/back`, `/findings`, `/open`, `/tune`, `/threats`, `/since`, `/actor` | yes | full coverage |
| `/plan`, `/yes`, `/no` | yes | |
| `/prompts`, `/prompt edit/show/diff/reset`, `/show prompts` | yes | |
| `/show runs`, `/replay`, `/trace` | yes | |
| `/show aliases` | yes | |
| `/quickstart` | yes | registered in `NAVIGATION_COMMANDS` and rendered from `quickstart_model` |
| `/help` (one-line examples) | yes | `shell_help_examples()` includes first-run examples such as `scan .` |

The structural drift tests live in `crates/kuzushi-tui/src/commands/tests.rs`
and keep featured help examples backed by `ShellCommandSpec.aliases`.

## 5. Catalog view — module descriptions

The Rust catalog view model pulls routed module metadata and should stay
oriented around the first useful scan path rather than marketing copy.

Concretely missing for first-time operators:

- A "RECOMMENDED FIRST" badge on `sast` (the only module that scans by
  default).
- A one-line invocation example next to each module (`/use sast` already
  appears in the tip strip; not anchored per row).

The current implementation lives in `crates/kuzushi-tui/src/ui_view_models/catalog.rs`.

## 6. /quickstart flow

Proposed:

```
kuzushi> /quickstart

  Quickstart — three steps to your first scan
    1. Make sure you have a target. Current target: ./acme-api
       (Change with: /target <path>)
    2. Pick a module. The default scanner is `sast`:
       /use sast
    3. Kick off a scan:
       scan .            (uses the default preset)
       /plan run lightly, no verify   (English → option diff)

  Estimated cost for the default preset on a small repo: ~$0.10–$0.50
  Watch the run live; results stream to /findings.
```

Implementation: a Rust `quickstart` command spec plus `quickstart_model`.
No prompt strings get hardcoded into module prompts; this is help text, not a
tool-prompt surface, so the `.kuzushi/prompts/<moduleId>/<verb>.md` override
rule does not apply.

## 7. Cost / budget visibility before a scan

The Rust scan path does not yet have a calibrated estimate source before
model-backed work starts. Adding a single "estimated cost" line would help
users decide whether to proceed, but this remains deferred until the estimate
can be backed by repo size, selected tasks, and configured model pricing.

## 8. Hard guardrails respected

- No silent model fallback added or removed.
- All new error messages route through `CliUsageError` and never substitute
  a default model.
- `/quickstart` is wired into Rust `ShellCommandSpec` and `parse_command` —
  no separate dispatch path.
- No prompt strings hardcoded; all changes are in help-text and error
  surfaces.
- `enforceAgentQuery` not touched.

## 9. Status — fixes shipped in this pass

- [x] (1) README "First 5 minutes" section
- [x] (2) Bare `kuzushi` welcome — concrete next steps
- [x] (3) `/help` "Get started" block with examples
- [x] (4) `ModuleCatalog` "RECOMMENDED FIRST" hint on `sast`
- [x] (5) Preflight API-key message links to Anthropic console
- [x] (6) `Unknown config key` points at `config explain`
- [x] (7) `Run not found` points at `runs list`
- [x] (9) `/quickstart` slash verb
- [x] (10) README env-var lift out of `<details>`
- [ ] (8) Pre-scan cost estimate — deferred (needs calibration)
