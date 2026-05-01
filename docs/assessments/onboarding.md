# Operator Onboarding Assessment

Goal: someone with the README open should be running their first useful scan
in under 5 minutes.

This document is the audit. Status of fixes is tracked at the bottom.

## 1. README walkthrough — friction points

The README's `## Quick Start` section is the canonical first-five-minutes
path. Stepping through it as a new operator surfaces the following friction:

| # | Step | Issue |
|---|------|-------|
| 1 | `npm install -g kuzushi` | OK. Node 22+ is mentioned but only inside the `## Quick Start` paragraph; people who skim straight to the codeblock at the top of the page miss it. |
| 2 | `kuzushi` | The bare command starts the shell. The first thing the operator sees is `formatWelcome(...)` (`src/copilot/shell.ts`) which says "Type 'modules' to choose a workflow, or '/ask <question>' for agent chat." That hides the most common next action: `scan .`. There is no `Try this first:` line. |
| 3 | Credential prompt | A readline-based credential prompt fires from `runReadlineCredentialPrompt()` when no creds are saved. It mentions `[1] Anthropic API key`, `[c] Inherit Claude`, `[i] use env vars`, `[Enter] Skip`. There is no link to where to get an Anthropic API key. The "Inherit Claude" path is opaque to people who do not already use Claude Code. |
| 4 | `kuzushi scan /path/to/your/repo` | This implicitly assumes the user already chose a preset. With no `--preset`, the wizard fires (`isFirstRun` → `runSetupWizard`) and the user is asked to pick `fast/safe/standard/deep/reference` but the README never told them this would happen. |
| 5 | "Auto-downloads Opengrep if you don't have a scanner" | True, but the preflight surface in `kuzushi doctor` still reports `[MISSING] binary:semgrep` because the embedded resolver is separate. Confusing for a first-time `kuzushi doctor`. |

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
| 2 | Bare `kuzushi` welcome message: replace generic "Type 'modules'…" with two concrete next-step lines: `scan .` to scan cwd, `/use sast` to focus a module, `/quickstart` for a guided tour. Show the active model. | high | `src/copilot/shell.ts:formatWelcome` |
| 3 | `/help` should print **`scan .`** and **`/use sast`** in a "Get started" block above the verb table, and call out `/quickstart` once. | high | `src/copilot/shell.ts:formatHelp` |
| 4 | CatalogView (`ModuleCatalog.tsx`) currently prints `id · description · last-run`. Add a "RECOMMENDED FIRST" hint pointing at `sast` (the only module that scans code out of the box). | high | `src/ui/components/ModuleCatalog.tsx` |
| 5 | API-key error: `${ENV} is not set.` is correct but does not link to provider docs or remind operators that `kuzushi auth` exists. Replace with: `${ENV} is not set. Get an Anthropic API key at https://console.anthropic.com/settings/keys, then export it or run \`kuzushi auth\`.` | high | `src/cli/preflight.ts:checkAgentRuntimeCredentials` |
| 6 | `Unknown config key: <name>` does not list candidate keys or tell operators about `kuzushi config explain`. | high | `src/cli.ts:configCmd.get/unset` |
| 7 | `Run not found: <id>` (`compareRuns`, `runs show`) — silent on how to find valid run ids. Add `Use \`kuzushi runs list\` to see available run ids.` | high | `src/cli.ts:compareRuns` + `runs show` |
| 8 | First-run wizard / scan: print a one-line cost estimate before the first scan kicks off, pinned to the chosen preset. The numbers exist (preset definitions); they're never surfaced before kickoff. | medium | (out of scope this pass — flagged for later) |
| 9 | Add `/quickstart` slash verb that prints a 3-step starter: ensure target → recommend `/use sast` → suggest `scan .` with example. | high | `src/copilot/shell.ts` + `src/copilot/shell-commands.ts` |
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

Cross-checking `SHELL_COMMAND_CATALOG` against CLAUDE.md §"Operator verbs":

| CLAUDE.md verb | In catalog? | Notes |
|----------------|-------------|-------|
| `/modules`, `/tools`, `/use`, `/back`, `/findings`, `/open`, `/tune`, `/threats`, `/since`, `/actor` | yes | full coverage |
| `/plan`, `/yes`, `/no` | yes | |
| `/prompts`, `/prompt edit/show/diff/reset`, `/show prompts` | yes | |
| `/show runs`, `/replay`, `/trace` | yes | |
| `/show aliases` | yes | |
| `/quickstart` | **missing** | not present anywhere |
| `/help` (one-line examples) | partial | description column is fine, but no inline example for the most-used verbs |

The structural drift-test (`/help output contains every verb from the
commands catalog`) already exists in `tests/copilot/shell.test.ts:1178`.
It guarantees registry → help-table coverage but does not check that the
verbs the operator actually needs first (`/scan`, `/use`, `/findings`)
appear with examples.

## 5. Catalog view — module descriptions

`ModuleCatalog.tsx` already pulls `description` from `ShellModuleCard`, but
the description is whatever the module's `displayName`/`description` happens
to be — there is no "recommended first" hint, and `formatModuleDescription`
truncates after the first sentence so anything pithier than `Lorem ipsum.`
shows up unhelpfully terse.

Concretely missing for first-time operators:

- A "RECOMMENDED FIRST" badge on `sast` (the only module that scans by
  default).
- A one-line invocation example next to each module (`/use sast` already
  appears in the tip strip; not anchored per row).

The change is local to `ModuleCatalog.tsx` and the buildModuleCatalog flow.

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

Implementation: a single new slash command `quickstart` with a static
template wired through `formatHelp`-style rendering, plus a one-line catalog
hint. No prompt strings get hardcoded into module prompts (this is a
help-text surface, not a tool-prompt surface, so the
`.kuzushi/prompts/<moduleId>/<verb>.md` rule does not apply).

## 7. Cost / budget visibility before a scan

The setup wizard does not print a cost estimate before kicking off the
first scan. Adding a single "estimated cost for `<preset>` on this repo"
line would directly help users decide whether to proceed. Out of scope for
this onboarding pass (deferred — flagged in fixes table item 8) because it
needs a calibration step against repo size to be honest.

## 8. Hard guardrails respected

- No silent model fallback added or removed.
- All new error messages route through `CliUsageError` and never substitute
  a default model.
- `/quickstart` is wired into `SHELL_COMMAND_CATALOG` (the registry) and
  routes through `handleSlashCommand` — no separate dispatch path.
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
