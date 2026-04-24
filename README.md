<img src="kuzushi.png" alt="Kuzushi" width="200" />

# Kuzushi — Security-Native AI Operating Environment

[![CI](https://github.com/allsmog/Kuzushi/actions/workflows/ci.yml/badge.svg)](https://github.com/allsmog/Kuzushi/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/kuzushi)](https://www.npmjs.com/package/kuzushi)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[kuzushi.dev](https://kuzushi.dev)

Kuzushi combines offensive security, defensive operations, and compliance governance into a single interactive platform — powered by LLM agents, backed by a persistent workspace, and delivered through a rich terminal UI.

Find the vulnerability. Prove it's exploitable. Deploy a honeypot to detect it. Check if it violates PCI DSS. Generate the patch. One tool, one conversation.

```sh
npm install -g kuzushi
kuzushi
```

## Three Ways to Use It

### Shell (default)

Just type `kuzushi`. The interactive copilot shell starts with your loaded modules, available tools, and any active workspace. Talk naturally or use structured commands.

```
kuzushi shell                                  # default — just `kuzushi` works
kuzushi shell --workspace acme-pentest         # resume an engagement
kuzushi shell --target ./repo                  # set initial target
kuzushi shell --load randori,vuln-scout,tob    # pre-load specific built-in modules
```

```
╭─────────────────────────────────────────────────────────────╮
│  kuzushi shell                      workspace: acme-api     │
│  modules: sast, randori, vuln-scout, tob, variant-hunter    │
│  target: ./acme-api  (Node.js + Express + PostgreSQL)       │
╰─────────────────────────────────────────────────────────────╯

kuzushi> modules
kuzushi> use sast
kuzushi/sast> run scan ./repo preset=deep
kuzushi/sast> back
kuzushi> tools
kuzushi> run verify:finding fingerprint=abc123
kuzushi> exit
```

#### Common shell flows

```
# Catalog / module home / tune
kuzushi> use sast             # focus → module home
kuzushi/sast> findings        # unified list with filter chips + chain boxing
kuzushi/sast> open F-0001     # linear deep page for a finding
kuzushi/sast> tune            # six plain controls + optional "house rules"
kuzushi/sast> back            # step up one level

# Natural-language planner — English → option diff → y/n apply
kuzushi/sast> /plan run harder, focus on auth, stop wasting money
kuzushi/sast> y               # apply the proposed changes

# Prompt editor — per-tool system-prompt override in $EDITOR
kuzushi/sast> /prompt edit triage          # opens .kuzushi/prompts/sast/triage.md
kuzushi/sast> /prompt show verify          # show effective prompt + source
kuzushi/sast> /show prompts                # cross-module audit table

# Replay / trace — re-read the outcome of a past run, no re-exec
kuzushi> /show runs                        # list recent runs
kuzushi> /replay 7f3a                      # re-render a past summary
kuzushi> /trace 7f3a                       # stream the per-event JSONL log

# Threat-model views — five screens over the randori output
kuzushi> /threats dfd                      # ASCII data flow diagram
kuzushi> /threats stride                   # element × STRIDE heat matrix
kuzushi> /threats stories                  # attacker narrative cards
kuzushi> /threats scope                    # criticality + operator edits
kuzushi> /threats summary                  # counts, drives, export paths
# Press 1..5 at any threat view to cycle.

# Short-ID aliases — F-0001 / C-01 resolve through a deterministic map
kuzushi/sast> /show aliases F-             # filter by prefix
kuzushi/sast> open F-0003                  # same as typing the fingerprint

# Diff-aware — pivot to "what changed since <ref>" without restarting
kuzushi> /since main                       # findings + threats scoped to changed files
kuzushi> /since v1.2.0                     # works with any git ref (tags, SHAs, HEAD~5)
```

#### Keyboard shortcuts

| Key            | While running                     | At the idle prompt                  |
| -------------- | --------------------------------- | ----------------------------------- |
| `Ctrl+C`       | Abort the running tool / turn     | First press arms, second exits (2s) |
| `Ctrl+D`       | Abort (same as `Ctrl+C`)          | Exits                               |
| `Enter`        | —                                 | Send input                          |
| `↑` / `↓`      | —                                 | Previous / next command             |
| `Esc`          | —                                 | Clear input buffer                  |
| `1`–`5`        | —                                 | Cycle threat-model sub-views        |

Ctrl+C aborts through four independent paths (Ink `useInput` on raw stdin,
a byte-level stdin watcher, `SIGINT`, and a dedicated `/dev/tty` reader)
so long-running LLM tools still cancel cleanly even when a subprocess has
grabbed the terminal's foreground group. Under abort every Claude Agent
SDK subprocess (and its descendants) receives `SIGTERM` directly — no
relying on the SDK's own signal handling.

Set `KUZUSHI_ABORT_DEBUG=1` to trace the abort path to stderr when
diagnosing Ctrl+C issues.

#### On-disk artefacts

Operators can version-control any of these and have them round-trip with
the shell — `/prompt edit` and `/tune` write here, and randori / scan runs
read from here.

| Path                                       | Role                                       |
| ------------------------------------------ | ------------------------------------------ |
| `~/.kuzushi/config.json`                   | Global config (`/config`)                  |
| `.kuzushi/threat-model.json`               | Persistent threat model (editable)         |
| `.kuzushi/house-rules/<moduleId>.md`       | Operator nudges per module (`/tune`)       |
| `.kuzushi/prompts/<moduleId>/<verb>.md`    | Per-tool system-prompt override            |
| `.kuzushi/runs/<runId>/summary.json`       | Run summary (for `/replay`)                |
| `.kuzushi/runs/<runId>/triage.jsonl`       | Per-event triage audit log (for `/trace`)  |
| `.kuzushi/runs/<runId>/verify.jsonl`       | Per-event verify audit log (for `/trace`)  |
| `.kuzushi/findings.sqlite3`                | Findings + pipeline_runs DB                |

### Scan (headless pipeline)

The full SAST pipeline — 40+ agent tasks orchestrated as a DAG. Semgrep, CodeQL, 30+ agentic detectors, AI triage, verification, PoC generation, patch synthesis. CI/CD-native with SARIF, quality gates, and exit codes.

```sh
kuzushi scan <repo>
kuzushi scan <repo> --preset deep --verify --auto-patch
kuzushi scan <repo> --sarif report.sarif --fail-on-tp --quality-gate
kuzushi scan <repo> --resume
```

### Run (headless module tool)

Execute a single module tool without the interactive shell. Scriptable, composable with unix pipes.

```sh
kuzushi run sast:scan ./repo --json
kuzushi run triage:run fingerprint=abc123 --json
kuzushi run verify:finding fingerprint=abc123 --quiet
kuzushi run findings:list severity=critical,high --json
```

## Quick Start

Prereqs: Node 22+, and either an API key or Claude Code OAuth login.

```sh
# Install globally
npm install -g kuzushi

# Start the copilot shell (default)
kuzushi

# Or run a headless scan
kuzushi scan /path/to/your/repo

# With specific providers
export ANTHROPIC_API_KEY=sk-ant-...
kuzushi scan /path/to/your/repo

# With OpenAI, Google, Groq, Mistral, or 15+ other providers
kuzushi scan /path/to/repo --model openai:gpt-4o
kuzushi scan /path/to/repo --model google:gemini-2.0-flash
```

Kuzushi auto-downloads Opengrep if you don't have a scanner installed. Zero dependencies to manage.

## Quick Start (Contributors)

Two commands, deterministic, loud on failure:

```sh
git clone https://github.com/allsmog/Kuzushi.git
cd Kuzushi
pnpm setup      # verifies Node 22+, pins pnpm via corepack, checks externals, pnpm install
pnpm doctor     # optional: re-verify the environment at any time
```

Then:

```sh
pnpm dev --help       # run the CLI from source via tsx
pnpm test             # unit tests (vitest)
pnpm check:types      # typecheck src + benchmarks + perf (in parallel)
pnpm build            # incremental compile to dist/ — incremental, fast
pnpm build:clean      # wipe dist/ and rebuild from scratch (used by `pnpm prepack`)
```

Optional benchmark corpuses (clones 3rd-party vulnerable apps on demand):

```sh
pnpm setup:benchmarks list          # list available corpuses
pnpm setup:benchmarks govwa         # clone one
pnpm setup:benchmarks all           # clone everything
```

Prefer a containerised environment? Open the repo in VS Code / Codespaces and
"Reopen in Container" — the `.devcontainer/devcontainer.json` runs
`pnpm setup --strict` automatically and installs semgrep + python for you.

## Module System

Kuzushi's capabilities come from `CopilotModule`s that expose tools (for shell and run modes) and optionally pipeline tasks (for scan mode DAG execution), plus a set of Claude Code plugins that are wrapped by built-in modules. Three buckets:

### Built-in `CopilotModule`s (always available)

| Module | Category | What It Does | Key Tools |
|--------|----------|--------------|-----------|
| **sast** | offense | 40+ task SAST pipeline: Semgrep, CodeQL, agentic detectors, AI triage, verification, PoC, patch | `sast:scan` plus split-module tools `semgrep:scan`, `codeql:scan`, `agentic-sast:scan`, `triage:run`, `verify:finding`, `patch:finding`, `findings:list`, `context:build`, `threat-hunt:run`, `taint-iris:hunt` |
| **randori** | intel | PASTA threat modeling via the `@kuzushi/randori-plugin` — S1–S4 stages plus narrative synthesis, returning a `ThreatModelDocument` | `randori:pasta`, `randori:threat-model` |
| **vuln-scout** | offense | Whitebox pentest via the `@kuzushi/vuln-scout` plugin — agentic SAST + taint analysis returning normalized Findings | `vuln-scout:audit` |
| **tob** | offense | Trail of Bits skills audit via `@kuzushi/tob-skills` — fp-check, sharp-edges, insecure-defaults, static-analysis, variant-analysis, and more | `tob:audit`, `tob:skills` |
| **shinsa** | governance | ISO 27001 Annex A + NIST SP 800-53 Rev 5 compliance assessment via `shinsa-plugin` — evidence-backed controls mapped to file:line citations | `shinsa:scan`, `shinsa:quick-check`, `shinsa:nist-scan`, `shinsa:nist-quick-check`, `shinsa:frameworks` |
| **prompt-armor** | offense | LLM red teaming via `promptarmor-plugin` — 80+ attack plugins, 25+ mutation strategies, code-aware remediation (network commands require `authorized: true`) | `prompt-armor:scan`, `prompt-armor:analyze`, `prompt-armor:attack`, `prompt-armor:diff`, `prompt-armor:report`, `prompt-armor:config` |
| **variant** | offense | Lifts confirmed findings into portable signatures and hunts for variants across the repo (including vendored deps) | `variant:lift-pattern`, `variant:hunt` |
| **ndiff** | offense | CVE-diff-based n-day hunting and variant search against a target | `ndiff:fetch-cve`, `ndiff:search-patch-shape`, `ndiff:hunt-variants` |

Load with the shell or at startup: `kuzushi shell --load randori,vuln-scout,tob,shinsa,prompt-armor,variant,ndiff` (the bare id works — `builtin:` prefix is optional). Legacy ids `variant-hunter` / `n-day-diff-hunter` still resolve for backward compatibility.

Legacy `sast:<action>` aliases for split-module tools still resolve for backward compatibility, but new scripts and docs should use the canonical tool names shown above.

### External `CopilotModule` packages

| Package | Module ID | Usage |
|---------|-----------|-------|
| `@kuzushi/augur` | `augur` | Neuro-symbolic SAST (IRIS/ICLR 2025 LLM-driven CodeQL taint analysis). Load with `--load package:@kuzushi/augur`. |

### Referenced Claude Code plugins

These are dependencies consumed by the built-in wrappers above, not directly loadable as `CopilotModule`s. Attempting `--load package:@kuzushi/randori-plugin` (etc.) prints a pointer to the corresponding built-in module.

| Package | Wrapped by | Notes |
|---------|------------|-------|
| `@kuzushi/randori-plugin` | built-in `randori` | PASTA threat-modeling plugin (commands, agents, skills, hooks). |
| `@kuzushi/vuln-scout` | built-in `vuln-scout` | Whitebox pentest skill pack under `whitebox-pentest/`. |
| `@kuzushi/tob-skills` | built-in `tob` | Fork of trailofbits/skills — security-relevant plugins under `plugins/`. |
| `shinsa-plugin` | built-in `shinsa` | ISO 27001 + NIST 800-53 compliance assessment (4 commands, 10 assessor agents). |
| `promptarmor-plugin` | built-in `prompt-armor` | LLM red teaming (6 commands + MCP server under `server/`). |

### Roadmap (not yet shipped)

`blackbox`, `pwn`, `pentest`, `honeypot`, `yokai`, `revgraph` — referenced in the long-term vision but not currently implemented as loadable modules. See [VISION.md](VISION.md) for direction.

### Authoring your own module

```sh
kuzushi create-module my-module --template offense   # scaffolds manifest + starter tool + vitest
```

The scaffolder emits `module.manifest.json` (with `kuzushiSdkVersion` and `$schema`), a TypeScript starter using `defineModule`/`defineTool`, and a vitest skeleton using `kuzushi/testing`. Import surface:

```ts
import { defineModule, defineTool, ModuleLoadError } from "kuzushi/modules"
import type { CopilotModule, ToolExecutionContext, ToolResult } from "kuzushi/modules"
import { createMockToolContext, assertToolResult, expectModuleShape } from "kuzushi/testing"
```

Load a local build with `--load file:///abs/path/to/my-module`, a published package with `--load package:@scope/name`, or an MCP server with `--load mcp:<spec>`. The full authoring guide — manifest, `ToolExecutionContext` reference, capability probes, load errors, testing, MCP bridging — lives in **[docs/modules.md](docs/modules.md)**.

## The SAST Pipeline

The built-in `sast` module runs a 40+ task DAG pipeline:

```
  ┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌─────────┐     ┌──────────┐
  │  Task DAG    │────>│  AI Triage   │────>│ Verification │────>│  Patch  │────>│  Report  │
  │ Semgrep      │     │ Investigate  │     │ Construct    │     │ Generate │     │ TP only  │
  │ CodeQL       │     │ each finding │     │ PoC exploits │     │ & verify │     │ + export │
  │ 30+ tasks    │     │ with context │     │ (optional)   │     │ (opt-in) │     │ + stream │
  └─────────────┘     └──────────────┘     └──────────────┘     └─────────┘     └──────────┘
```

1. **Context gathering** — auto-detects tech stack, frameworks, auth patterns, ORMs, sanitization
2. **Code graph** — builds entry-point-to-sink graph via static analysis + LLM discovery
3. **Threat modeling** — Randori PASTA plugin: business objectives, technical scope, DFD decomposition, STRIDE threats with ATT&CK/CAPEC/OWASP mapping and 5-factor probabilistic scoring
4. **Threat-informed hunting** — adversarial Claude agents per DFD external entity, CTF-style hunting
5. **Task DAG execution** — Semgrep, CodeQL, agentic scanner, 15+ specialized detectors (SSRF, SQLi, XSS, command injection, XXE, deserialization, NoSQL injection, template injection, prototype pollution, race conditions, supply chain, GraphQL, secrets/crypto, auth logic, systems-level deep semantic analysis)
6. **Classifier funnel** — cheap single-token pre-filter removes ~80% noise before expensive triage
7. **Deduplication** — fingerprints and merges equivalent findings across scanners
8. **AI triage** — agent investigates each finding with source context, code graph, evidence chains, threat model, CWE-specific knowledge
9. **Variant analysis** — confirmed TPs trigger automatic search for similar patterns
10. **Verification** (optional) — constructs concrete PoC exploit payloads
11. **PoC harness** (optional) — produces runnable exploit scripts with execution feedback
12. **Dynamic analysis** (optional) — executes harnesses in Docker sandbox
13. **Auto-patch** (optional) — generates, validates, and re-verifies patches in disposable worktrees
14. **Report** — terminal display + SARIF, Markdown, JSON, CSV, JSONL; optional SSE streaming

For each finding, you get: **verdict** (tp/fp/by_design/needs_review), **confidence** (0-1), **rationale** with code references, **verification steps**, **fix suggestion**, optional **PoC exploit**, and **cost in USD**.

## CI Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  kuzushi:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npx kuzushi scan . --sarif results.sarif --junit results.xml --quality-gate --fail-on-tp
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

Exit codes: `0` clean, `1` findings (or task failures), `2` usage/config/auth, `3` unexpected crash. See `.github/workflows/kuzushi-reference.yml` for a reference workflow with SARIF upload, JUnit publish, and PR sticky comment.

#### `--ci` stream mode

`--ci` disables the Ink TUI and attaches a plain-text stream formatter
that writes one line per meaningful pipeline event. Log-renderer-friendly,
grep-friendly, and free of ANSI control codes:

```sh
kuzushi scan ./repo --ci --sarif results.sarif
```

```
[2026-04-20T14:20:01Z] scan: ./repo started
[2026-04-20T14:20:01Z] phase: (init) → scanning
[2026-04-20T14:20:12Z] stage: scan → done [8.3s]
[2026-04-20T14:20:12Z] stage: triage → active (15 findings)
[2026-04-20T14:20:45Z] finding: abc123def456 tp 92% $0.0041
[2026-04-20T14:21:20Z] summary: 4 tp · 10 fp · $0.87 · 1m 18s
```

Honoured from a TTY too — `kuzushi scan … --ci | tee run.log` works.

#### PR comments

`buildPrComment(summary, { repoName, runUrl })` (in `src/report-pr-comment.ts`)
renders a GitHub-markdown block suitable for `gh pr comment -F -`. Includes
verdict counts, exploitable badge, cost + duration, and a top-10 TP table
with severity emojis.

### Quality Gates

```sh
kuzushi scan <repo> --quality-gate         # fail CI on threshold violations
kuzushi scan <repo> --fail-on-tp           # fail if any high/critical TP is found
kuzushi scan <repo> --sarif results.sarif  # export SARIF for GitHub Code Scanning
kuzushi scan <repo> --ci                   # plain-text stream mode (no Ink)
```

## Scan Presets

```sh
kuzushi scan <repo> --preset fast        # semgrep only, no context/enrichment
kuzushi scan <repo> --preset standard    # semgrep + IRIS taint + secrets/crypto
kuzushi scan <repo> --preset deep        # + verification + threat modeling + systems hunt
kuzushi scan <repo> --preset reference   # + PoC + threat-informed hunting + frontier model
```

## Key Features

**Vendor-agnostic LLM runtime** — Anthropic, OpenAI, Google, Groq, Mistral, and 15+ providers. Swap models at runtime with `--model provider:modelId`. Runs airgapped with Ollama.

**Exploit verification** — constructs concrete PoC payloads (SQL injection strings, XSS vectors, etc.) that prove exploitability, not just theoretical possibility.

**IRIS-style taint analysis** — LLM-driven CodeQL taint analysis (ICLR 2025). LLM selects CWE classes, writes CodeQL queries dynamically, labels candidates, generates TaintTracking configs, iteratively refines on failure.

**Randori PASTA threat modeling** — 4-stage PASTA analysis (objectives, scope, DFD, STRIDE threats) via Claude Code plugin. Threat leads injected into all detector prompts. ATT&CK, CAPEC, OWASP mapping.

**Systems-level deep semantic hunt** — finds bugs that survive decades of review: integer overflow, sentinel collisions, signed/unsigned comparison, buffer overflows, use-after-free in protocol state machines, unsafe Rust blocks. LLM writes CodeQL queries using range analysis, not TaintTracking.

**Multi-strategy analysis** — 2-4 analytical approaches per vulnerability class with confidence boosting when strategies agree. Auto-generates Semgrep rules from confirmed findings.

**Auto-patch with closed-loop verification** — generates patches in disposable worktrees, validates, re-runs the scanner to confirm the vulnerability is gone.

**Crypto behavioral testing** — generates and executes behavioral test harnesses in Docker for crypto misuse: timing side-channels, ECB mode, weak hashes, weak PRNGs.

**Language-tuned detection** — auto-detects languages and frameworks, injects language-specific sinks, safe patterns, few-shot examples, anti-hallucination constraints. 8 ecosystems: C/C++, Java/Kotlin, Python, Go, JS/TS, Rust, PHP, Ruby.

**Resumable runs** — checkpoints to SQLite. `--resume` picks up where you left off.

**Interactive terminal UI** — React+Ink-powered live display with pipeline progress tree, spinners, trophy screen for confirmed exploits. REPL during scans (pause, skip, inspect). First-run setup wizard. Falls back to plain text in non-TTY. Built on a unified primitive library (`src/ui/primitives/`: `SelectList`, `TextInput`, `ConfirmDialog`, `Table`, `Breadcrumb`, `KeybindFooter`, `ExpandableSection`, `Divider`, `MultilineText`) with shared hooks (`src/ui/hooks/`: `useBoundedIndex`, `useFocusTrap`, `useTerminalSize`, `useCursorVisibility`, `useExpanded`, `useKeybindings`) for consistent focus, keyboard navigation, and resize handling.

**Incremental scanning** — skips re-triage for unchanged findings. Dependency-aware invalidation via import graph.

**Audit logging** — JSONL audit trail of every agent decision.

<details>
<summary><strong>All Scan Commands</strong></summary>

### Scan

```
kuzushi scan <repo>                        # scan with defaults
kuzushi scan <repo> --tasks codeql
kuzushi scan <repo> --tasks semgrep,codeql
kuzushi scan <repo> --severity ERROR
kuzushi scan <repo> --max 20
kuzushi scan <repo> --model anthropic:claude-sonnet-4-6
kuzushi scan <repo> --task-model triage=openai:gpt-4o
kuzushi scan <repo> --fresh
kuzushi scan <repo> --resume
```

### Verification & PoC

```
kuzushi scan <repo> --verify
kuzushi scan <repo> --verify --poc-harness
kuzushi scan <repo> --verify --poc-harness --dynamic-analysis
```

### Multi-Strategy & Code Graph

```
kuzushi scan <repo> --multi-strategy
kuzushi scan <repo> --multi-strategy-full
kuzushi scan <repo> --code-graph
```

### Auto-Patch

```
kuzushi scan <repo> --verify --auto-patch
kuzushi scan <repo> --auto-patch --patch-verify-depth full
```

### Diff-Aware & Crypto

```
kuzushi scan <repo> --taint-diff-base main
kuzushi scan <repo> --crypto-behavioral-test
```

### Output

```
kuzushi scan <repo> --output report.md
kuzushi scan <repo> --sarif results.sarif
kuzushi scan <repo> --json results.json
kuzushi scan <repo> --csv results.csv
kuzushi scan <repo> --junit results.xml
kuzushi scan <repo> --stream
kuzushi scan <repo> --audit-log
```

### Run History

```
kuzushi runs list                          # 50 most recent runs
kuzushi runs list --status interrupted     # only resumable runs
kuzushi runs show <runId> --costs          # details + cost breakdown
kuzushi runs show <runId> --json           # JSON output for tooling
```

### Run Mode

```
kuzushi run sast:scan ./repo --json
kuzushi run triage:run fingerprint=abc123 --json
kuzushi run verify:finding fingerprint=abc123 --quiet
kuzushi run findings:list severity=critical,high --json
```

### Patch

```
kuzushi patch <repo> --fingerprint <fp>
kuzushi patch <repo> --fingerprint <fp> --build-cmd "npm run build" --test-cmd "npm test"
```

### Config

```
kuzushi config get
kuzushi config set model anthropic:claude-sonnet-4-6
kuzushi config set tasks semgrep,agentic
kuzushi config validate --repo .
kuzushi config path
```

</details>

<details>
<summary><strong>Configuration Reference</strong></summary>

| Key | Default | Description |
| --- | --- | --- |
| `model` | `anthropic:claude-sonnet-4-6` | Default LLM model for all tasks and stages |
| `tasks` | `["semgrep"]` | Enabled task IDs, in execution order |
| `taskConfig` | `{ semgrep: {...}, triage: {...}, ... }` | Per-task config blocks keyed by task ID or stage ID |
| `severity` | `["ERROR","WARNING"]` | Semgrep severity filter |
| `excludePatterns` | `["test","tests","node_modules",...]` | Directories/globs to skip |
| `triageConcurrency` | `5` | Parallel LLM triage calls |
| `scanMode` | `"concurrent"` | Task execution mode |
| `verify` | `false` | Enable proof-of-exploitability verification |
| `pocHarness` | `false` | Enable PoC harness generation |
| `cryptoBehavioralTestEnabled` | `false` | Enable crypto behavioral testing |
| `codeGraphEnabled` | `true` | Enable LLM code graph |
| `multiStrategyMode` | `"off"` | Multi-strategy analysis (`off`, `adaptive`, `full`) |
| `autoPatchEnabled` | `false` | Enable auto-patch generation |
| `incrementalCache` | `true` | Enable incremental scanning |
| `auditLog` | `false` | Write JSONL audit files |

**Stage model overrides** via `taskConfig`:

| Key | Purpose |
| --- | --- |
| `taskConfig.triage.model` | Model for triage agents |
| `taskConfig.verify.model` | Model for verification agents |
| `taskConfig.poc-harness.model` | Model for PoC harness generation |

Global config: `~/.kuzushi/config.json`. Project overrides: `<repo>/.kuzushi/config.json`. CLI flags override config.

### Environment Variables

| Variable | Required | Description |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | When using `anthropic:*` models | Anthropic API key |
| `OPENAI_API_KEY` | When using `openai:*` models | OpenAI API key |
| `GEMINI_API_KEY` / `GOOGLE_API_KEY` | When using `google:*` models | Google API key |

</details>

<details>
<summary><strong>CodeQL Setup</strong></summary>

The `codeql` scanner requires the [CodeQL CLI](https://github.com/github/codeql-cli-binaries/releases) installed separately (not auto-downloaded).

```sh
# Via GitHub CLI (recommended):
gh extension install github/gh-codeql && gh codeql install-stub

# Or download directly from:
# https://github.com/github/codeql-cli-binaries/releases
```

CodeQL is opt-in. Enable it:

```sh
kuzushi scan <repo> --tasks codeql
kuzushi scan <repo> --tasks semgrep,codeql
kuzushi config set tasks semgrep,codeql
```

</details>

## Architecture

See [VISION.md](VISION.md) for the full architecture vision, module system design, workspace/knowledge graph, intel layer, governance model, and implementation roadmap.

### Terminal UI layer

The Ink React frontend lives in `src/ui/`:

| Path | Role |
| --- | --- |
| `src/ui/App.tsx` | Root Ink component; dispatches on `UIState.mode` (`preflight`, `running`, `summary`, `review`, `done`, `shell`). |
| `src/ui/state.ts` | `UIStore` — observer-pattern state + `useSyncExternalStore` binding. |
| `src/ui/render.ts` | Entry point; TTY detection and Ink mount / plain fallback. |
| `src/ui/plain-renderer.ts` | Non-TTY subscriber that prints delta-based updates. |
| `src/ui/tokens.ts` | Semantic color/typography tokens + `SPACING` / `COLUMN_WIDTHS` constants. |
| `src/ui/format.ts` | Terminal formatting utilities — progress bars, cost/duration, column padding, ANSI-aware truncation (`truncateEnd`, `truncateMiddle`, `padCell`, `visibleWidth`). |
| `src/ui/error-format.ts` | Ink-free error classification (`classifyError`, `formatError`, `suggestNextStep`) consumed by `ErrorCard`. |
| `src/ui/primitives/` | Reusable building blocks: `SelectList`, `TextInput`, `ConfirmDialog`, `Table`, `Breadcrumb`, `KeybindFooter`, `ExpandableSection`, `Divider`, `MultilineText`. |
| `src/ui/hooks/` | Behavioral hooks: `useBoundedIndex`, `useFocusTrap`, `useTerminalSize` (SIGWINCH-aware), `useCursorVisibility`, `useExpanded`, `useKeybindings`. |
| `src/ui/components/` | Feature components (pipeline, findings, setup wizard, copilot shell) composed from the primitives above. |

Styling discipline: components import from `tokens` (never `chalk` directly) and lay out with Ink `<Box>` flexbox properties (`flexDirection`, `justifyContent`, `gap`, `padding`, `margin`) rather than string-padding tricks.

## License

MIT
