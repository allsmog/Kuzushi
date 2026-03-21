<img src="kuzushi.png" alt="Kuzushi" width="200" />

# Kuzushi — Agentic SAST Orchestrator

[![CI](https://github.com/allsmog/Kuzushi/actions/workflows/ci.yml/badge.svg)](https://github.com/allsmog/Kuzushi/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/kuzushi)](https://www.npmjs.com/package/kuzushi)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Agentic SAST orchestrator. Runs security analysis tasks — scanners, AI triage, exploit verification, and more — as a dependency graph on an event-driven pipeline, then tells you what's actually dangerous.

## Quick Start

Prereqs: Node 22+, an API key for at least one supported LLM provider.

**With Anthropic (default):**

1. Get an API key at https://console.anthropic.com/
2. Set it: `export ANTHROPIC_API_KEY=sk-ant-...`
3. Scan: `npx kuzushi /path/to/your/repo`

**With OpenAI, Google, or other providers:**

1. Set the provider key: `export OPENAI_API_KEY=sk-...` (or `GEMINI_API_KEY`, etc.)
2. Scan: `npx kuzushi /path/to/repo --model openai:gpt-4o`

That's it. Kuzushi auto-downloads Opengrep if you don't have a scanner installed. To add CodeQL, see [CodeQL Setup](#codeql-setup).

## What It Does

- **Runs Opengrep/Semgrep** with severity-ranked rule matching
- **Runs configurable scanners** (`semgrep`, `agentic`, `codeql`) in one orchestration flow
- **Gathers repo context** — auto-detects language, frameworks, auth patterns, ORMs, and sanitization libraries to enrich AI analysis
- **Scores and deduplicates** findings by severity, likelihood, impact, and subcategory — cross-scanner normalization merges equivalent findings from different scanners at the same location
- **AI-triages selected findings** — after dedupe/resume/max filters, agent investigates with repo tools, assigns tp/fp/needs_review with confidence and rationale
- **Verifies exploitability** — optional post-triage phase constructs concrete proof-of-concept payloads for true positives (e.g., SQL injection strings, XSS vectors)
- **Generates PoC harnesses** — optional post-verification phase produces runnable exploit scripts (TypeScript, Python, etc.) for verified-exploitable findings
- **Vendor-agnostic LLM runtime** — swap between Anthropic, OpenAI, Google, and 15+ other providers via the `pi-ai` backend with zero consumer-code changes
- **Taint analysis integration** — multi-pass CodeQL-based source/sink labeling pipeline with LLM-assisted classification and deterministic library generation
- **Structured evidence** — taintPath, proofState, and engineProvenance persist end-to-end from scan through store, resume, and all export formats (JSON, SARIF, Markdown, CSV, JSONL)
- **Multi-lens detection** — SSRF, NoSQL injection, and template injection tasks run parallel focused lenses (local sink + cross-function dataflow) and merge through dedup for broader coverage
- **Reachability-assisted ranking** — optional post-scan reachability check penalizes unreachable code before triage (enable with `callGraphAssistEnabled`)
- **Call-graph-assist** — enriches high-score findings with call-chain evidence from code intelligence without additional LLM calls
- **Pre-verification ranking** — verification candidates sorted by score, triage confidence, and evidence quality so highest-value findings verify first
- **Tracks cost** — per-finding triage, verification, and PoC harness costs are persisted and displayed in the summary
- **Extended metrics** — classifier drops, corroborated clusters, verification outcomes, and PoC generation outcomes flow from pipeline stats to reports
- **Event-driven pipeline** — pluggable message bus interface (in-process backend implemented; Redis/Google Pub/Sub/NATS adapters are scaffolded)
- **DAG-based task orchestration** — tasks declare dependencies, run in parallel groups, pass outputs downstream
- **Extensible agent framework** — `AgentTask` interface for adding new analysis types (threat modeling, binary analysis, etc.)
- **Persists results** in SQLite — resume interrupted scans, skip already-triaged findings
- **Resumable runs** — checkpoint pipeline state to SQLite; `--resume` picks up where a crashed or interrupted scan left off
- **Retry with backoff** — transient agent failures are retried automatically with exponential backoff
- **Audit logging** — optional JSONL audit trail of every agent decision for debugging and accountability
- **Multiple export formats** — markdown, SARIF v2.1.0, JSON, CSV, and JSONL reports for CI pipelines and team review
- **Prints a styled report** showing only what matters: true positives, needs-review items, and verified exploits with PoC payloads

## How It Works

Semgrep/Opengrep catches syntactic patterns but can't verify data flow or intent. LLMs can reason about code but hallucinate when scanning from scratch (95%+ false positive rate). Kuzushi combines both: SAST signal narrows the search space, LLM reasoning eliminates false positives. This hybrid approach matches human researcher agreement rates.

Under the hood, Kuzushi uses an event-driven architecture with a DAG-based task orchestrator:

1. **Context gathering** (optional, enabled by default) — the context-gatherer task analyzes the repo structure (package.json, go.mod, etc.) to identify the tech stack, frameworks, and security-relevant libraries.
2. **Pipeline starts** — the orchestrator resolves enabled tasks into a dependency graph and groups them into parallel stages.
3. **Scanners run** — scanner tasks (Semgrep, CodeQL, Agentic, etc.) execute concurrently within their stage, emitting findings as typed events on the message bus.
4. **Results gate downstream tasks** — the orchestrator waits for each stage to complete before starting dependent stages. Upstream outputs are forwarded to dependent tasks via `TaskContext`.
5. **Triage stage** — findings are deduplicated (fingerprint + cross-scanner location/CWE/rule normalization), ranked, and sent to an LLM for semantic verification with configurable concurrency. The repo context from step 1 enriches every triage prompt.
6. **Verification stage** (optional) — triaged findings that pass verification gates (`verifyVerdicts`, scanner-level `scannerConfig.<id>.verify`, and `verifyMinConfidence`) are sent to a verification agent that attempts to construct concrete PoC exploit payloads.
7. **PoC harness generation** (optional) — verified-exploitable findings are sent to a harness generator that produces runnable exploit scripts with syntax validation.
8. **Report** — final results are persisted, rendered to terminal, and optionally exported as markdown, SARIF, JSON, CSV, or JSONL.

All communication happens through a transport-agnostic `MessageBus` interface. The default in-process bus works out of the box; distributed adapters (Redis, Google Pub/Sub, NATS) are planned and scaffolded behind the same interface.

## Commands

### Scan (default)

```
kuzushi <repo>                        # scan with defaults
kuzushi <repo> --scanners codeql
kuzushi <repo> --scanners semgrep,codeql
kuzushi <repo> --scanners semgrep,agentic
kuzushi <repo> --severity ERROR       # only ERROR-level findings
kuzushi <repo> --max 20               # triage top 20 findings only
kuzushi <repo> --model anthropic:claude-sonnet-4-6  # use a different model
kuzushi <repo> --triage-model openai:gpt-4o  # separate model for triage
kuzushi <repo> --triage-max-turns 15  # triage agent turn budget
kuzushi <repo> --api-key sk-ant-... --base-url https://api.example.com/  # custom API endpoint
kuzushi <repo> --fresh                # clear prior results, re-triage everything
kuzushi <repo> --db ./my.sqlite3      # custom database path
kuzushi <repo> --resume               # resume the most recent interrupted run
kuzushi <repo> --resume <run-id>      # resume a specific run by ID
```

### Vendor-Agnostic Runtime

```
kuzushi <repo> --model openai:gpt-4o
kuzushi <repo> --model google:gemini-2.0-flash
kuzushi <repo> --model anthropic:claude-sonnet-4-6
kuzushi config set model openai:gpt-4o
```

Model strings use `provider:modelId` format. The default `pi-ai` backend implements its own agentic tool-calling loop with local Read/Glob/Grep tools, structured output enforcement, budget tracking, and abort support. All consumer code (triage, verify, PoC harness, scanners) works unchanged — the `AgentRuntime` abstraction handles it.

### Verification

```
kuzushi <repo> --verify               # enable exploit verification for TPs
kuzushi <repo> --verify --verify-model openai:gpt-4o-mini  # cheaper model for verification
kuzushi <repo> --verify --verify-max-turns 20
kuzushi <repo> --verify --verify-concurrency 3
kuzushi <repo> --verify --verify-min-confidence 0.7  # skip low-confidence TPs
```

### PoC Harness Generation

```
kuzushi <repo> --verify --poc-harness                          # generate exploit scripts for verified findings
kuzushi <repo> --verify --poc-harness --poc-harness-model openai:gpt-4o-mini
kuzushi <repo> --verify --poc-harness --poc-harness-max-turns 25
kuzushi <repo> --verify --poc-harness --poc-harness-concurrency 2
```

### Output & Observability

```
kuzushi <repo> --output report.md     # export markdown report
kuzushi <repo> --sarif results.sarif  # export SARIF v2.1.0
kuzushi <repo> --json results.json    # export JSON report
kuzushi <repo> --csv results.csv      # export CSV report
kuzushi <repo> --jsonl results.jsonl  # export JSONL report
kuzushi <repo> --audit-log            # write agent activity to .kuzushi/runs/{runId}/
kuzushi <repo> --no-context           # disable repo context gathering
```

### CI / Quality Gates

```
kuzushi <repo> --quality-gate         # fail CI on threshold violations
kuzushi <repo> --fail-on-tp           # fail if any high/critical TP is found
kuzushi <repo> --enabled-tasks taint-analysis-preflight,taint-analysis-label,taint-analysis-run  # enable specific tasks
```

### Retry

```
kuzushi <repo> --max-triage-retries 3       # retry failed triage calls (default: 2)
kuzushi <repo> --max-verify-retries 3       # retry failed verification calls (default: 2)
kuzushi <repo> --retry-backoff-ms 10000     # initial backoff delay (default: 5000)
```

### Config

```
kuzushi config get                    # show all config
kuzushi config get model              # show one key
kuzushi config set model anthropic:claude-sonnet-4-6
kuzushi config set scanners semgrep,agentic
kuzushi config set scannerConfig.codeql.dbPath ./codeql-db
kuzushi config set scannerConfig.codeql.suite javascript-security-extended
kuzushi config set scannerConfig.semgrep.binary opengrep
kuzushi config set scannerConfig.semgrep.configFlag auto
kuzushi config set scannerConfig.agentic.model anthropic:claude-sonnet-4-6
kuzushi config set scannerConfig.agentic.maxFindings 25
kuzushi config set severity ERROR,WARNING,INFO
kuzushi config set verify true
kuzushi config set verifyMinConfidence 0.7
kuzushi config set auditLog true
kuzushi config unset model            # reset to default
kuzushi config path                   # print config file location
```

Global config lives at `~/.kuzushi/config.json`. Optional project overrides can live at `<repo>/.kuzushi/config.json`. CLI flags override config values.

Security note: `agentRuntimeConfig.apiKey` is stored in plaintext in config files. Prefer `--api-key` for one-off runs or `ANTHROPIC_API_KEY` from your shell/secret manager.

## Configuration

| Key | Default | Description |
| --- | --- | --- |
| `model` | `anthropic:claude-sonnet-4-6` | LLM model for scanners and default triage model |
| `triageModel` | _(uses `model`)_ | Override model used by the triage agent |
| `triageBatchModel` | `anthropic:claude-haiku-4-5` | Model for batch triage (falls back to `triageModel`, then `model`) |
| `triageMaxTurns` | `null` (uses runtime default: `10`) | Max agentic turns per triage call |
| `scanners` | `["semgrep"]` | Scanner plugins to run, in order |
| `severity` | `["ERROR","WARNING"]` | Semgrep severity filter |
| `excludePatterns` | `["test","tests","node_modules",...]` | Directories/globs to skip |
| `scannerConfig` | `{ semgrep: {...}, agentic: {...}, codeql: {...} }` | Per-scanner config blocks keyed by scanner id |
| `busBackend` | `"in-process"` | Message bus transport (`in-process`, future: `redis`, `google-pubsub`, `nats`) |
| `triageConcurrency` | `5` | Parallel LLM triage calls |
| `scanMode` | `"concurrent"` | Scanner execution mode (`sequential` or `concurrent`) |
| `enabledTasks` | `["context-gatherer", "context-enricher", "secrets-crypto-detect", "code-config-detect", ...]` | Agent tasks to enable beyond scanners |
| `agentRuntimeBackend` | `"pi-ai"` | Agent runtime backend (`pi-ai`, future: `acp`) |
| `verify` | `false` | Enable proof-of-exploitability verification |
| `verifyModel` | _(uses `triageModel` or `model`)_ | Override model for verification agent |
| `verifyMaxTurns` | `15` | Max turns for verification agent |
| `verifyConcurrency` | `3` | Parallel verification calls |
| `verifyVerdicts` | `["tp"]` | Which triage verdicts to verify |
| `verifyMinConfidence` | `0` | Minimum triage confidence to trigger verification (0-1) |
| `pocHarness` | `false` | Enable post-verification PoC harness generation (requires `--verify`) |
| `pocHarnessModel` | _(uses `triageModel` or `model`)_ | Override model for PoC harness agent |
| `pocHarnessMaxTurns` | `20` | Max turns for PoC harness agent |
| `pocHarnessConcurrency` | `2` | Parallel PoC harness generation calls |
| `enableContextGathering` | `true` | Run repo context analysis before triage |
| `auditLog` | `false` | Write agent activity to JSONL audit files |
| `reportOutput` | _(unset)_ | Write markdown report output to this path |
| `sarifOutput` | _(unset)_ | Write SARIF v2.1.0 output to this path |
| `jsonOutput` | _(unset)_ | Write JSON report to this path |
| `csvOutput` | _(unset)_ | Write CSV report to this path |
| `jsonlOutput` | _(unset)_ | Write JSONL report to this path |
| `maxTriageRetries` | `2` | Retry failed triage calls |
| `maxVerifyRetries` | `2` | Retry failed verification calls |
| `maxPocHarnessRetries` | `2` | Retry failed PoC harness generation calls |
| `retryBackoffMs` | `5000` | Initial retry backoff delay in ms |
| `retryBackoffMultiplier` | `2` | Exponential backoff multiplier |

Example:

```json
{
  "scanners": ["semgrep", "codeql", "agentic"],
  "scanMode": "concurrent",
  "triageConcurrency": 3,
  "verify": true,
  "verifyMinConfidence": 0.7,
  "auditLog": true,
  "enabledTasks": ["context-gatherer", "context-enricher", "secrets-crypto-detect", "code-config-detect"],
  "scannerConfig": {
    "codeql": { "dbPath": "./codeql-db", "suite": "javascript-security-extended" },
    "semgrep": { "binary": "opengrep", "configFlag": "auto" },
    "agentic": { "model": "anthropic:claude-sonnet-4-6", "maxFindings": 20 }
  }
}
```

### Environment Variables

| Variable | Required | Description |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | When using `anthropic:*` models | Anthropic API key for pi-ai backend |
| `OPENAI_API_KEY` | When using `openai:*` models | OpenAI API key for pi-ai backend |
| `GEMINI_API_KEY` / `GOOGLE_API_KEY` | When using `google:*` models | Google API key for pi-ai backend |

## Scanner Plugins

- `semgrep`: traditional SAST via Opengrep/Semgrep binary
- `codeql`: semantic dataflow/taint analysis via GitHub CodeQL CLI (SARIF output)
- `agentic`: AI-driven agentic scanner — LLM with read-only repo tools via any supported runtime
- `taint-analysis`: multi-pass CodeQL source/sink labeling pipeline — runs preflight (database creation, candidate extraction), LLM-assisted labeling, and deterministic library/query generation + analysis

## Semgrep Resolution

For the `semgrep` plugin, Kuzushi finds a scanner binary in this order:

1. `opengrep` on your PATH
2. `semgrep` on your PATH
3. Previously downloaded binary at `~/.kuzushi/bin/opengrep`
4. Auto-downloads Opengrep from GitHub releases (~40 MB, cached for future runs)

No pip, no brew, no manual install needed.

## CodeQL Setup

The `codeql` scanner requires the [CodeQL CLI](https://github.com/github/codeql-cli-binaries/releases) to be installed separately. Unlike Semgrep, it is **not auto-downloaded** (the CLI is ~500 MB and requires accepting GitHub's license).

Install it:

```sh
# Via GitHub CLI (recommended):
gh extension install github/gh-codeql && gh codeql install-stub

# Or download directly from:
# https://github.com/github/codeql-cli-binaries/releases
```

Kuzushi finds the CodeQL binary in this order:

1. `codeql` on your PATH
2. Previously placed binary at `~/.kuzushi/bin/codeql`
3. Fails with install instructions if not found

CodeQL is **opt-in** — the default scanner list is `["semgrep"]`. To enable it:

```sh
kuzushi <repo> --scanners codeql              # CodeQL only
kuzushi <repo> --scanners semgrep,codeql      # both scanners
kuzushi config set scanners semgrep,codeql    # persist as default
```

CodeQL builds a database from your source code before running queries. You can skip this step by pointing to a pre-built database:

```sh
kuzushi config set scannerConfig.codeql.dbPath ./codeql-db
```

## Pi-AI Runtime

The `pi-ai` backend uses `@mariozechner/pi-ai` to provide vendor-agnostic LLM access. It supports 15+ providers (Anthropic, OpenAI, Google, Groq, Mistral, etc.) through a single interface.

Kuzushi implements an internal agentic loop on top of pi-ai:

1. **Tool-calling loop** — call model, parse tool calls, execute tools, feed results back, repeat until stop or max turns
2. **Local tool implementations** — Read (file reader with line numbers), Glob (Node 22+ `globSync`), Grep (regex search across files)
3. **Structured output** — system prompt injection + post-hoc JSON extraction from fenced code blocks or raw text
4. **Safety controls** — max turns, budget enforcement, abort signal, permission gating via `canUseTool`

```sh
# Use with any supported provider:
OPENAI_API_KEY=... kuzushi <repo> --model openai:gpt-4o
GEMINI_API_KEY=... kuzushi <repo> --model google:gemini-2.0-flash
ANTHROPIC_API_KEY=... kuzushi <repo> --model anthropic:claude-sonnet-4-6
```

## Taint Analysis Setup

The `taint-analysis` scanner is a multi-pass CodeQL-based pipeline that uses LLM-assisted classification to label sources, sinks, sanitizers, and summaries. It requires:

1. **CodeQL CLI** — same requirement as the `codeql` scanner
2. **Python 3** — used by taint analysis scripts for query generation

Taint analysis templates, references, and scripts are bundled as the [`@kuzushi/augur`](https://www.npmjs.com/package/@kuzushi/augur) npm package and installed automatically with `pnpm install`. No manual clone or `TAINT_ANALYSIS_PATH` setup needed.

```sh
kuzushi <repo> --scanners taint-analysis
kuzushi config set scannerConfig["taint-analysis"].labelingModel anthropic:claude-sonnet-4-6
kuzushi config set scannerConfig["taint-analysis"].passes "[1,2,3,4,5,6]"
```

To override the bundled taint-analysis assets (e.g., for local development), set `TAINT_ANALYSIS_PATH` or `scannerConfig["taint-analysis"].taintAnalysisPath`:

```sh
export TAINT_ANALYSIS_PATH=/path/to/local/taint-analysis
kuzushi config set scannerConfig["taint-analysis"].taintAnalysisPath /path/to/local/taint-analysis
```

Taint analysis runs in three DAG-ordered stages: **preflight** (database creation, candidate extraction), **label** (LLM classification), and **analyze** (library generation, query execution, finding extraction).

### Taint Analysis TI + Artifact Outputs

Each taint analysis run emits interoperability artifacts under the workspace (`scannerConfig["taint-analysis"].workspaceDir`, default `./iris`) and run directory:

- `iris/exploration/TI_PRIOR.md` and `iris/exploration/ti_prior.json` — live TI prior (CISA KEV + NVD) with degraded-mode metadata when fetches fail
- `iris/labels/TAINT_MODEL.json` — per-CWE taint model (`sources/sinks/sanitizers/propagators`) with TI-weighted basis
- `iris/results/findings.raw.json` — normalized raw findings aggregate from taint analysis pass SARIF outputs
- `.kuzushi/runs/<runId>/findings.triaged.json` — triaged findings export including optional taint analysis source/sink triage details

Relevant `scannerConfig["taint-analysis"]` options:

- `tiMode`: `"live-required"` (default)
- `tiFailurePolicy`: `"continue_without_ti"` (default)
- `tiTimeoutMs`: live TI fetch timeout in milliseconds
- `refinementEnabled`: enable one post-triage refinement loop (default `false`)
- `refinementIterations`: max refinement passes when enabled (default `1`)
- `refinementDeltaOnly`: triage only changed findings after refinement (default `true`)
- `refinementModel`: optional model override for refinement stage wiring

## Output

Results are stored in SQLite at `<repo>/.kuzushi/findings.sqlite3`. Each finding includes:

- **verdict**: `tp` (true positive), `fp` (false positive), or `needs_review`
- **confidence**: 0.0-1.0
- **rationale**: why the LLM reached that verdict, referencing specific code
- **verification_steps**: 2-6 steps a human reviewer can follow
- **fix_patch**: suggested fix (when applicable)
- **exploitability** (with `--verify`): whether a concrete exploit was constructed, PoC payload, attack vector, and preconditions
- **cost**: per-finding triage and verification cost in USD

The terminal report shows true positives first, then needs-review items. False positives are counted but hidden. Verified exploitable findings are highlighted with their PoC payloads.

Export options: `--output report.md` (markdown), `--sarif results.sarif` (SARIF v2.1.0), `--json results.json`, `--csv results.csv`, `--jsonl results.jsonl`.

## SARIF / GitHub Code Scanning

Kuzushi can emit SARIF v2.1.0 directly. GitHub Code Scanning ingests SARIF and creates inline annotations.

```
kuzushi <repo> --sarif results.sarif

gh api \
  -X POST \
  repos/OWNER/REPO/code-scanning/sarifs \
  -f commit_sha="$(git rev-parse HEAD)" \
  -f ref="refs/heads/$(git rev-parse --abbrev-ref HEAD)" \
  -f sarif="$(gzip -c results.sarif | base64 | tr -d '\n')"
```

## Resume Support

Kuzushi fingerprints every finding (content-based SHA-256 that survives line shifts). Re-running a scan skips already-triaged findings automatically. Use `--fresh` to start over.

For interrupted runs, use `--resume` to pick up where the pipeline left off. Kuzushi checkpoints pipeline state (scan findings, triage progress, verification progress) to SQLite. On resume, completed phases are skipped and only remaining work is executed.

```
kuzushi <repo> --resume               # resume most recent interrupted run
kuzushi <repo> --resume abc-123       # resume a specific run by ID
```

## Audit Logging

With `--audit-log`, Kuzushi writes a structured audit trail to `.kuzushi/runs/{runId}/`:

- `triage.jsonl` — every tool call, reasoning step, and verdict from triage agents
- `verify.jsonl` — same for verification agents
- `run.json` — run config and scan options
- `stats.json` — final pipeline statistics

Use this to debug verdicts, review agent reasoning, or build compliance records.

## Architecture

Kuzushi is built on three core abstractions:

**Message Bus** — A transport-agnostic `MessageBus` interface (`publish`, `subscribe`, `waitFor`) that decouples pipeline stages. The default in-process implementation uses an `EventEmitter`; the interface supports swapping in Redis, Google Pub/Sub, or NATS for distributed setups.

**AgentTask + DAG** — Every unit of work (context gatherer, scanner, future threat modeler, etc.) implements the `AgentTask` interface: an `id`, `dependsOn` list, `outputKind`, and a `run()` method. The `TaskRegistry` resolves enabled tasks into a DAG, groups them into parallel stages, detects cycles, and hands execution to the `PipelineOrchestrator`. Upstream task outputs are forwarded to dependents automatically.

**Pipeline Phases** — After the DAG completes, the orchestrator drives three sequential phases: triage (classify findings), verification (construct PoC exploits), and report (display results). Each phase has its own concurrency control, cost tracking, and checkpoint support.

Existing `ScannerPlugin` implementations (Semgrep, Agentic) are adapted into `AgentTask` via `adaptScannerPlugin()`, so the scanner plugin API remains stable.

See [AGENTS.md](AGENTS.md) for the full developer guide on adding new agent tasks.

## Development

```
pnpm install                          # install deps
pnpm dev -- /path/to/repo             # run in dev mode
pnpm typecheck                        # type check
pnpm test                             # run tests
pnpm test:coverage                    # tests + coverage (70% threshold)
pnpm build                            # compile to dist/
```

Tests are organized by subsystem: `tests/bus/` for orchestrator, workers, and event bus tests, `tests/agents/` for DAG, task registry, and context-gatherer tests, and `tests/` for scanners, triage, verification, store, config, retry, and report.

## Troubleshooting

- **"Error: missing API credentials for selected model provider(s)."**: Set the provider env var(s) for your selected models (for example `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GEMINI_API_KEY`)
- **"No findings from scanner. Code looks clean."**: Your code is clean, or try `--severity ERROR,WARNING,INFO` to include lower-severity rules
- **Scan interrupted**: Re-run the same command (already-triaged findings are skipped), or use `--resume` to continue from the exact checkpoint
- **Wrong model**: `kuzushi config set model anthropic:claude-sonnet-4-6` or pass `--model` per-scan
- **Scanner download fails**: Install Opengrep or Semgrep manually, ensure it's on your PATH
- **High triage cost**: Use `--triage-model openai:gpt-4o-mini` for cheaper triage, or `--max 10` to limit findings
- **Verification too expensive**: Use `--verify-min-confidence 0.8` to only verify high-confidence TPs, or `--verify-model openai:gpt-4o-mini`
- **pi-ai model not found**: Ensure the model string uses `provider:modelId` format (e.g., `openai:gpt-4o`, not just `gpt-4o`)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

[MIT](LICENSE)
