<img src="kuzushi.png" alt="Kuzushi" width="200" />

# Kuzushi — Agentic SAST Orchestrator

Agentic SAST orchestrator. Runs security analysis tasks — scanners, AI triage, exploit verification, and more — as a dependency graph on an event-driven pipeline, then tells you what's actually dangerous.

## Quick Start

Prereqs: Node 22+, an API key for at least one supported LLM provider.

**With Anthropic (default):**

1. Get an API key at https://console.anthropic.com/
2. Set it: `export ANTHROPIC_API_KEY=sk-ant-...`
3. Scan: `npx kuzushi /path/to/your/repo`

**With OpenAI, Google, or any pi-ai-supported provider:**

1. Set the provider key: `export OPENAI_API_KEY=sk-...` (or `GEMINI_API_KEY`, etc.)
2. Scan: `npx kuzushi /path/to/repo --agent-runtime pi-ai --model openai:gpt-4o`

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
- **Newaza integration** — multi-pass CodeQL-based source/sink labeling pipeline with LLM-assisted classification, checkpoint gating, and deterministic library generation
- **Tracks cost** — per-finding triage, verification, and PoC harness costs are persisted and displayed in the summary
- **Event-driven pipeline** — pluggable message bus interface (in-process backend implemented; Redis/Google Pub/Sub/NATS adapters are scaffolded)
- **DAG-based task orchestration** — tasks declare dependencies, run in parallel groups, pass outputs downstream
- **Extensible agent framework** — `AgentTask` interface for adding new analysis types (threat modeling, binary analysis, etc.)
- **Persists results** in SQLite — resume interrupted scans, skip already-triaged findings
- **Resumable runs** — checkpoint pipeline state to SQLite; `--resume` picks up where a crashed or interrupted scan left off
- **Retry with backoff** — transient agent failures are retried automatically with exponential backoff
- **Audit logging** — optional JSONL audit trail of every agent decision for debugging and accountability
- **Markdown reports** — export a shareable `.md` report for CI pipelines and team review
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
8. **Report** — final results are persisted, rendered to terminal, and optionally exported as markdown.

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
kuzushi <repo> --model claude-opus-4-20250514  # use a different model
kuzushi <repo> --triage-model claude-opus-4-20250514  # separate model for triage
kuzushi <repo> --triage-max-turns 15  # triage agent turn budget
kuzushi <repo> --api-key sk-ant-... --base-url https://basecamp.stark.acme.com/
kuzushi <repo> --fresh                # clear prior results, re-triage everything
kuzushi <repo> --db ./my.sqlite3      # custom database path
kuzushi <repo> --resume               # resume the most recent interrupted run
kuzushi <repo> --resume <run-id>      # resume a specific run by ID
```

### Vendor-Agnostic Runtime

```
kuzushi <repo> --agent-runtime pi-ai --model openai:gpt-4o
kuzushi <repo> --agent-runtime pi-ai --model google:gemini-2.0-flash
kuzushi <repo> --agent-runtime pi-ai --model anthropic:claude-sonnet-4-20250514
kuzushi config set agentRuntimeBackend pi-ai
kuzushi config set model openai:gpt-4o
```

When `agentRuntimeBackend` is `pi-ai`, model strings use `provider:modelId` format. The pi-ai backend implements its own agentic tool-calling loop with local Read/Glob/Grep tools, structured output enforcement, budget tracking, and abort support. All consumer code (triage, verify, PoC harness, scanners) works unchanged — the `AgentRuntime` abstraction handles it.

### Verification

```
kuzushi <repo> --verify               # enable exploit verification for TPs
kuzushi <repo> --verify --verify-model claude-haiku-4-5-20251001  # cheaper model for verification
kuzushi <repo> --verify --verify-max-turns 20
kuzushi <repo> --verify --verify-concurrency 3
kuzushi <repo> --verify --verify-min-confidence 0.7  # skip low-confidence TPs
```

### PoC Harness Generation

```
kuzushi <repo> --verify --poc-harness                          # generate exploit scripts for verified findings
kuzushi <repo> --verify --poc-harness --poc-harness-model claude-haiku-4-5-20251001
kuzushi <repo> --verify --poc-harness --poc-harness-max-turns 25
kuzushi <repo> --verify --poc-harness --poc-harness-concurrency 2
```

### Output & Observability

```
kuzushi <repo> --output report.md     # export markdown report
kuzushi <repo> --sarif results.sarif  # export SARIF v2.1.0
kuzushi <repo> --audit-log            # write agent activity to .kuzushi/runs/{runId}/
kuzushi <repo> --no-context           # disable repo context gathering
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
kuzushi config set model claude-opus-4-20250514
kuzushi config set scanners semgrep,agentic
kuzushi config set scannerConfig.codeql.dbPath ./codeql-db
kuzushi config set scannerConfig.codeql.suite javascript-security-extended
kuzushi config set scannerConfig.semgrep.binary opengrep
kuzushi config set scannerConfig.semgrep.configFlag auto
kuzushi config set scannerConfig.agentic.model claude-sonnet-4-20250514
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
| `model` | `claude-sonnet-4-20250514` | LLM model for scanners and default triage model |
| `triageModel` | _(uses `model`)_ | Override model used by the triage agent |
| `triageMaxTurns` | `10` | Max agentic turns per triage call |
| `scanners` | `["semgrep"]` | Scanner plugins to run, in order |
| `severity` | `["ERROR","WARNING"]` | Semgrep severity filter |
| `excludePatterns` | `["test","tests","node_modules",...]` | Directories/globs to skip |
| `scannerConfig` | `{ semgrep: {...}, agentic: {...}, codeql: {...} }` | Per-scanner config blocks keyed by scanner id |
| `busBackend` | `"in-process"` | Message bus transport (`in-process`, future: `redis`, `google-pubsub`, `nats`) |
| `triageConcurrency` | `1` | Parallel LLM triage calls |
| `scanMode` | `"sequential"` | Scanner execution mode (`sequential` or `concurrent`) |
| `enabledTasks` | `[]` | Additional agent tasks beyond scanners |
| `agentRuntimeBackend` | `"claude-sdk"` | Agent runtime backend (`claude-sdk`, `pi-ai`, future: `acp`) |
| `verify` | `false` | Enable proof-of-exploitability verification |
| `verifyModel` | _(uses `triageModel` or `model`)_ | Override model for verification agent |
| `verifyMaxTurns` | `15` | Max turns for verification agent |
| `verifyConcurrency` | `1` | Parallel verification calls |
| `verifyVerdicts` | `["tp"]` | Which triage verdicts to verify |
| `verifyMinConfidence` | `0` | Minimum triage confidence to trigger verification (0-1) |
| `pocHarness` | `false` | Enable post-verification PoC harness generation (requires `--verify`) |
| `pocHarnessModel` | _(uses `triageModel` or `model`)_ | Override model for PoC harness agent |
| `pocHarnessMaxTurns` | `20` | Max turns for PoC harness agent |
| `pocHarnessConcurrency` | `1` | Parallel PoC harness generation calls |
| `enableContextGathering` | `true` | Run repo context analysis before triage |
| `auditLog` | `false` | Write agent activity to JSONL audit files |
| `reportOutput` | _(unset)_ | Write markdown report output to this path |
| `sarifOutput` | _(unset)_ | Write SARIF v2.1.0 output to this path |
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
  "enabledTasks": [],
  "scannerConfig": {
    "codeql": { "dbPath": "./codeql-db", "suite": "javascript-security-extended" },
    "semgrep": { "binary": "opengrep", "configFlag": "auto" },
    "agentic": { "model": "claude-sonnet-4-20250514", "maxFindings": 20 }
  }
}
```

### Environment Variables

| Variable | Required | Description |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | Yes (claude-sdk backend) | Anthropic API key — required when `agentRuntimeBackend` is `claude-sdk` |
| `OPENAI_API_KEY` | When using `openai:*` models | OpenAI API key for pi-ai backend |
| `GEMINI_API_KEY` / `GOOGLE_API_KEY` | When using `google:*` models | Google API key for pi-ai backend |

## Scanner Plugins

- `semgrep`: traditional SAST via Opengrep/Semgrep binary
- `codeql`: semantic dataflow/taint analysis via GitHub CodeQL CLI (SARIF output)
- `agentic`: AI-driven agentic scanner — LLM with read-only repo tools via any supported runtime
- `newaza`: multi-pass CodeQL source/sink labeling pipeline — runs preflight (database creation, candidate extraction), LLM-assisted labeling with human-in-the-loop checkpoint, and deterministic library/query generation + analysis

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

Unlike the Claude SDK backend (which has a built-in agentic loop), the pi-ai backend implements its own:

1. **Tool-calling loop** — call model, parse tool calls, execute tools, feed results back, repeat until stop or max turns
2. **Local tool implementations** — Read (file reader with line numbers), Glob (Node 22+ `globSync`), Grep (regex search across files)
3. **Structured output** — system prompt injection + post-hoc JSON extraction from fenced code blocks or raw text
4. **Safety controls** — max turns, budget enforcement, abort signal, permission gating via `canUseTool`

```sh
# Use with any supported provider:
OPENAI_API_KEY=... kuzushi <repo> --agent-runtime pi-ai --model openai:gpt-4o
GEMINI_API_KEY=... kuzushi <repo> --agent-runtime pi-ai --model google:gemini-2.0-flash
ANTHROPIC_API_KEY=... kuzushi <repo> --agent-runtime pi-ai --model anthropic:claude-sonnet-4-20250514
```

## Newaza Setup

The `newaza` scanner is a multi-pass CodeQL-based pipeline that uses LLM-assisted classification to label sources, sinks, sanitizers, and summaries. It requires:

1. **CodeQL CLI** — same requirement as the `codeql` scanner
2. **Python 3** — used by Newaza's scripts for query generation

Newaza's templates, references, and scripts are bundled as the [`@kuzushi/newaza`](https://www.npmjs.com/package/@kuzushi/newaza) npm package and installed automatically with `pnpm install`. No manual clone or `NEWAZA_PATH` setup needed.

```sh
kuzushi <repo> --scanners newaza
kuzushi <repo> --scanners newaza --approve-checkpoint  # auto-approve label review
kuzushi config set scannerConfig.newaza.labelingModel claude-sonnet-4-20250514
kuzushi config set scannerConfig.newaza.passes "[1,2,3,4,5,6]"
```

To override the bundled newaza assets (e.g., for local development), set `NEWAZA_PATH` or `scannerConfig.newaza.newazaPath`:

```sh
export NEWAZA_PATH=/path/to/local/newaza
kuzushi config set scannerConfig.newaza.newazaPath /path/to/local/newaza
```

Newaza runs in three DAG-ordered stages: **preflight** (database creation, candidate extraction), **label** (LLM classification with checkpoint gate), and **analyze** (library generation, query execution, finding extraction). A human-in-the-loop checkpoint pauses after labeling for review — use `--approve-checkpoint` to auto-approve in CI.

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

Use `--output report.md` to export a shareable markdown report.
Use `--sarif results.sarif` to export SARIF v2.1.0 for code scanning platforms.

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
pnpm test                             # run tests (214 tests across 31 files)
pnpm test:coverage                    # tests + coverage (70% threshold)
pnpm build                            # compile to dist/
```

Tests are organized by subsystem: `tests/bus/` for orchestrator, workers, and event bus tests, `tests/agents/` for DAG, task registry, and context-gatherer tests, and `tests/` for scanners, triage, verification, store, config, retry, and report.

## Troubleshooting

- **"Error: ANTHROPIC_API_KEY environment variable is required."**: Export your key — `export ANTHROPIC_API_KEY=sk-ant-...` (only required for `claude-sdk` backend; use `--agent-runtime pi-ai` with other providers)
- **"No findings from scanner. Code looks clean."**: Your code is clean, or try `--severity ERROR,WARNING,INFO` to include lower-severity rules
- **Scan interrupted**: Re-run the same command (already-triaged findings are skipped), or use `--resume` to continue from the exact checkpoint
- **Wrong model**: `kuzushi config set model claude-opus-4-20250514` or pass `--model` per-scan
- **Scanner download fails**: Install Opengrep or Semgrep manually, ensure it's on your PATH
- **High triage cost**: Use `--triage-model claude-haiku-4-5-20251001` for cheaper triage, or `--max 10` to limit findings
- **Verification too expensive**: Use `--verify-min-confidence 0.8` to only verify high-confidence TPs, or `--verify-model claude-haiku-4-5-20251001`
- **pi-ai model not found**: Ensure the model string uses `provider:modelId` format (e.g., `openai:gpt-4o`, not just `gpt-4o`)
- **Newaza checkpoint blocks CI**: Pass `--approve-checkpoint` to auto-approve label review in non-interactive environments

## License

MIT
