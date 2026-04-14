<img src="kuzushi.png" alt="Kuzushi" width="200" />

# Kuzushi — AI Security Scanner That Only Shows You Real Vulnerabilities

[![CI](https://github.com/allsmog/Kuzushi/actions/workflows/ci.yml/badge.svg)](https://github.com/allsmog/Kuzushi/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/kuzushi)](https://www.npmjs.com/package/kuzushi)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[kuzushi.dev](https://kuzushi.dev)

SAST tools cry wolf. Semgrep finds 500 issues in your codebase. 480 of them are false positives. You spend hours triaging a wall of noise and still miss the real vulnerability on line 247.

Kuzushi runs the same scanners, then sends an AI agent to investigate each finding — reading the actual code, tracing data flow, checking for sanitization. It tells you which findings are real, which are noise, and optionally proves exploitability by constructing a working PoC.

```sh
npx kuzushi /path/to/your/repo
```

No config files. Just point it at a repo.

<!-- TODO: Add terminal recording / asciinema GIF here -->

## Quick Start

Prereqs: Node 22+, and either an API key or Claude Code OAuth login.

```sh
# Install globally (recommended — get upgrades with npm update -g kuzushi)
npm install -g kuzushi

# Or run without installing
npx kuzushi /path/to/your/repo
```

```sh
# With Claude Code OAuth (no API key needed — uses your Claude login)
kuzushi /path/to/your/repo

# With Anthropic API key
export ANTHROPIC_API_KEY=sk-ant-...
kuzushi /path/to/your/repo

# With OpenAI
export OPENAI_API_KEY=sk-...
kuzushi /path/to/repo --model openai:gpt-4o

# With Google, Groq, Mistral, or 15+ other providers
kuzushi /path/to/repo --model google:gemini-2.0-flash
```

Kuzushi auto-downloads Opengrep if you don't have a scanner installed. Zero dependencies to manage.

## The Problem

**SAST scanners alone** have high recall but terrible precision — they flag everything that *could* be a vulnerability, drowning you in false positives. Teams burn hours triaging, develop alert fatigue, and eventually stop looking.

**LLMs alone** can reason about code but hallucinate when scanning from scratch — 95%+ false positive rate when you ask "find vulnerabilities in this repo."

**Kuzushi combines both.** SAST signal narrows the search space. AI reasoning eliminates false positives. The result: near-human researcher agreement rates on vulnerability classification.

## What You Get

For each finding, Kuzushi produces:

- **Verdict** — `true_positive`, `false_positive`, `by_design`, or `needs_review`
- **Confidence** — 0.0 to 1.0
- **Rationale** — why the agent reached that verdict, referencing specific code lines
- **Verification steps** — 2-6 actionable steps a human reviewer can follow
- **Fix suggestion** — suggested patch when applicable
- **PoC exploit** (with `--verify`) — a concrete proof-of-concept payload proving the vulnerability is exploitable
- **Cost** — per-finding triage and verification cost in USD

The terminal report shows true positives first, then needs-review items. False positives and by-design findings are counted but deprioritized. You only see what matters.

## How It Works

```
  ┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌─────────┐     ┌──────────┐
  │  Task DAG    │────▶│  AI Triage   │────▶│ Verification │────▶│  Patch  │────▶│  Report  │
  │ Semgrep      │     │ Investigate  │     │ Construct    │     │ Generate │     │ TP only  │
  │ CodeQL       │     │ each finding │     │ PoC exploits │     │ & verify │     │ + export │
  │ 15+ tasks    │     │ with context │     │ (optional)   │     │ (opt-in) │     │ + stream │
  └─────────────┘     └──────────────┘     └──────────────┘     └─────────┘     └──────────┘
```

1. **Context gathering** — auto-detects your tech stack, frameworks, auth patterns, ORMs, and sanitization libraries
2. **Code graph** — builds a persistent entry-point-to-sink graph via static analysis + LLM discovery mode. For HTTP services, traces pre-identified routes. For CLI tools, daemons, and non-HTTP projects, the LLM identifies entry points itself (main functions, socket listeners, gRPC servers, CLI handlers) and traces security-relevant call/data-flow paths
3. **Threat modeling** — Randori PASTA plugin (shipped as `@kuzushi/randori-plugin`) performs 4-stage threat analysis: business objectives, technical scope, DFD decomposition, and STRIDE threat scenarios with ATT&CK/CAPEC/OWASP mapping and 5-factor probabilistic scoring. All threat leads are injected into every detector's prompts.
4. **Threat-informed hunting** — spawns one adversarial Claude agent per DFD external entity (users, services, attackers) to CTF-style hunt for vulnerabilities from each actor's perspective
5. **Task DAG execution** — runs enabled tasks as a dependency-aware DAG: Semgrep, CodeQL, agentic scanner, and 15+ specialized detectors (SSRF, SQLi, XSS, command injection, XXE, deserialization, NoSQL injection, template injection, prototype pollution, race conditions, supply chain, GraphQL, secrets/crypto, auth logic, sharp edges, systems-level deep semantic analysis); multi-strategy mode runs 2-4 analytical approaches per vuln class
4. **Classifier funnel** — cheap single-token pre-filter removes ~80% of noise before expensive triage
5. **Deduplication** — fingerprints and merges equivalent findings across scanners
6. **Incremental skip** — findings already triaged in previous runs are skipped automatically
7. **AI triage** — an agent investigates each finding with pre-loaded source context, code graph paths, evidence chains, threat model context, and CWE-specific knowledge modules. Threat model output from Randori PASTA is injected into triage prompts so the agent can distinguish design choices (`by_design`) from real vulnerabilities (`tp`). Batch-dropped findings auto-escalate to individual triage
8. **Variant analysis** — confirmed TPs trigger automatic search for similar patterns across the codebase
9. **Verification** (optional) — constructs concrete PoC exploit payloads for true positives
10. **PoC harness generation** (optional) — produces runnable exploit scripts with iterative execution feedback
11. **Dynamic analysis** (optional) — executes harnesses in Docker sandbox to confirm exploitability
12. **Auto-patch** (optional) — generates, validates, and re-verifies patches in disposable git worktrees
13. **Report** — terminal display + export to SARIF, Markdown, JSON, CSV, or JSONL; optional SSE live streaming

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
      - run: npx kuzushi . --sarif results.sarif --quality-gate --fail-on-tp
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### Quality Gates

```sh
kuzushi <repo> --quality-gate         # fail CI on threshold violations
kuzushi <repo> --fail-on-tp           # fail if any high/critical TP is found
kuzushi <repo> --sarif results.sarif  # export SARIF for GitHub Code Scanning
```

## Key Features

**Vendor-agnostic LLM runtime** — works with Anthropic, OpenAI, Google, Groq, Mistral, and 15+ other providers. Swap models at runtime with `--model provider:modelId`. Use cheaper models for triage, premium models for verification.

**Exploit verification** — goes beyond classification. Constructs concrete PoC payloads (SQL injection strings, XSS vectors, etc.) that prove a finding is exploitable, not just theoretically possible.

**Crypto behavioral testing** — generates and executes behavioral test harnesses in a Docker sandbox for crypto misuse findings. Detects timing side-channels, ECB mode, weak hashes, weak PRNGs, and more.

**IRIS-style taint analysis** — LLM-driven CodeQL taint analysis inspired by the IRIS paper (ICLR 2025). An LLM selects relevant CWE classes for the project, writes CodeQL extraction queries dynamically (language-agnostic, framework-agnostic), labels candidates, generates TaintTracking configurations, and iteratively refines queries when compilation fails. Structured taint paths (source-to-sink step data) are persisted to the findings DB for downstream verification and reporting. No templates, no hardcoded framework detection.

**Randori PASTA threat modeling** — ships `@kuzushi/randori-plugin` as a dependency. Runs 4-stage PASTA analysis (objectives, scope, DFD decomposition, STRIDE threats) via Claude Code plugin. Threat leads are injected into all detector prompts for threat-informed scanning. ATT&CK, CAPEC, and OWASP mapping included.

**Threat-informed hunting** — spawns adversarial Claude agents for each DFD external entity identified by the threat model. Each agent explores the codebase as that actor (end user, admin, external service, LLM agent) looking for exploitable paths. Findings are deduplicated and fed into triage/verification.

**Systems-level deep semantic hunt** — LLM-driven analysis pipeline for finding the class of bugs that survive decades of code review and fuzzing: integer overflow/wraparound (CWE-190), sentinel value collisions (CWE-787), signed/unsigned comparison bugs (CWE-681), buffer overflows exploitable via missing stack canaries (CWE-693), use-after-free in protocol state machines (CWE-416), and unsafe block violations in Rust (CWE-704). The LLM writes and runs CodeQL queries using range analysis, loop induction analysis, and type predicates — NOT TaintTracking — to find bugs that source-to-sink taint flows cannot express. Activates automatically for C, C++, Rust, and Go codebases. The `reference` preset routes a frontier model to this task for maximum depth.

**Auto rule generation** — verified exploitable findings automatically generate custom Semgrep rules. Rules are persisted to `.kuzushi/custom-rules/` and auto-loaded on subsequent scans, creating a feedback loop where the scanner gets smarter over time. Rules are validated against the original finding and removed if they don't match.

**Diff-aware taint analysis** — narrows analysis to files changed since a base branch. Run `--taint-diff-base main` in CI to only analyze what's new in the PR.

**Resumable runs** — checkpoints pipeline state to SQLite. Interrupted scan? `--resume` picks up exactly where it left off.

**Patch synthesis** — `kuzushi patch <repo> --fingerprint <fp>` generates and validates security patches in disposable git worktrees without touching your working copy.

**Language-tuned detection** — every detector adapts its prompts to your repo's actual tech stack. Kuzushi auto-detects languages and frameworks, then injects language-specific sinks, safe patterns, few-shot examples, investigation hints (grep patterns, key files), framework-aware guidance, and anti-hallucination constraints. A Python repo gets `subprocess.run` shell=True analysis and Django/Flask/FastAPI-specific advice. A C/C++ repo gets buffer-size #define resolution, signed/unsigned mismatch detection, and memory-safety few-shots. A Java repo gets SpEL injection, XXE factory configuration, and Spring Security guidance. 8 language ecosystems covered: C/C++, Java/Kotlin, Python, Go, JavaScript/TypeScript, Rust, PHP, Ruby — each with per-vulnerability-class depth. Polyglot repos get all relevant languages composed together.

**15+ specialized detectors** — dedicated detection tasks for command injection, XXE, insecure deserialization, SSRF, NoSQL injection, template injection, prototype pollution, race conditions, supply chain, GraphQL security, secrets/crypto, code config, auth logic, sharp edges, crypto behavioral testing, and systems-level deep semantic analysis (integer overflow, buffer overflow, sentinel collision, use-after-free, unsafe blocks). Each has vulnerability-class-specific prompts, anti-hallucination constraints, and multi-lens analysis. All detectors receive threat model leads for threat-informed scanning.

**Classifier funnel** — single-token LLM pre-filter using a cheap model removes ~80% of false positives before expensive triage, cutting per-scan cost dramatically.

**Source pre-read** — triage agents receive the flagged source file pre-loaded (50 lines surrounding the finding), eliminating cold-start tool calls and improving reasoning accuracy.

**LLM code graph** — builds a persistent code graph tracing entry points through middleware, controllers, services, and data-access layers. Static skeleton from import analysis + LLM-assisted gap-filling for dynamic dispatch, DI, and callback patterns. Discovery mode: when no HTTP routes are detected, the LLM identifies entry points itself (main functions, socket listeners, gRPC servers, CLI handlers) and traces security-relevant paths with threat model context. Feeds graph context into triage for better reasoning.

**Multi-strategy analysis** — runs 2-4 different analytical approaches per vulnerability class (syntactic pattern matching, dataflow tracing, first-principles reasoning, execution-based proof) and merges results with confidence boosting when strategies agree. Auto-generates reusable Semgrep rules from confirmed multi-strategy findings.

**13 CWE knowledge modules** — domain-specific knowledge for SQL injection, XSS, SSRF, command injection, path traversal, auth bypass, deserialization, race conditions, crypto, XXE, file upload, IDOR, and NoSQL injection — including dangerous patterns, safe patterns, bypass techniques, and fix examples.

**Incremental scanning** — skips re-triage for unchanged findings across runs. Tracks the last scanned commit, computes file diffs, and expands the rescan scope with dependency-aware invalidation via the import graph.

**Auto-patch with closed-loop verification** — after confirming a vulnerability, automatically generates a patch in a disposable git worktree, validates it (apply, build, test), then re-runs the scanner on the patched code to confirm the vulnerability is gone.

**Live streaming** — SSE server streams pipeline events in real-time (`--stream`). Connect with `curl`, `EventSource`, or any SSE client to watch findings appear as they're triaged.

**Audit logging** — optional JSONL audit trail of every agent decision for debugging, accountability, and compliance records.

## Scan Presets

Presets configure the pipeline for different cost/depth tradeoffs. CLI flags override preset values.

```sh
kuzushi <repo> --preset fast        # semgrep only, no context/enrichment/variant analysis
kuzushi <repo> --preset standard    # semgrep + IRIS taint + secrets/crypto detection
kuzushi <repo> --preset deep        # standard + verification + threat modeling + systems-level hunt
kuzushi <repo> --preset reference   # verification + PoC generation + threat-informed hunting
                                    # + deep semantic hunt with a frontier model
```

The `reference` preset uses a cost-smart model tiering strategy: a standard model handles bulk scanning and triage, while a frontier model is used surgically for the systems-hunt and threat-hunt stages — where stronger adversarial reasoning has the highest ROI for zero-day discovery. Per-task model overrides keep costs controlled.

## Tasks

Every stage of the pipeline is an **AgentTask** — a composable unit with explicit dependencies that the orchestrator runs as a DAG. Tasks are selected via `--tasks` or `config.tasks`, and per-task config (including model overrides) lives in `config.taskConfig`.

| Task ID | Description | Auto-download |
|---------|-------------|---------------|
| `semgrep` (default) | Traditional SAST via Opengrep/Semgrep | Yes |
| `codeql` | Semantic dataflow/taint analysis via GitHub CodeQL CLI | No (opt-in) |
| `agentic` | AI-driven scanner — LLM with read-only repo tools | N/A |
| `taint-cwe-select` / `taint-iris` | IRIS-style LLM-driven CodeQL taint analysis — dynamic CWE selection, LLM-generated queries, iterative refinement | No (opt-in) |
| `systems-hunt` | Deep semantic analysis for C/C++/Rust/Go — LLM-driven CodeQL range analysis, loop induction, missing mitigations | No (opt-in) |
| `secrets-crypto-detect` | Secrets, API keys, and cryptographic misuse detection | N/A |
| `code-config-detect` | Security-relevant code and configuration issues | N/A |
| `threat-model-randori` | PASTA threat modeling with STRIDE analysis | N/A |
| `threat-hunt` | Adversarial CTF-style hunting per DFD entity | N/A |
| `context-gatherer` | Auto-detects tech stack, frameworks, auth patterns | N/A |
| `context-enricher` | Deep context enrichment (middleware, trust boundaries) | N/A |

```sh
kuzushi <repo> --tasks semgrep,codeql               # run specific tasks
kuzushi <repo> --tasks agentic                       # AI-only scan
kuzushi <repo> --task-model threat-hunt=anthropic:claude-opus-4-6  # per-task model override
```

---

<details>
<summary><strong>All Commands</strong></summary>

### Scan (default)

```
kuzushi <repo>                        # scan with defaults
kuzushi <repo> --tasks codeql
kuzushi <repo> --tasks semgrep,codeql
kuzushi <repo> --tasks semgrep,agentic
kuzushi <repo> --severity ERROR       # only ERROR-level findings
kuzushi <repo> --max 20               # triage top 20 findings only
kuzushi <repo> --model anthropic:claude-sonnet-4-6  # use a different model
kuzushi <repo> --task-model triage=openai:gpt-4o  # separate model for triage stage
kuzushi <repo> --api-key sk-ant-... --base-url https://api.example.com/  # custom API endpoint
kuzushi <repo> --fresh                # clear prior results, re-triage everything
kuzushi <repo> --db ./my.sqlite3      # custom database path
kuzushi <repo> --resume               # resume the most recent interrupted run
kuzushi <repo> --resume <run-id>      # resume a specific run by ID
```

### Verification

```
kuzushi <repo> --verify               # enable exploit verification for TPs
kuzushi <repo> --verify --task-model verify=openai:gpt-4o-mini  # cheaper model for verification
kuzushi <repo> --verify --verify-max-turns 20
kuzushi <repo> --verify --verify-concurrency 3
kuzushi <repo> --verify --verify-min-confidence 0.7  # skip low-confidence TPs
```

### PoC Harness Generation

```
kuzushi <repo> --verify --poc-harness                          # generate exploit scripts for verified findings
kuzushi <repo> --verify --poc-harness --task-model poc-harness=openai:gpt-4o-mini
kuzushi <repo> --verify --poc-harness --poc-harness-max-turns 25
kuzushi <repo> --verify --poc-harness --poc-harness-concurrency 2
```

### Dynamic Analysis

```
kuzushi <repo> --verify --poc-harness --dynamic-analysis       # execute harnesses to confirm/reject findings
kuzushi <repo> --verify --dynamic-analysis --dynamic-max-candidates 10
kuzushi <repo> --verify --dynamic-analysis --dynamic-min-score 8
```

### Patch Synthesis

```
kuzushi patch <repo> --fingerprint <fp>                        # synthesize and validate a patch
kuzushi patch <repo> --fingerprint <fp> --build-cmd "npm run build"
kuzushi patch <repo> --fingerprint <fp> --test-cmd "npm test" --max-iterations 5
```

### Code Graph

```
kuzushi <repo> --code-graph                       # enable LLM-powered code graph (entry-point-to-sink tracing)
```

### Multi-Strategy Analysis

```
kuzushi <repo> --multi-strategy                   # adaptive mode: run cheapest strategy first, exit early if confident
kuzushi <repo> --multi-strategy-full              # run all strategies in parallel for maximum coverage
kuzushi <repo> --multi-strategy-budget 3.0        # per-finding budget across all strategies (USD)
kuzushi <repo> --multi-strategy-auto-rules        # generate Semgrep rules from confirmed multi-strategy findings
```

### Auto-Patch (Closed-Loop)

```
kuzushi <repo> --verify --auto-patch                                # patch exploitable findings, re-verify
kuzushi <repo> --verify --auto-patch --auto-patch-after triage      # patch any TP (broadest trigger)
kuzushi <repo> --verify --auto-patch --auto-patch-after poc         # patch only after PoC proves it
kuzushi <repo> --auto-patch --patch-verify-depth triage             # re-run scanner + triage on patched code
kuzushi <repo> --auto-patch --patch-verify-depth full               # full pipeline re-verify (most thorough)
kuzushi <repo> --auto-patch --patch-concurrency 3                   # parallel patch synthesis tasks
```

### Streaming

```
kuzushi <repo> --stream                           # start SSE server on auto-assigned port
kuzushi <repo> --stream --stream-port 3001        # start SSE server on specific port
# Then in another terminal:
curl -N http://localhost:3001/events              # watch live pipeline events
```

### Crypto Behavioral Testing

```
kuzushi <repo> --crypto-behavioral-test                        # generate & run behavioral tests for crypto misuse findings
```

### Diff-Aware Taint

```
kuzushi <repo> --taint-diff-base main                          # only taint-analyze files changed since main
kuzushi <repo> --taint-diff-base main --taint-diff-mode delta  # emit only findings intersecting the diff
kuzushi <repo> --taint-diff-base main --taint-diff-mode baseline  # merge cached + rerun for full baseline
```

### Output & Observability

```
kuzushi <repo> --output report.md     # export markdown report
kuzushi <repo> --sarif results.sarif  # export SARIF v2.1.0
kuzushi <repo> --json results.json    # export JSON report
kuzushi <repo> --csv results.csv      # export CSV report
kuzushi <repo> --jsonl results.jsonl  # export JSONL report
kuzushi <repo> --audit-log            # write agent activity to .kuzushi/runs/{runId}/
kuzushi <repo> --verbose              # show debug-level runtime diagnostics
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
kuzushi config set model anthropic:claude-sonnet-4-6
kuzushi config set tasks semgrep,agentic
kuzushi config set taskConfig.codeql.dbPath ./codeql-db
kuzushi config set taskConfig.codeql.suite javascript-security-extended
kuzushi config set taskConfig.semgrep.binary opengrep
kuzushi config set taskConfig.semgrep.configFlag auto
kuzushi config set taskConfig.agentic.model anthropic:claude-sonnet-4-6
kuzushi config set taskConfig.agentic.maxFindings 25
kuzushi config set taskConfig.triage.model anthropic:claude-opus-4-6
kuzushi config set taskConfig.verify.model openai:gpt-4o-mini
kuzushi config set severity ERROR,WARNING,INFO
kuzushi config set verify true
kuzushi config set verifyMinConfidence 0.7
kuzushi config set auditLog true
kuzushi config validate --repo .      # validate the effective config for this repo
kuzushi config unset model            # reset to default
kuzushi config path                   # print config file location
```

Global config lives at `~/.kuzushi/config.json`. Optional project overrides can live at `<repo>/.kuzushi/config.json`. CLI flags override config values.

**Repo-local config sandboxing:** By default, project-level config files (`<repo>/.kuzushi/config.json`) are sandboxed — keys that could execute code or reach external systems (e.g., `hooks`, `externalTasks`, `pocExecute`, scanner binary paths) are silently stripped. This prevents a cloned repo from altering your runtime behavior. Pass `--trust-repo-config` to opt in to the full project config when you trust the repository.

Security note: `agentRuntimeConfig.apiKey` is stored in plaintext in config files. Prefer `--api-key` for one-off runs or `ANTHROPIC_API_KEY` from your shell/secret manager.

</details>

<details>
<summary><strong>Configuration Reference</strong></summary>

| Key | Default | Description |
| --- | --- | --- |
| `model` | `anthropic:claude-sonnet-4-6` | Default LLM model for all tasks and stages |
| `tasks` | `["semgrep"]` | Enabled task IDs, in execution order |
| `taskConfig` | `{ semgrep: {...}, triage: {...}, ... }` | Per-task config blocks keyed by task ID or stage ID (see below) |
| `severity` | `["ERROR","WARNING"]` | Semgrep severity filter |
| `excludePatterns` | `["test","tests","node_modules",...]` | Directories/globs to skip |
| `busBackend` | `"in-process"` | Message bus transport (`in-process`) |
| `triageConcurrency` | `5` | Parallel LLM triage calls |
| `scanMode` | `"concurrent"` | Task execution mode (`sequential` or `concurrent`) |
| `agentRuntimeBackend` | `"pi-ai"` | Agent runtime backend (`pi-ai`) |
| `verify` | `false` | Enable proof-of-exploitability verification |
| `verifyMaxTurns` | `15` | Max turns for verification agent |
| `verifyConcurrency` | `3` | Parallel verification calls |
| `verifyVerdicts` | `["tp"]` | Which triage verdicts to verify |
| `verifyMinConfidence` | `0` | Minimum triage confidence to trigger verification (0-1) |
| `pocHarness` | `false` | Enable post-verification PoC harness generation (requires `--verify`) |
| `pocHarnessMaxTurns` | `20` | Max turns for PoC harness agent |
| `pocHarnessConcurrency` | `2` | Parallel PoC harness generation calls |
| `cryptoBehavioralTestEnabled` | `false` | Enable crypto behavioral testing for crypto misuse findings |
| `cryptoBehavioralMaxFindings` | `10` | Max findings to generate behavioral tests for per run |
| `cryptoBehavioralTimeoutMs` | `120000` | Execution timeout per harness in ms |
| `cryptoBehavioralPerFindingBudgetUsd` | `1` | Cost budget per finding for harness generation |
| `codeGraphEnabled` | `true` | Enable LLM-powered code graph construction and enrichment |

**Stage model overrides** — set per-stage models via `taskConfig` instead of top-level fields:

| `taskConfig` key | Fallback chain | Purpose |
| --- | --- | --- |
| `taskConfig.triage.model` | `model` | Model for triage agents |
| `taskConfig.verify.model` | `model` | Model for verification agents |
| `taskConfig.poc-harness.model` | `taskConfig.verify.model` → `model` | Model for PoC harness generation |
| `multiStrategyMode` | `"off"` | Multi-strategy analysis mode (`off`, `adaptive`, `full`) |
| `multiStrategyBudgetUsd` | `2.0` | Per-finding budget across all strategies (USD) |
| `autoPatchEnabled` | `false` | Enable automatic patch generation in pipeline |
| `autoPatchAfter` | `"verify"` | Trigger threshold for auto-patch (`verify`, `poc`, `triage`) |
| `patchVerifyDepth` | `"task"` | Re-verification depth after patching (`task`, `triage`, `full`) |
| `patchConcurrency` | `2` | Max concurrent patch synthesis tasks |
| `incrementalCache` | `true` | Enable incremental scanning (skip unchanged findings across runs) |
| `incrementalDepTracking` | `true` | Include importers of changed files in rescan scope |
| `streamingEnabled` | `false` | Enable SSE streaming server for live pipeline events |
| `streamingPort` | `0` (auto) | Port for the SSE streaming server |
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

Example config:

```json
{
  "tasks": ["semgrep", "codeql", "context-gatherer", "context-enricher", "secrets-crypto-detect", "code-config-detect", "taint-cwe-select", "taint-iris"],
  "scanMode": "concurrent",
  "triageConcurrency": 3,
  "verify": true,
  "verifyMinConfidence": 0.7,
  "auditLog": true,
  "taskConfig": {
    "codeql": { "dbPath": "./codeql-db", "suite": "javascript-security-extended" },
    "semgrep": { "binary": "opengrep", "configFlag": "auto" },
    "agentic": { "model": "anthropic:claude-sonnet-4-6", "maxFindings": 20 },
    "triage": { "model": "anthropic:claude-opus-4-6" },
    "verify": { "model": "openai:gpt-4o-mini" }
  }
}
```

### Environment Variables

| Variable | Required | Description |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | When using `anthropic:*` models | Anthropic API key for pi-ai backend |
| `OPENAI_API_KEY` | When using `openai:*` models | OpenAI API key for pi-ai backend |
| `GEMINI_API_KEY` / `GOOGLE_API_KEY` | When using `google:*` models | Google API key for pi-ai backend |

</details>

<details>
<summary><strong>CodeQL Setup</strong></summary>

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

</details>

<details>
<summary><strong>Taint Analysis Setup</strong></summary>

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

</details>

<details>
<summary><strong>Agent Runtime Backends</strong></summary>

Kuzushi supports two agent runtime backends:

**Claude (default)** — Uses `@anthropic-ai/claude-agent-sdk` to spawn Claude Code subprocesses with built-in tool implementations (Read, Glob, Grep, Bash, etc.). Supports session reuse: batch operations keep a single subprocess alive across multiple turns via the SDK's streaming input API, reducing subprocess spawns by ~99%. Requires `ANTHROPIC_API_KEY`.

**Pi-AI** — Uses `@mariozechner/pi-ai` to provide vendor-agnostic LLM access. It supports 15+ providers (Anthropic, OpenAI, Google, Groq, Mistral, etc.) through a single interface. All LLM calls run in-process (no subprocesses).

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

</details>

<details>
<summary><strong>Architecture</strong></summary>

Kuzushi is built on three core abstractions:

**Message Bus** — A transport-agnostic `MessageBus` interface (`publish`, `subscribe`, `waitFor`) that decouples pipeline stages. The stable build supports the in-process `EventEmitter` transport today.

**AgentTask + DAG** — Every unit of work (context gatherer, scanner, future threat modeler, etc.) implements the `AgentTask` interface: an `id`, `dependsOn` list, `outputKind`, and a `run()` method. The `TaskRegistry` resolves enabled tasks into a DAG, groups them into parallel stages, detects cycles, and hands execution to the `PipelineOrchestrator`. Upstream task outputs are forwarded to dependents automatically.

**Pipeline Phases** — After the DAG completes, the orchestrator drives sequential phases: triage (classify findings), verification (construct PoC exploits), patch synthesis (auto-generate and re-verify fixes), and report (display results + optional SSE streaming). Each phase has its own concurrency control, cost tracking, and checkpoint support.

**Strategy Framework** — The multi-strategy system wraps detection tasks with multiple analytical approaches (syntactic, dataflow, reasoning, execution) that run in parallel or adaptively, merging results with corroboration-based confidence boosting.

**Code Graph** — A persistent SQLite-backed graph of code paths from entry points to sinks, built from static import analysis and LLM-assisted tracing. Injected into triage prompts for deeper reasoning about reachability and sanitization.

**Session Reuse** — The Claude runtime uses the Agent SDK's `AsyncIterable<SDKUserMessage>` prompt to keep a single subprocess alive across multiple turns. Batch operations (taint labeling, triage, verification, rescoring, PoC generation, patch synthesis) write per-batch data to `.kuzushi/batches/` files and send the subprocess a prompt to `Read` each file. This reduces worst-case subprocess spawns from ~3,100 to ~24 per pipeline run. Runtimes without `createSession` support (pi-ai) fall back to one subprocess per call automatically.

Existing `ScannerPlugin` implementations (Semgrep, Agentic) are adapted into `AgentTask` via `adaptScannerPlugin()`, so the scanner plugin API remains stable.

See [AGENTS.md](AGENTS.md) for the full developer guide on adding new agent tasks.

### Package Surface

Kuzushi is published as a CLI-first package. The supported npm surface is the executable plus the root package export; internal modules under `dist/*` and `src/*` are not a stable API contract and may change between releases.

Release builds are expected to come from a clean compile into `dist/`. `pnpm build` now cleans `dist/` first, `prepack` rebuilds automatically, and `pnpm verify:pack` runs `npm pack --dry-run` so stale artifacts do not get published.

</details>

## Output

Results are stored in SQLite at `<repo>/.kuzushi/findings.sqlite3`. Export to any format:

```sh
kuzushi <repo> --output report.md     # Markdown
kuzushi <repo> --sarif results.sarif  # SARIF v2.1.0 (GitHub Code Scanning compatible)
kuzushi <repo> --json results.json    # JSON
kuzushi <repo> --csv results.csv      # CSV
kuzushi <repo> --jsonl results.jsonl  # JSONL
```

## Development

```
pnpm install                          # install deps
pnpm dev -- /path/to/repo             # run in dev mode
pnpm check:types                      # typecheck app + benchmark tooling
pnpm typecheck                        # type check
pnpm test                             # run tests
pnpm test:e2e                         # deterministic mock-backed smoke scan against fixture app
pnpm test:coverage                    # tests + coverage (70% threshold)
pnpm build                            # compile to dist/
pnpm verify:pack                      # verify published tarball contents
pnpm benchmark                        # run benchmark suite against govwa dataset
pnpm benchmark:freeze                 # freeze current benchmark results as baseline
pnpm benchmark:diff                   # diff current results against frozen baseline
pnpm benchmark:regression             # CI regression check against baseline
```

`pnpm test:e2e` and the benchmark regression workflow use `tests/fixtures/mock-anthropic-server.mjs` for deterministic mock-backed coverage. They are useful smoke/regression checks, but they are not real LLM integration tests.

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
