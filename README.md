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
kuzushi shell                            # default — just `kuzushi` works
kuzushi shell --workspace acme-pentest   # resume an engagement
kuzushi shell --target ./repo            # set initial target
kuzushi shell --load blackbox,honeypot   # pre-load specific modules
```

```
┌─────────────────────────────────────────────────────────────┐
│  kuzushi shell                      workspace: acme-api     │
│  modules: sast, randori, blackbox, honeypot, shinsa         │
│  target: ./acme-api  (Node.js + Express + PostgreSQL)       │
└─────────────────────────────────────────────────────────────┘

kuzushi> modules
kuzushi> use sast
kuzushi/sast> run scan ./repo preset=deep
kuzushi/sast> back
kuzushi> tools
kuzushi> run sast:verify fingerprint=abc123
kuzushi> exit
```

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
kuzushi run sast:triage fingerprint=abc123 --json
kuzushi run sast:verify fingerprint=abc123 --quiet
kuzushi run sast:findings severity=critical,high --json
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

Kuzushi's capabilities come from pluggable modules. Each module exposes tools (for shell and run modes) and optionally pipeline tasks (for scan mode DAG execution).

| Module | Category | What It Does |
|--------|----------|-------------|
| **sast** (built-in) | offense | 40+ task SAST pipeline: Semgrep, CodeQL, agentic detectors, AI triage, verification, PoC, patch |
| **randori** | intel | 7-stage PASTA threat modeling with ATT&CK/CAPEC/NVD intel, attack trees, probabilistic risk |
| **vuln-scout** | offense | Whitebox SAST with 15 Joern CPG verification scripts, 8 autonomous agents |
| **augur** | offense | Neuro-symbolic SAST (IRIS/ICLR 2025 LLM-driven CodeQL taint analysis) |
| **blackbox** | offense | Black/grey-box pentesting: nmap, gobuster, nikto, hydra, privilege escalation |
| **pwn** | offense | Binary exploitation: checksec, GDB, ROP chains, heap exploitation, SROP |
| **pentest** | offense | MCP server wrapping metasploit, nmap, hydra, john |
| **honeypot** | defense | Autonomous honeypot orchestration: 14 service types, 6 honeytokens, Falco |
| **yokai** | defense | Supply chain tripwires: dependency confusion, typosquatting, registry canaries |
| **prompt-armor** | offense | LLM red teaming: 80+ attack plugins, 25+ mutation strategies |
| **shinsa** | governance | Multi-framework compliance: ISO 27001, NIST 800-53, SOC 2, PCI DSS |
| **revgraph** | intel | Binary reverse engineering: Ghidra + Neo4j, NL2Cypher, function embeddings |

Modules are loaded via the shell (`use <module>`) or at startup (`--load blackbox,honeypot`).

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
      - run: npx kuzushi scan . --sarif results.sarif --quality-gate --fail-on-tp
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### Quality Gates

```sh
kuzushi scan <repo> --quality-gate         # fail CI on threshold violations
kuzushi scan <repo> --fail-on-tp           # fail if any high/critical TP is found
kuzushi scan <repo> --sarif results.sarif  # export SARIF for GitHub Code Scanning
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

**Interactive terminal UI** — React+Ink-powered live display with pipeline progress tree, spinners, trophy screen for confirmed exploits. REPL during scans (pause, skip, inspect). First-run setup wizard. Falls back to plain text in non-TTY.

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
kuzushi scan <repo> --stream
kuzushi scan <repo> --audit-log
```

### Run Mode

```
kuzushi run sast:scan ./repo --json
kuzushi run sast:triage fingerprint=abc123 --json
kuzushi run sast:verify fingerprint=abc123 --quiet
kuzushi run sast:findings severity=critical,high --json
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

## License

MIT
