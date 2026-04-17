# Kuzushi — Security-Native AI Operating Environment

Kuzushi is not a scanner. It is a security-native AI operating environment that combines offensive security, defensive operations, and compliance governance into a single interactive platform — powered by LLM agents, backed by a persistent workspace, and delivered through a rich terminal UI.

The difference is "VS Code with extensions" vs. "Burp Suite." Both can do web security testing. One was built for it.

## Three Execution Modes

All three modes share the same core: ModuleRegistry, WorkspaceManager, MessageBus, AgentRuntime, SQLite store. The only difference is the interaction layer.

```
                    ┌─────────────────────────────────┐
                    │         Shared Core              │
                    │                                  │
                    │  ModuleRegistry                  │
                    │  WorkspaceManager                │
                    │  MessageBus + DAG Orchestrator    │
                    │  AgentRuntime (Claude/pi-ai)     │
                    │  SQLite Store + Vector Store     │
                    │  GovernanceLayer                 │
                    └──────┬──────────┬──────────┬─────┘
                           │          │          │
              ┌────────────▼──┐  ┌────▼────┐  ┌──▼───────────┐
              │   Shell Mode  │  │  Scan   │  │  Run Mode    │
              │  (default)    │  │  Mode   │  │              │
              │               │  │         │  │              │
              │ Interactive   │  │ Headless│  │ Headless     │
              │ Ink REPL      │  │ Pipeline│  │ Single-op    │
              │ NL + commands │  │ CI/CD   │  │ Pipe-able    │
              │ Workspace     │  │ SARIF   │  │ JSON stdout  │
              │ Full modules  │  │ Ink UI  │  │ Exit codes   │
              └───────────────┘  └─────────┘  └──────────────┘
```

### Shell (default: `kuzushi`)

The interactive copilot. Conversational, persistent workspace, full module composition. Natural language + structured commands. Rendered through Ink.

### Scan (`kuzushi scan <repo>`)

The headless pipeline workhorse. Runs the full SAST DAG (semgrep, codeql, 30+ agentic detectors, triage, verify, PoC, patch). CI/CD-native with SARIF, JSON, quality gates, exit codes. Rendered through Ink with plain-text fallback.

### Run (`kuzushi run <module:action>`)

Direct module tool invocation. Non-interactive, scriptable, unix-composable. The bridge between shell and automation.

```bash
kuzushi run sast:scan ./repo --json > findings.json
kuzushi run randori:pasta --json | jq '.data.document.threats'
```

## Module Library

Kuzushi's capabilities come from `CopilotModule`s that expose tools (for interactive/headless use) and optionally pipeline tasks (for DAG execution). Three buckets — today's catalog versus the aspirational roadmap:

### Shipping today — built-in `CopilotModule`s

| Module | Category | What It Does |
|--------|----------|--------------|
| **sast** | offense | 40+ task SAST pipeline: Semgrep, CodeQL, agentic detectors, AI triage, verification, PoC, patch synthesis |
| **randori** | intel | PASTA threat modeling (S1–S4 + narrative) via the `@kuzushi/randori-plugin` Claude Code plugin, returning a normalized `ThreatModelDocument` |
| **vuln-scout** | offense | Whitebox pentest via the `@kuzushi/vuln-scout` plugin — agentic SAST + taint analysis returning normalized Findings |
| **tob** | offense | Security audit via `@kuzushi/tob-skills` — fp-check, sharp-edges, insecure-defaults, static-analysis, variant-analysis, and more |
| **variant-hunter** | offense | Lifts confirmed findings into portable signatures and hunts for variants across the repo (including vendored deps) |
| **n-day-diff-hunter** | offense | CVE-diff-based n-day hunting and variant search |

### Shipping today — external `CopilotModule` package

| Package | Module ID | What It Does |
|---------|-----------|--------------|
| `@kuzushi/augur` | **augur** | Neuro-symbolic SAST (IRIS/ICLR 2025 style LLM-driven CodeQL taint analysis). Load via `--load package:@kuzushi/augur`. |

### Roadmap — not yet shipped

These are the North Star modules — design intent exists, implementations do not (yet). Treat the entries below as the direction this vision is pointing toward, not current capability:

| Module | Category | Intended scope |
|--------|----------|----------------|
| **blackbox** | offense | Black/grey-box pentesting: nmap, gobuster, nikto, hydra, privilege escalation |
| **pwn** | offense | Binary exploitation: checksec, GDB, ROP chains, heap exploitation, SROP |
| **pentest** | offense | MCP server wrapping metasploit, nmap, hydra, john (loaded natively via MCP) |
| **honeypot** | defense | Autonomous honeypot orchestration: service types, honeytokens, decoys, Falco |
| **yokai** | defense | Supply chain tripwires: dependency confusion, typosquatting, registry canaries |
| **prompt-armor** | offense | LLM red teaming: attack plugins, mutation strategies, orchestrating agents |
| **shinsa** | governance | Multi-framework compliance: ISO 27001, NIST 800-53, SOC 2, PCI DSS |
| **revgraph** | intel | Binary reverse engineering: Ghidra + Neo4j, NL2Cypher queries, function embeddings |

## What a Session Looks Like

_Aspirational example — the `blackbox`, `honeypot`, and `shinsa` transcript below references roadmap modules. Today, the actual session surface covers `sast`, `randori`, `vuln-scout`, `tob`, `variant-hunter`, `n-day-diff-hunter`, and the `augur` package._

```
┌─────────────────────────────────────────────────────────────┐
│  kuzushi shell                      workspace: acme-api     │
│  modules: sast, randori, blackbox, honeypot, shinsa         │
│  target: ./acme-api  (Node.js + Express + PostgreSQL)       │
└─────────────────────────────────────────────────────────────┘

you> What's the attack surface of this API?

kuzushi> Running context-gatherer + app-model-build...

  3 HTTP routes discovered:
    POST /auth/login        (public, no rate limit)
    GET  /api/users/:id     (auth required, no ownership check)
    POST /api/upload        (auth required, S3 destination)

  High-risk areas:
  1. /api/upload — no file type validation before S3 put
  2. /api/users/:id — IDOR potential (no ownership check)
  3. /auth/login — brute-forceable (no rate limiting)

you> Hunt for SSRF chains

kuzushi> Loading: ssrf-detect, taint-iris, threat-hunt
  [████████░░░░] 3/4 strategies complete...

  SSRF Chain Found (critical, confidence: 0.91)
    Source: req.body.webhookUrl in POST /api/integrations/webhook
    Sink:   axios.get(url) in src/services/webhook.ts:47
    Chain:  webhookUrl -> validateUrl() [bypassable] -> axios.get() -> IMDS
    PoC:    curl -X POST /api/integrations/webhook \
              -d '{"url":"http://169.254.169.254/latest/meta-data/"}'

you> Set up a honeypot to detect if anyone tries that in prod

kuzushi> [honeypot] Deploying IMDS canary...
  Honeytoken: fake AWS credentials in metadata response
  Alert: Slack #security-alerts on any access
  MITRE: T1552.005 (Cloud Instance Metadata API)
  Deployed. Monitoring active.

you> Are we PCI DSS compliant?

kuzushi> [shinsa] Running PCI DSS v4.0 assessment...
  Status: NON-COMPLIANT (3 gaps)
  Req 6.5.1 — Injection: SSRF chain above
  Req 6.5.8 — CSRF: missing on state-changing endpoints
  Req 8.1.6 — Lockout: /auth/login has no lockout
  2 gaps linked to findings in workspace. Generate patches?
```

One conversation. Offense, defense, compliance, remediation.

## Workspace & Knowledge Graph

The **workspace** persists across sessions — it's the copilot's memory for a security engagement.

```
Workspace "acme-pentest"
  ├── Targets: [./acme-api (repo), 10.0.0.1 (host)]
  ├── Findings: [SSRF in webhook.ts, IDOR in users/:id, ...]
  ├── Threat Model: [PASTA output from Randori]
  ├── Compliance: [PCI DSS snapshot — 3 gaps]
  ├── Active Sessions: [honeypot on IMDS, blackbox scan running]
  ├── Exploit Chains: [SSRF -> IMDS -> AWS creds -> S3 exfil]
  └── Cost: $2.47 total
```

The **knowledge graph** links artifacts across modules:
- Finding -> exploits -> ThreatScenario
- Finding -> violates -> ComplianceControl
- Finding -> chains_with -> Finding (exploit chains)
- Honeypot -> detects -> ThreatScenario

**Attack surface** is a first-class, regenerable artifact. Built incrementally by multiple modules. Queryable, diffable, always up to date.

## Intel Layer (Local Vector Store)

Semantic search over security knowledge, entirely local:

```
~/.kuzushi/intel/
  ├── compliance/       # ISO 27001, NIST 800-53, PCI DSS, SOC 2 control text
  ├── cves/             # NVD CVE descriptions + embeddings
  ├── attack-patterns/  # ATT&CK techniques, CAPEC patterns
  ├── past-findings/    # Triage rationales from previous engagements
  └── custom/           # User-supplied docs (security policies, arch docs)
```

"Have we seen a vuln like this before?" — semantic search over every engagement you've ever run. Past triage rationales become searchable precedent for future findings.

## Governance

Offensive capabilities need guardrails:

1. **Scope policies** — target allowlists (CIDRs, repos, domains). Nothing runs out of scope.
2. **Action tiers** — scan (always safe) -> exploit (confirm) -> network (confirm) -> deploy (confirm).
3. **4-level autonomy** — propose-only -> human-in-loop -> autonomous -> full. Per-module.
4. **Engagement audit trail** — every tool call, every conversation turn -> JSONL.
5. **Budget enforcement** — per-operation USD tracking, cost caps across all modules.
6. **Model flexibility** — Claude, Ollama, OpenAI, Gemini, Mistral via pi-ai. Runs airgapped.

## Why Not Just Claude Code + Plugins?

Claude Code is a general-purpose dev tool that can call security plugins. Kuzushi is purpose-built:

- **The pipeline and the conversation are the same thing.** Pause mid-triage, ask "why did you mark this as FP?", redirect the agent, resume. 40 tasks in parallel DAG stages, not sequential tool calls.
- **Engagement management, not conversation management.** Workspaces persist targets, findings, threat models, compliance state, exploit chains across sessions.
- **Security-native context injection.** Every agent response is grounded in your threat model, open findings, compliance gaps — not just your codebase conventions.
- **Governance Claude Code doesn't have.** Target scoping, engagement audit trails, rules of engagement, 4-level autonomy per module.
- **Model-flexible.** Runs on Ollama in an airgapped network. Claude Code requires Claude.
- **Single distributable.** One install, not 8 plugins + 3 MCP servers.

## Implementation Roadmap

### Phase 1: Module System + CopilotCore (done)
`CopilotModule` interface, `ModuleRegistry`, core SAST module wrapper, `CopilotCore` coordinator.

### Phase 2: Run Mode (done)
`kuzushi run <module:action>` — headless tool invocation with JSON output and exit codes.

### Phase 3: Shell Mode (done)
`kuzushi` default command — Ink-rendered interactive shell with module/tool dispatch.

### Phase 4: Workspace & Knowledge Graph
SQLite workspace tables, WorkspaceManager, knowledge graph, cross-session persistence.

### Phase 5: Governance
Scope policies, approval gates, engagement audit trail, 4-level autonomy.

### Phase 6: Intel Layer (Vector Store)
Local vector DB, NVD/ATT&CK/CAPEC sync, user doc ingestion, semantic search.

### Phase 7: External Module Integration
Port Randori, Blackbox, Honeypot, Shinsa, PromptArmor as modules. MCP adapter.

### Phase 8: NL Copilot
Wire AgentSession into the shell — the LLM routes natural language to module tools. The shell becomes conversational.
