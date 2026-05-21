# Kuzushi Vision

Status: roadmap and product strategy. For the shipping Rust CLI/TUI workflow,
start with `README.md`.

Kuzushi's shipping product focus is an evidence-backed repository security
workbench: local-first scan, shell, and run surfaces over durable findings,
proof states, verification records, suppressions, patches, reports, traces,
and run artifacts.

The long-term vision is broader security-agent operations, but every expansion
has to strengthen the current evidence workflow first. Capabilities that do
not produce clear artifacts, proof state, operator next actions, or audit
trails belong in roadmap material, not the primary product promise.

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
              │ Ratatui shell │  │ Pipeline│  │ Single-op    │
              │ NL + commands │  │ CI/CD   │  │ Pipe-able    │
              │ Workspace     │  │ JSON    │  │ JSON stdout  │
              │ Full modules  │  │ Plain CI│  │ Exit codes   │
              └───────────────┘  └─────────┘  └──────────────┘
```

### Shell (default: `kuzushi`)

The interactive operator shell. Persistent workspace, full module composition, explicit agent routes, and structured commands. Rendered through the Rust Ratatui TUI.

### Scan (`kuzushi scan <repo>`)

The headless pipeline workhorse. Runs the SAST executor (Semgrep, CodeQL, selected agentic detectors, triage, verification, and patch flows when configured). CI/CD-native JSON and deterministic progress output are current; unsupported legacy flags are not part of the Rust path.

### Run (`kuzushi run <module:action>`)

Direct module tool invocation. Non-interactive, scriptable, unix-composable. The bridge between shell and automation.

```bash
kuzushi --target ./repo run sast:scan --input '{}' > findings.json
kuzushi --target ./repo run randori:pasta --input '{}' | jq '.data.document.threats'
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
| **shinsa** | governance | Compliance assessment via `shinsa-plugin` — ISO 27001 Annex A + NIST SP 800-53 Rev 5 with evidence-backed findings |
| **prompt-armor** | offense | LLM red teaming via `promptarmor-plugin` — 80+ attack plugins, 25+ mutation strategies, code-aware remediation |
| **variant-hunter** | offense | Lifts confirmed findings into portable signatures and hunts for variants across the repo (including vendored deps) |
| **n-day-diff-hunter** | offense | CVE-diff-based n-day hunting and variant search |

### Compatibility / package-shaped modules

| Package | Module ID | What It Does |
|---------|-----------|--------------|
| `@kuzushi/augur` | **augur** | Neuro-symbolic SAST (IRIS/ICLR 2025 style LLM-driven CodeQL taint analysis). Package/module shape exists, but native Rust CLI/TUI dynamic package loading is not the supported operator path today. |

### Roadmap — not primary product surface

These are North Star directions. Treat the entries below as roadmap material,
not current capability and not the product's near-term wedge. They should only
graduate when they produce first-class evidence artifacts and fit the
scan/findings/proof/report loop.

| Module | Category | Intended scope |
|--------|----------|----------------|
| **blackbox** | offense | Black/grey-box pentesting: nmap, gobuster, nikto, hydra, privilege escalation |
| **pwn** | offense | Binary exploitation: checksec, GDB, ROP chains, heap exploitation, SROP |
| **pentest** | offense | MCP server wrapping metasploit, nmap, hydra, john (loaded natively via MCP) |
| **honeypot** | defense | Autonomous honeypot orchestration: service types, honeytokens, decoys, Falco |
| **yokai** | defense | Supply chain tripwires: dependency confusion, typosquatting, registry canaries |
| **revgraph** | intel | Binary reverse engineering: Ghidra + Neo4j, NL2Cypher queries, function embeddings |

## What a Future Session Could Look Like

_Aspirational example. The transcript below intentionally includes roadmap
modules and should not be read as current CLI/TUI behavior. The current
operator path is the evidence loop in `README.md`: doctor, context, scan,
findings, finding detail, suppress/verify/patch/report._

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

The important product idea is not "one chat that does everything." It is one
evidence graph that can connect repository context, threat model, findings,
proof, suppressions, patches, and reports without losing provenance.

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
`kuzushi` default command — Rust Ratatui interactive shell with module/tool dispatch.

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
