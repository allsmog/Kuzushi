# Kuzushi vs. Xint — Capability Comparison

Research-grade comparison of Kuzushi against [Xint](https://xint.io/) (Theori's
AI-driven AppSec platform). Treat this as a PR-review-grade input, not
committed product direction.

This doc was written 2026-05-07 against `claude/compare-xint-capabilities-ULHcn`.
Public information on Xint comes from theori.io / xint.io / vendor blog posts /
press coverage; some details are inferred from marketing copy because the
product is closed-source SaaS.

---

## 1. TL;DR

Kuzushi and Xint are aimed at the same problem (LLM-driven security review of
real codebases) but ship in different shapes:

- **Xint** is a closed, managed SaaS with two productised offerings: **Xint
  Code** (LLM-native SAST over source/config/binaries) and **Xint Web**
  (autonomous black-box DAST). Architecture is multi-agent, multi-phase,
  model-agnostic, with a focus on business-logic bugs and predictable
  per-scan pricing.
- **Kuzushi** is an open, operator-driven Rust + TypeScript toolkit with 29+
  modules across SAST/taint/recon/secrets/SCA/IaC/threat-modeling/n-day
  hunting/vendor-assessment/prompt-injection-testing, three execution modes
  (scan / shell / run), an integrated DAG pipeline, an interactive Ratatui
  TUI, and an MCP bridge for third-party tools.

In headline categories Kuzushi matches or exceeds Xint Code's *breadth*
(more module families, more execution modes, more extensibility, more
operator surface). In headline *outcomes* Xint has a public track record
Kuzushi cannot yet match: 0-day RCEs in Redis / PostgreSQL / MariaDB, a
20-year-old PostgreSQL bug, a "free money" business-logic finding, and a
deployment at Samsung. The two systems also diverge sharply on Web/DAST:
Xint Web is a real autonomous black-box scanner, Kuzushi's web surface
(`chrome-rce`, `recon`) is much narrower.

---

## 2. Xint at a glance

Sourced from public material — closed product, no source available.

### 2.1 Products

| Product   | Target               | Mode                                       |
| --------- | -------------------- | ------------------------------------------ |
| Xint Code | Source + config + binaries | LLM-native SAST, "human-level" business-logic analysis |
| Xint Web  | Running web apps     | Black-box DAST, scenario-based pentest     |

### 2.2 Architecture (per Theori blog + press)

- Multi-agent, multi-phase orchestration engine; agents are scoped to
  specific tasks (potential threat analysis, path assessment, threat
  modeling) and run in parallel.
- **Model-agnostic** — picks the best frontier model per task rather than
  pinning all agents to one model.
- **Multi-stage verification pipeline** — every candidate finding is
  re-checked for severity + exploitability before reporting, with the
  explicit goal of cutting false positives.
- Reports include step-by-step reproduction and impact assessment.
- Pricing is positioned as predictable / not token-metered ("solving the
  token-burn problem"), which implies internal scoping and budget caps
  rather than charging the operator per token.

### 2.3 Notable outputs

- 0-day RCEs in Redis, PostgreSQL, MariaDB (ZeroDay Cloud database
  category sweep, "zero human intervention").
- A 20-year-old PostgreSQL data-exfiltration / arbitrary-code-injection
  bug.
- A logic bug allowing users to mint balance without depositing ("free
  money glitch") and an MFA flow exposing verification codes via a
  redirect page.
- Production deployment at Samsung Electronics for IT-asset security
  automation.

### 2.4 What Xint does *not* publish

- Concrete vulnerability-class taxonomy (it sells "real bugs", not a
  fixed CWE list).
- Open APIs / SDK / module system for third-party detectors.
- CI/CD integration specifics (SARIF export, PR comments, GitHub
  Actions). Plausible but not documented in the sources surveyed.
- Local / on-prem deployment story.
- Audit-trail / replay / governance disclosures.

---

## 3. Kuzushi at a glance

Source: codebase survey at HEAD (`ec9f8f4`) plus
`CLAUDE.md`, `docs/modules.md`, and `docs/assessments/mode-parity.md`.

### 3.1 Module inventory (29 visible + 3 hidden DAG-internal)

| Family                   | Modules                                                                                  |
| ------------------------ | ---------------------------------------------------------------------------------------- |
| Indexing / context       | `context`, `context-lite` (hidden)                                                       |
| SAST orchestration       | `sast`, `semgrep`, `codeql`, `agentic-sast` (16 LLM detectors)                           |
| Taint analysis           | `taint-iris`, `taint-iris-next`                                                          |
| Threat modeling          | `threat-model` (STRIDE/DFD/scope), `carlini-threat-hunt` (actor-scoped agent hunt)       |
| Triage / verify / patch  | `triage`, `verify`, `patch`                                                              |
| Findings / workspace     | `findings`, `workspace`, `catalog`, `config`                                             |
| Secrets / deps / IaC     | `secret-scan`, `dep-hygiene`, `iac-scan`                                                 |
| Recon / web              | `recon` (nmap, subdomain, http-fingerprint), `chrome-rce`                                |
| Variant / n-day          | `variant`, `ndiff` (CVE diff → variant hunt)                                             |
| Vendor / pentest         | `vuln-scout`, `tob` (Trail of Bits plugins), `vendor-assessment`                         |
| Compliance / hardening   | `shinsa` (incl. NIST), `randori` (PASTA), `x-ray` (Pashov pre-audit report)              |
| LLM safety               | `prompt-armor` (prompt injection / jailbreak testing)                                    |
| DAG-internal             | `pipeline`, `systems-hunt` (hidden)                                                      |

### 3.2 Execution modes

`CopilotCore.executeTool(...)` is the single dispatch path; all three modes
share governance, audit trail, runtime activity tee, capability probe, and
`resolveOption` fallback.

| Mode  | CLI                                  | Output                                   |
| ----- | ------------------------------------ | ---------------------------------------- |
| scan  | `kuzushi scan <repo> [--mode …]`    | DAG pipeline, `.kuzushi/runs/<runId>/`  |
| shell | `kuzushi [--target <repo>]`         | Interactive Ratatui TUI, 19 views        |
| run   | `kuzushi run <module:tool> --input` | Headless single-tool, `--json` output    |

### 3.3 Agent runtime

- pi-ai (`@mariozechner/pi-ai` 0.68.0) provides multi-backend routing.
- `src/agent-runtime/enforcement.ts` blocks silent runtime/model
  fallback at startup *and* before every dispatch.
- Per-tool model resolution: `ctx.toolModel ?? ctx.config.model`. No
  hard-coded provider defaults inside modules.

### 3.4 Persisted state

- `.kuzushi/v2/findings.sqlite3` — findings store shared across modes.
- `.kuzushi/runs/<runId>/{summary.json,triage.jsonl,verify.jsonl}` —
  scan-mode artefacts; consumed by shell `/replay` and `/trace`.
- `.kuzushi/threat-model.json`, `.kuzushi/context-snapshot.json`,
  `.kuzushi/v2/attachments.json`, `.kuzushi/v2/artifact-kb.sqlite3`.
- Prompt overrides at `.kuzushi/prompts/<moduleId>/<verb>.md`,
  layered with session datastore + `taskConfig`.

### 3.5 Extensibility

- `defineModule` / `defineTool` / `defineDagTool` authoring helpers with
  compile-time tool-name-prefix enforcement (`<moduleId>:<verb>`).
- Load specifiers: `builtin:`, `file://`, `package:`, `mcp:`. Bare
  strings default to builtin.
- `kuzushi/testing` mocks for third-party module authors.
- `mcp-bridge.ts` wraps any MCP stdio server as a `CopilotModule`.

---

## 4. Side-by-side capability matrix

`Yes` = ships and is documented. `Partial` = exists but narrower than the
competitor's offering. `No` = absent or not in public material. Marketing
claims without technical disclosure are listed as `Partial` even when
Xint says "fully autonomous."

| Capability                                  | Xint                | Kuzushi              | Notes |
| ------------------------------------------- | ------------------- | -------------------- | ----- |
| **Code / SAST**                             |                     |                      | |
| LLM-native SAST                             | Yes (Xint Code)     | Yes (`agentic-sast`) | Kuzushi exposes 16 named detectors; Xint advertises a unified pipeline. |
| Deterministic SAST (Semgrep, CodeQL)        | Unclear             | Yes                  | Kuzushi orchestrates open scanners as first-class modules. |
| Taint analysis                              | Implied             | Yes (`taint-iris`, `taint-iris-next`) | Kuzushi has explicit CWE-driven taint tools. |
| Binary analysis                             | Yes (claimed)       | No                   | Xint claims source + config + binaries; Kuzushi is source-only. |
| Business-logic / multi-step bugs            | Yes (track record)  | Partial              | Kuzushi's `carlini-threat-hunt` and `agentic-sast/auth-logic` aim here; Xint has the public outcomes. |
| Multi-stage verification                    | Yes                 | Yes (`verify:finding`) | Kuzushi runs PoC generation + execution; Xint describes a multistage filter. |
| Patch / fix generation                      | Implied             | Yes (`patch:finding`) | Kuzushi exposes patches as a tool with a test harness. |
| Variant / n-day hunting                     | Unclear             | Yes (`variant`, `ndiff`) | Kuzushi extracts CVE fix patterns and hunts variants. |
| **Web / DAST**                              |                     |                      | |
| Autonomous black-box web scan               | Yes (Xint Web)      | No                   | Largest single capability gap. Kuzushi has no autonomous crawler. |
| Authenticated scan / login flow handling    | Yes                 | No                   | Xint Web supports common auth methods. |
| Scenario-based pentest                      | Yes                 | Partial              | `chrome-rce`, `recon`, `vuln-scout` cover narrow surfaces. |
| **Infrastructure / supply chain**           |                     |                      | |
| Secrets scanning                            | Unclear             | Yes (`secret-scan`)  | |
| Dependency / SCA                            | Unclear             | Yes (`dep-hygiene`)  | |
| IaC scanning                                | Unclear             | Yes (`iac-scan`)     | |
| Cloud posture                               | No                  | No                   | Neither tool covers CSPM. |
| Container / image scanning                  | Unclear             | No                   | |
| **Reasoning surfaces**                      |                     |                      | |
| Threat modeling (STRIDE / DFD)              | Implied             | Yes (`threat-model`) | Kuzushi has dedicated TUI views (`Threat: Dfd|Stride|Stories|Scope|Summary`). |
| Pre-audit / reconnaissance report           | No                  | Yes (`x-ray`)        | Pashov-style scoping report. |
| Vendor / third-party assessment             | No                  | Yes (`vendor-assessment`) | |
| Compliance / hardening (NIST etc.)          | No                  | Yes (`shinsa`)       | |
| Adversarial / pattern analysis              | No                  | Yes (`randori` PASTA) | |
| **LLM-application security**                |                     |                      | |
| Prompt-injection / jailbreak testing        | No                  | Yes (`prompt-armor`) | Six tools: `scan`, `analyze`, `attack`, `diff`, `report`, `config`. |
| **Operator surfaces**                       |                     |                      | |
| Interactive TUI                             | No                  | Yes (Rust Ratatui, 19 views) | |
| Headless single-tool run                    | Unclear             | Yes (`kuzushi run`)  | |
| CI mode (deterministic stdout)              | Implied             | Yes (`scan --ci`)    | |
| Conversational agent                        | Implied             | Yes (`AgentChat`, `ask`) | |
| **Engineering integrations**                |                     |                      | |
| MCP bridge                                  | No                  | Yes (`mcp-bridge`)   | |
| Custom modules / SDK                        | No                  | Yes (`defineModule`, `kuzushi/testing`) | |
| Prompt overrides per tool                   | No                  | Yes (`.kuzushi/prompts/<id>/<verb>.md`) | |
| Cost cap / budget halt                      | Implied (predictable pricing) | Yes (`config.costBudgetUsd`) | Different mechanism — Xint absorbs cost server-side; Kuzushi exposes per-run budget to the operator. |
| Audit trail                                 | Unclear             | Yes (`auditLog`, JSONL) | |
| Replay / trace from artefacts               | No                  | Yes (`/replay`, `/trace`) | |
| No-silent-fallback governance               | Unclear             | Yes (`agent-runtime/enforcement.ts`) | |
| **Deployment**                              |                     |                      | |
| Local / on-prem                             | Unclear             | Yes                  | Kuzushi is a local CLI; Xint is SaaS. |
| Multi-tenant SaaS                           | Yes                 | No                   | |
| Reports / dashboards                        | Yes                 | Partial              | Kuzushi exports JSON / JSONL / SQLite + TUI views; no hosted dashboard. |
| **Track record (public)**                   |                     |                      | |
| 0-day disclosures                           | Yes (Redis/PG/MariaDB) | None published | Largest *credibility* gap. |
| Enterprise reference customer               | Yes (Samsung)       | None published       | |

---

## 5. Where Kuzushi matches or exceeds Xint

These are areas where Kuzushi's public surface is concretely broader than
what Xint discloses. They are *defensible* talking points, not aspirational.

1. **Module breadth.** Kuzushi ships 29+ modules covering SAST, taint,
   secrets, SCA, IaC, recon, browser-RCE, variant/n-day, vendor
   assessment, compliance, prompt-injection testing, and threat
   modeling. Xint publicly addresses code SAST and web DAST.
2. **Execution modes.** scan / shell / run all converge on one core but
   serve different operator postures (pipeline, exploration,
   automation). Xint exposes scans only.
3. **Interactive operator surface.** A Rust Ratatui TUI with 19 views
   (catalog, module, findings, threats, replay, trace, prompts, agent
   chat, options, history). Xint is a hosted product; the equivalent is
   a web dashboard.
4. **Extensibility.** `defineModule`/`defineTool` authoring helpers,
   `kuzushi/testing` mocks, four load specifiers, an MCP bridge, and
   prompt overrides per `<moduleId>:<verb>`. Xint has no public SDK.
5. **Local / sovereign deployment.** Repos and findings stay on disk
   (`.kuzushi/v2/findings.sqlite3`, `.kuzushi/runs/`); the operator
   chooses the model provider. Xint is SaaS — repos must be uploaded.
6. **Governance and observability.** No-silent-fallback enforcement on
   model/runtime selection, JSONL audit trail, replay/trace from
   per-run artefacts. Xint discloses no equivalent guardrails.
7. **Threat-model-driven hunting.** `threat-model` + `carlini-threat-hunt`
   couples STRIDE/DFD output to actor-scoped agent runs. Xint hints at
   threat modeling as one phase but does not surface it as an editable
   artefact.
8. **LLM-application security (`prompt-armor`).** A dedicated module
   for prompt-injection / jailbreak testing of *the operator's own*
   LLM apps. Outside Xint's published scope.
9. **N-day variant hunting (`ndiff`, `variant`).** Lift a fix pattern
   from a CVE, hunt variants. Xint has not publicly framed this as a
   product surface.
10. **Cost transparency to the operator.** Per-tool cost, session cost,
    `/cost` view, `costBudgetUsd` halt. Xint's model is "predictable
    pricing" — better for buyers, less observable for engineers.

---

## 6. Where Xint exceeds Kuzushi (honest gaps)

1. **Autonomous DAST.** Xint Web is a black-box scanner that crawls,
   handles common auth, and runs scenario-based attacks. Kuzushi has
   `chrome-rce` and `recon` but no autonomous web-app driver. This is
   the largest single capability gap.
2. **Binary analysis.** Xint Code claims to scan compiled artefacts;
   Kuzushi is source-only.
3. **Public outcomes.** 0-day RCEs in Redis, PostgreSQL, MariaDB;
   a 20-year-old PostgreSQL bug; a Samsung deployment. Kuzushi has no
   comparable public track record. Buyers weight this heavily.
4. **Scale claim.** Xint markets "millions of LoC in <12 hours."
   Kuzushi has not published a comparable scale benchmark, and
   `agentic-sast` cost / throughput on monorepos is not characterised
   in the docs surveyed.
5. **Hosted dashboard / report deliverable.** Xint produces a polished
   per-engagement report with reproduction steps and impact. Kuzushi
   produces JSON/JSONL/SQLite + TUI views; the
   `output-reporting.md` assessment already flags PR-comment and
   CI-stream weaknesses.
6. **Predictable pricing for buyers.** Xint absorbs token cost behind a
   per-scan price. Kuzushi's operator-billed token model is more
   transparent but less buyer-friendly for procurement.
7. **Multi-stage verification as a *product claim*.** Xint markets the
   verification pipeline as the FP-reduction lever. Kuzushi has
   `triage` + `verify` + `patch` and the machinery to do this, but the
   end-to-end FP-reduction story is not published as a benchmark.
8. **Managed model selection.** Xint says "we pick the best frontier
   model per task." Kuzushi enforces *no silent fallback* — operator
   *must* configure compatible runtime + model. The Kuzushi posture is
   safer; the Xint posture is friendlier to non-experts.

---

## 7. Strategic notes for Kuzushi

These follow from §5/§6 and the existing assessments
(`output-reporting.md`, `configurability-gaps.md`, `new-modules.md`):

- **The DAST gap is the biggest competitive exposure.** A `web-dast`
  module that drives a headless browser through scenario-based attacks
  (auth, IDOR, broken access control, SSRF, file upload, business-logic
  flows) would close the most visible feature gap with Xint Web. The
  building blocks exist (`chrome-rce`, `recon`, `agentic-sast` detectors,
  `carlini-threat-hunt` for actor scoping) but are not composed into an
  autonomous web driver.
- **Publish a real benchmark.** Even one reproducible run on a known
  vulnerable codebase (DVWA, Juice Shop, GoatRodeo, intentionally-bugged
  Postgres fork) with cost, time, FP-rate, and finding list would close
  the credibility gap created by Xint's 0-day disclosures.
- **Lean into the differentiators Xint structurally cannot match.**
  Local execution, MCP bridge, prompt overrides, audit/replay, threat-
  model-driven hunting, prompt-armor, n-day variant hunting, vendor
  assessment, IaC + secrets + SCA in the same toolkit. These are
  *architectural* advantages of being open + extensible + operator-run.
- **Reporting is the soft underbelly.** `output-reporting.md` already
  flagged this. A Xint-style per-engagement report (reproduction
  steps + impact + remediation) generated from `findings.sqlite3` +
  `verify.jsonl` is mostly assembly work over data Kuzushi already has.
- **Don't try to out-pitch Xint on "fully autonomous."** Kuzushi's
  governance enforcer + cost cap + prompt overrides + replay are the
  *operator-control* story. Position around "auditable autonomy"
  rather than competing on opacity.

---

## 8. Sources

Public material on Xint (closed product, no source available):

- [Xint — The AI Hacker for Faster, Smarter Security](https://xint.io/)
- [Xint by Theori — product page](https://theori.io/products/xint)
- [Xint Web product page](https://xint.io/products/xint-web)
- [Theori launches Xint Code (SiliconANGLE, 2026-03-17)](https://siliconangle.com/2026/03/17/theori-launches-xint-code-ai-platform-uncover-hidden-vulnerabilities-massive-codebases/)
- [Theori brings Xint Code to market (Help Net Security, 2026-03-18)](https://www.helpnetsecurity.com/2026/03/18/theori-xint-code/)
- [Xint Code business-logic announcement (BusinessWire, 2026-03-17)](https://www.businesswire.com/news/home/20260317129537/en/)
- [How Xint's Predictable Pricing Solves the Token Burn Problem (Theori blog)](https://theori.io/blog/154812)
- [Theori deploys Xint to Samsung Electronics (Xint blog)](https://xint.io/blog/165203)
- [AI Pentesting Agents 2026 — landscape survey (AppSecSanta)](https://appsecsanta.com/research/ai-pentesting-agents-2026)

Kuzushi material (this repo at `ec9f8f4`):

- `CLAUDE.md` (mode parity, model safety, module system).
- `docs/modules.md` (authoring guide).
- `docs/assessments/mode-parity.md`, `output-reporting.md`,
  `configurability-gaps.md`, `new-modules.md`.
- `src/modules/`, `src/agents/index.ts`, `src/agent-runtime/`,
  `src/modules/mcp-bridge.ts`, `crates/kuzushi-tui/src/app.rs`.
