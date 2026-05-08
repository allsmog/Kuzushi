# Kuzushi vs. Xint — Capability Comparison

Research-grade comparison of Kuzushi against Theori's published security AI
work: their commercial **Xint** platform ([xint.io](https://xint.io/)) and
their open-source DARPA AIxCC Finals submission **RoboDuck**
([theori-io/aixcc-afc-archive](https://github.com/theori-io/aixcc-afc-archive)).
Treat this as a PR-review-grade input, not committed product direction.

This doc was written 2026-05-07 against `claude/compare-xint-capabilities-ULHcn`.
Public information on Xint comes from theori.io / xint.io / vendor blog posts /
press coverage; some details are inferred from marketing copy because the
product is closed-source SaaS. The RoboDuck section is sourced directly from
the published source tree (~29.5k LoC Python + 1.9k LoC Rust) and its
`docs/crs-architecture.md`.

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

**RoboDuck (sections 8–11)** is Theori's open-source DARPA AIxCC Finals
CRS — third place, $1.5M prize. It is a *narrower* system than either
Xint or Kuzushi: scoped to OSS-Fuzz / C / C++ / JVM targets, daemonised
behind an HTTP API, optimised for fuzzer-driven POV+patch+SARIF
production at AFC scale ("can spend $1,000+ in under an hour"). RoboDuck
contains capabilities Kuzushi does not have (real fuzzing, branch
flipper, harness-input encoder/decoder, dynamic-debug agent, build/test
patch gauntlet, Infer + Joern + LLVM-cov + Jacoco integrations). Kuzushi
covers far more *scope* (general-purpose security for any repo,
threat-modelling, recon, IaC, secrets, SCA, vendor, prompt-injection
testing, an interactive shell). RoboDuck is **AGPL-3.0**, which means
Kuzushi (MIT) can *learn from* it but cannot wholesale absorb code.

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

## 8. RoboDuck (AIxCC Finals CRS) at a glance

Sourced from `theori-io/aixcc-afc-archive` HEAD. Repo statistics:
~29.5k lines Python + 1.9k lines Rust (PyO3 acceleration crate) + ~530
lines JS (React `agent-log-viewer`).

### 8.1 Positioning

A **Cyber Reasoning System** — a daemon that consumes OSS-Fuzz-format
tasks via HTTP and produces three artefacts: a Proof of Vulnerability
(POV — a working crash input), a patch, and SARIF. Targets AFC scoring
rules: time-bounded, fuzzer-driven, must validate POVs against the
harness binary. Languages: **C / C++ / JVM only**. Modes: *Full* (whole
repo) and *Delta* (commit-range PR).

### 8.2 Architecture

`docs/crs-architecture.md` describes a static pipeline:

```
Task → Build → Fuzz ⇄ Coverage ⇄ Frontier → BranchFlip → Corpus
            ↘ Infer ↘
              AInalyze ↘ → VulnReport → score → VulnAnalyze →
              Diff ↗                           AnalyzedVuln → DedupeVuln
                                                           → POVProduce → Crash → LLMTriage
                                                           → GenPatch  → Patch
Patch + POV + SARIF → Bundle → Competition API
```

There is no operator UI. There is no module SDK. There is no
configurable scope or threat-model phase. The pipeline is hard-coded
because the AFC defined the workflow.

### 8.3 Agents (17, in `crs/agents/`)

| Agent                       | Role                                                              |
| --------------------------- | ----------------------------------------------------------------- |
| `BranchFlipperAgent`        | Coverage-frontier-driven directed input synthesis (no symex)      |
| `CRSDiffAgent`              | Delta-mode commit/diff vulnerability analysis                     |
| `CRSDynamicDebugAgent`      | LLM-driven gdb / jdb stepping for runtime introspection           |
| `CRSPovProducerAgent`       | Synthesises crash inputs against a fuzz harness                   |
| `CRSVulnAnalyzerAgent`      | Validates and characterises a candidate vulnerability             |
| `Classifier` / `LikelyVulnClassifier` / `LikelyFlippableClassifier` / `DedupClassifier` | Cheap GPT-4.1 classifiers for ranking + dedup |
| `EditAgent` / `RewriteAgent` | Source-edit primitives                                           |
| `FunctionSummarizer`        | Per-function semantic summary cache                               |
| `GenerateKaitaiAgent`       | LLM-generated [Kaitai Struct](https://kaitai.io/) grammar for binary input formats |
| `HarnessInputEncoderAgent` / `HarnessInputDecoderAgent` | LLM-written Python encoder/decoder so the agent can craft fuzzer-compatible inputs |
| `PatcherAgent`              | Build-and-test patch loop, validated against POV + functionality tests |
| `QueryJoernAgent`           | Joern CPG queries via natural language                            |
| `SourceQuestionsAgent`      | Open-ended Q&A over the codebase for the other agents             |
| `SummarizeChangesAgent`     | Diff/PR summarisation                                             |
| `TriageAgent`               | Crash → vuln-report mapping + impact assessment                   |

Plus six "FullMode" prompt variants per language/case combination
(`FullModeSingleC` / `FullModeMultiC` / `…Java` / `…Unknown`) — these
are prompt templates, not separate agent classes.

### 8.4 Modules (12, in `crs/modules/`)

| Module             | Purpose                                                                |
| ------------------ | ---------------------------------------------------------------------- |
| `fuzzing`          | libFuzzer + Jazzer harness orchestration; corpus, minset, dedup       |
| `coverage`         | LLVM-cov (C/C++) + Jacoco (JVM) coverage extraction + reachability    |
| `debugger`         | gdb + jdb wrapper (used by `CRSDynamicDebugAgent`)                    |
| `graph`            | Reachability / call-graph (rustworkx) + Dijkstra path finding         |
| `kaitai`           | Kaitai Struct binary-format runtime                                   |
| `project`          | OSS-Fuzz project ingestion + harness discovery + build orchestration  |
| `python_sandbox`   | Sandboxed Python execution for agent-generated code                   |
| `sarif`            | SARIF report parsing/emission                                          |
| `search_code`      | tree-sitter (C/C++/Java) + ripgrep + GNU global + clang-AST + joern   |
| `source_editor`    | Edit primitives (used by `EditAgent`)                                 |
| `static_analysis`  | Facebook **Infer** wrapper for C/C++ + LLM-driven analysis            |
| `testing`          | Functionality test harness used by patch loop                          |

### 8.5 External tooling shipped

`external/`: Facebook **Infer**, llvm-cov build, Bear, OSS-Fuzz corpus
seeds. `utils/`: Joern, Jacoco parser, lcov parser, javac wrapper,
clang AST parser, custom libFuzzer wrapper engine, sandboxed-Python
runner.

### 8.6 Models

Per-agent map in `configs/models-*.toml`. The default
(`models-anthropic.toml`) routes:
- POV/patch/triage/branch-flip/dynamic-debug → `claude-3-7-sonnet` /
  `claude-sonnet-4` (fallback `claude-3-5-sonnet`).
- Classifiers (LikelyVuln, LikelyFlippable, Dedup) → `azure/gpt-4.1`
  ("classifiers only work with openai" per inline comment).
- Function summaries / encoders / kaitai → `claude-3-5-sonnet`.

Multi-provider is *required*: classifier agents are pinned to OpenAI,
the rest are pinned to Anthropic. This is a deliberate cost/quality
mix, not a fallback chain.

### 8.7 Operational surface

- HTTP API on `:1324` (`POST /v1/task/`).
- Docker Compose for local; Terraform/Azure for cloud.
- Per-task SQLite DB on host volume (`./data`); resets via
  `docker compose down -v`.
- Logs to `./logs`; React `agent-log-viewer` renders agent traces.
- No interactive shell, no TUI, no operator-facing CLI beyond curl.

### 8.8 License

**AGPL-3.0** (vs. Kuzushi's MIT). Code-level absorption is
incompatible with Kuzushi's license. Patterns, architecture, and
documented techniques can be re-implemented; agent prompts and
algorithms can be referenced as public prior art.

---

## 9. Where RoboDuck exceeds Kuzushi

These are concrete capability gaps where RoboDuck has shipped
production code and Kuzushi has nothing or only a stub.

1. **Real fuzzing.** libFuzzer + Jazzer harness orchestration,
   corpus management, minset, crash bucketing, dedup, frontier
   tracking. Kuzushi has no `fuzz` module. This is the *core*
   technique RoboDuck is built around.
2. **Coverage-driven loops.** LLVM-cov + Jacoco, with a reachability
   graph and Dijkstra-based path finding from harness entry to a
   target line. Kuzushi has no coverage subsystem.
3. **Branch flipping.** A novel, AFC-distinctive technique:
   coverage frontier → "what input flips this branch?" → LLM proposes
   bytes, validates against `query_coverage` tool. RoboDuck explicitly
   markets this as their alternative to symbolic execution. There is
   nothing comparable in Kuzushi.
4. **Harness input encoder/decoder agents.** LLM-written Python
   encoder *for the harness's binary input format*, plus a paired
   decoder, so subsequent agents can craft inputs symbolically. This
   is what lets the rest of the pipeline operate on structured input
   without a fuzzer corpus seeding it. Kuzushi has nothing.
5. **Kaitai-Struct grammar synthesis.** When the harness consumes a
   format with no public spec, an LLM generates a Kaitai grammar, and
   then the encoder uses it. Kuzushi has nothing.
6. **Dynamic debug agent.** LLM stepping through gdb / jdb on real
   binaries with breakpoints, register dumps, variable inspection.
   Kuzushi has no live-debugger surface.
7. **Patch gauntlet.** `PatcherAgent` builds the project, runs
   functionality tests, retests POVs, and rolls back on failure.
   Kuzushi's `patch:finding` exists but is not as deeply integrated
   with project build + test matrices.
8. **Static analysis with Infer.** Production Facebook Infer
   integration for C/C++. Kuzushi ships Semgrep + CodeQL, not Infer.
9. **POV production as a first-class loop.** RoboDuck's
   `pov_producer` synthesises a *runnable crash input* validated
   against the actual fuzz harness. Kuzushi's `verify:finding` is
   conceptually adjacent but does not target fuzzer-driven crash
   reproduction.
10. **Per-agent multi-provider model mix.** Agent-X on Claude, Agent-Y
    on GPT-4.1 — by deliberate design (classifiers on OpenAI, reasoners
    on Anthropic). Kuzushi enforces no-silent-fallback but the polish
    of "this agent must run on this provider" is less developed.
11. **Production-tested at AFC scale.** Designed to spend $1k+/hr,
    proved viable on real OSS-Fuzz targets in the AIxCC Finals.
    Kuzushi has no equivalent stress-test on record.
12. **HTTP task ingest.** Programmatic submission with basic-auth,
    persistent SQLite product DB, async work queue. Kuzushi runs
    scans CLI-style; there is no daemon-facing API.
13. **OSS-Fuzz-native.** Accepts any OSS-Fuzz project directory as
    input — instant compatibility with hundreds of upstream targets.
    Kuzushi has no OSS-Fuzz adapter.

---

## 10. Where Kuzushi exceeds RoboDuck

RoboDuck was built for one job (CRS for AIxCC). Kuzushi is a
general-purpose security toolkit. The asymmetry runs the opposite
direction in everything *outside* fuzz-harness-bound vulnerability
discovery.

1. **Scope breadth.** Kuzushi has 29+ modules covering SAST, taint,
   secrets, SCA, IaC, recon, browser-RCE, variant/n-day, vendor
   assessment, compliance (NIST/PASTA), prompt-injection testing,
   threat modeling, x-ray pre-audit. RoboDuck does fuzz-driven
   POV+patch on C/C++/JVM and nothing else.
2. **Language coverage.** Kuzushi works on any language Semgrep /
   CodeQL / tree-sitter cover, plus LLM-driven analysis for
   everything else. RoboDuck is C / C++ / JVM only.
3. **Operator surfaces.** scan + shell + run modes; a Rust Ratatui
   TUI with 19 views; conversational `AgentChat`; replay/trace from
   per-run artefacts. RoboDuck has none of this — it's a daemon.
4. **Threat modeling.** STRIDE/DFD/scope generation as editable
   artefacts plus an actor-scoped agent hunt (`carlini-threat-hunt`).
   RoboDuck has no threat-modelling phase; it has "reachable from
   harness?" and that is its threat model.
5. **Extensibility.** `defineModule` / `defineTool` / `defineDagTool`
   authoring helpers, four load specifiers (`builtin:` / `file://` /
   `package:` / `mcp:`), `kuzushi/testing` mocks, MCP bridge.
   RoboDuck has 17 hard-coded agents and one prompt YAML.
6. **Governance and observability.** No-silent-fallback enforcement,
   per-tool model resolution, JSONL audit trail, `costBudgetUsd`
   halt, prompt overrides at `.kuzushi/prompts/<id>/<verb>.md`
   layered with `taskConfig` and shell datastore. RoboDuck has a
   per-agent model map and a single `prompts/default.yaml`.
7. **Out-of-fuzz reasoning surfaces.** Vendor assessment, x-ray
   pre-audit reports, prompt-armor LLM jailbreak testing, n-day
   variant hunting (`ndiff`), Pashov-style audit reports, Shinsa
   NIST scans. None of these exist in RoboDuck — they are entirely
   outside its design centre.
8. **License.** Kuzushi is **MIT**. RoboDuck is **AGPL-3.0**. For a
   commercial AppSec tool, MIT is a feature.
9. **Cost surface.** Per-tool cost, session cost, `/cost` view,
   budget halt. RoboDuck warns "this can spend $1000/hr" — that is
   the cost story.

---

## 11. What Kuzushi could ethically borrow

License-aware: AGPL-3.0 means no copy-paste of RoboDuck source
into Kuzushi's MIT tree. Patterns, architecture, named techniques,
and documented behaviour are fair game as prior art. Re-implement
in Kuzushi's idiom from scratch.

In rough priority order:

1. **A `fuzzing` module family.** OSS-Fuzz adapter + libFuzzer /
   Jazzer harness runner + corpus / minset / crash bucketing.
   Single largest gap vs. RoboDuck. Closes the "we don't actually
   run anything" weakness in `verify:finding` for native targets.
2. **A `coverage` module.** LLVM-cov + Jacoco wrappers exposing a
   reachability graph that other modules (taint, agentic-sast,
   verify) can consult. Kuzushi has Joern via `taint-iris-next`
   but no runtime coverage.
3. **A POV-producer agent.** Crash-input synthesis loop that
   targets a known-vulnerable function. Could live inside `verify`
   or be its own `pov-producer` module. Reduces FP rate by forcing
   exploitability proof.
4. **A patch gauntlet.** Extend `patch:finding` with build + test
   + POV-retest before claiming success. RoboDuck's
   `PatcherAgent.test_patch` is a clean reference design.
5. **Branch-flipper as an agentic-sast detector.** Take a
   coverage frontier + a candidate sink, ask the LLM "what input
   flips this?" Useful even outside fuzz harnesses (CTFs,
   focused-target hunts).
6. **Harness-input encoder/decoder pattern.** When verifying
   findings against a target with structured input (protocol,
   binary format, RPC), have the LLM write a Python encoder so
   subsequent verify steps stay in symbolic Python. The Kaitai
   grammar synthesis pattern is a generalisable trick.
7. **Dynamic-debug-agent surface.** A `debug` module that exposes
   gdb / jdb / lldb step/breakpoint/inspect tools. Could live
   under `verify` or be its own module. Useful when static
   analysis is inconclusive.
8. **Per-agent multi-provider model strategy.** RoboDuck's
   "classifiers must be OpenAI, reasoners must be Anthropic"
   pattern is a real engineering result. Kuzushi's
   no-silent-fallback enforcement is the *safety* half; RoboDuck's
   per-agent provider pinning is the *ergonomics* half. Combining
   them would be unique.
9. **Infer integration.** Add a `infer` module alongside `semgrep`
   and `codeql`. Strong on C/C++ memory safety where Semgrep is
   weak.
10. **OSS-Fuzz adapter.** A `kuzushi scan` mode that ingests an
    OSS-Fuzz `project.yaml` + `Dockerfile` + `build.sh` and emits
    Kuzushi findings. Lets Kuzushi piggy-back on hundreds of
    upstream targets.

Items 1–4 together would reposition Kuzushi from "static-analysis
agent" to "actually runs the bug" for native targets — closing the
single biggest credibility gap with both Xint (which claims
multistage verification) and RoboDuck (which proves it).

---

## 12. Sources

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

Public material on RoboDuck (Theori AIxCC Finals CRS, AGPL-3.0):

- [theori-io/aixcc-afc-archive](https://github.com/theori-io/aixcc-afc-archive) — Finals release source.
- [theori-io/aixcc-asc-archive](https://github.com/theori-io/aixcc-asc-archive) — Semifinals release source.
- [theori-io/aixcc-public](https://github.com/theori-io/aixcc-public) — Public results, agent traces, Branch Flipper whitepaper.
- [Theori — DARPA AIxCC landing page](https://theori-io.github.io/aixcc-public/index.html)
- [AI Cyber Challenge and Theori's RoboDuck (Theori blog)](https://theori.io/blog/aixcc-and-roboduck-63447)
- [DARPA — AI Cyber Challenge results (2025-08)](https://www.darpa.mil/news/2025/aixcc-results)
- [aixcc-afc-archive `docs/crs-architecture.md`](https://github.com/theori-io/aixcc-afc-archive/blob/main/docs/crs-architecture.md)

Kuzushi material (this repo at `ec9f8f4`):

- `CLAUDE.md` (mode parity, model safety, module system).
- `docs/modules.md` (authoring guide).
- `docs/assessments/mode-parity.md`, `output-reporting.md`,
  `configurability-gaps.md`, `new-modules.md`.
- `src/modules/`, `src/agents/index.ts`, `src/agent-runtime/`,
  `src/modules/mcp-bridge.ts`, `crates/kuzushi-tui/src/app.rs`.
