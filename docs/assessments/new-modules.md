# New built-in module assessment — 2026-04-30

This assessment proposes 1–3 new `CopilotModule`s for Kuzushi that fill
real product gaps. The recommended ship lands in this PR; the deferred
candidate is left as a manifest-only scaffold pointing at the next PR.

## 1. Inventory of currently-shipped modules

Source: `src/agents/index.ts` (`createDefaultTaskRegistry`) and
`src/modules/*` (every file with `defineModule(...)` or factory
`create*Module()`).

| Module id        | Category   | Coverage summary                                                                 |
| ---------------- | ---------- | -------------------------------------------------------------------------------- |
| `sast`           | defense    | Umbrella DAG: scanners → triage → verify → patch.                                |
| `agentic-sast`   | defense    | LLM-driven detection sub-tasks (incl. in-source `secrets-crypto-detect`).        |
| `semgrep`        | defense    | Semgrep ruleset runner.                                                          |
| `codeql`         | defense    | CodeQL DB build + query runner.                                                  |
| `taint-iris`     | defense    | LLM taint analysis with CWE pre-selection.                                       |
| `triage`         | defense    | Per-finding LLM triage (TP / FP / NR).                                           |
| `verify`         | defense    | Exploit-attempt verification of triaged findings.                                |
| `patch`          | defense    | Patch synthesis for confirmed findings.                                          |
| `findings`       | defense    | Findings list / lookup / list-aliases.                                           |
| `context`        | defense    | Repo / file-index / app-model / module catalog DAG nodes.                        |
| `pipeline`       | defense    | Hidden orchestrator-only DAG nodes.                                              |
| `threat-hunt`    | offense    | Per-actor agent fan-out for threat-model-driven hunting.                         |
| `randori`        | intel      | PASTA threat model build via Claude Code plugin subprocess.                      |
| `systems-hunt`   | offense    | Cross-binary / systems-level vulnerability hunting.                              |
| `recon`          | offense    | Recon (hosts/services/ports) for blackbox flows.                                 |
| `vuln-scout`     | offense    | Plugin-fan-out whitebox pentest.                                                 |
| `tob`            | defense    | Trail-of-Bits skills audit (plugin-fan-out).                                     |
| `ndiff`          | intel      | CVE/GHSA → fix-shape signature → variant hunt.                                   |
| `variant`        | intel      | Variant analysis around a confirmed finding.                                     |
| `prompt-armor`   | offense    | LLM red-teaming wrapper.                                                         |
| `shinsa`         | governance | Compliance (ISO 27001, NIST 800-53).                                             |

### What's NOT covered

- **Git history secret discovery.** The in-tree `secrets-crypto-detect`
  is an LLM in-source detector — it scans the working tree only. Leaked
  secrets that were committed historically and later "removed" remain in
  `git log` and on every clone. No module reads commit history.
- **IaC misconfiguration.** Terraform / Kubernetes / Dockerfile drift
  from least-privilege has no module. (`agentic-sast`'s LLM detectors
  occasionally pick this up, but only on files in the working tree and
  only as a side effect.)
- **Dependency-vuln triage with reachability.** `vuln-scout` exists as a
  plugin fan-out, but no module reads `npm audit` / `pip-audit` JSON and
  filters by whether the vulnerable function is actually imported /
  reachable from a repo entry point.
- **Authn/authz route mapping.** Identifying anonymous-accessible
  endpoints in a web framework is not done by any current module.
- **License-compliance auditing.** No module.
- **LLM-app-specific attack surface mapping** (prompt-injection sinks,
  tool-use abuse paths). `prompt-armor` is offensive (red-team), not
  defensive (sink mapping).

## 2. Three candidate proposals

### Candidate A — `secrets-history`

**Persona.** Red-teamer (pre-engagement enumeration), appsec engineer
(quarterly audit), DevSecOps (pre-merge gate).

**Gap caught.** Existing detector misses:
- Secrets committed in past commits and later removed from `HEAD`.
- Secrets in non-source files added historically (config dumps, env
  bundles, ops scripts).
- Shape-specific provider tokens that need exact regex (Stripe, AWS,
  GitHub PATs, Slack bots, OpenAI sk-…), not LLM judgement.

**Sizing.** ≤ 600 LOC. Pure logic: shell out to `git rev-list` + `git
show`, regex over diff hunks, score with Shannon entropy. No LLM in the
hot path.

**Reject criteria.**
- Operator persona: ✅ all three above.
- Failure mode no other module catches: ✅ history coverage.
- Shippable in ≤ 1500 LOC: ✅ ~500–600.
- Fits `<moduleId>:<action>` shape: ✅ `secrets-history:scan`.
- Host-internal changes needed: ❌ none.

### Candidate B — `iac-misconfig`

**Persona.** DevSecOps lead, platform engineer, compliance lead.

**Gap caught.** Terraform `aws_s3_bucket { acl = "public-read" }`,
Kubernetes `securityContext: { runAsUser: 0 }`, Dockerfile `USER root`
+ `chmod 777`. Detected via static rules + LLM "is this risk
operationally accepted in this repo?" pass.

**Sizing.** ≤ 1200 LOC. Two phases: (1) deterministic rule pack,
(2) LLM contextual triage that reads the repo README / threat-model and
suppresses environments where the misconfig is acceptable (e.g. a
demo app intentionally exposing a public S3 bucket).

**Reject criteria.**
- Operator persona: ✅.
- Failure mode: ✅ — agentic-sast occasionally finds these but only
  when the file is in working tree and an LLM happens to look at it.
  No deterministic pass exists.
- Shippable in ≤ 1500 LOC: ✅ tight but achievable for a v0.
- Fits shape: ✅.
- Host-internal changes: ❌ none.

### Candidate C — `dep-reach`

**Persona.** Appsec engineer, release engineer.

**Gap caught.** `npm audit` / `pip-audit` produce hundreds of advisories
on any non-trivial repo, the vast majority of which are non-reachable.
Existing modules do not consume the audit JSON directly nor cross it
against the repo's import graph.

**Sizing.** ~ 1000–1500 LOC for a useful first cut. Needs a small
language-aware import resolver per ecosystem (npm + pip), which adds
complexity. Strong feature but borderline for a one-PR ship without
risking quality.

**Reject criteria.**
- Operator persona: ✅.
- Failure mode: ✅.
- Shippable in ≤ 1500 LOC: ⚠ tight; risk of shipping a thin v0.
- Fits shape: ✅.
- Host-internal changes: ❌ none.

## 3. Final picks

**Ship now: `secrets-history`.** Highest leverage per LOC, deterministic
(no LLM cost in the hot path), no external dependencies (`git` is
already a host requirement), one tool (`secrets-history:scan`), output
is `Finding[]` so it composes with the existing triage / verify / patch
DAG out of the box. Real failure mode that no other module catches.

**Scaffold-only: `iac-misconfig`.** Shipped as a manifest-only stub with
a `// TODO(next-PR)` comment. Worth claiming the module id now to keep
the namespace clean and document intent without bloating this PR.

**Defer: `dep-reach`.** Real gap, but the language-aware import
resolution is a project of its own. Track in `GAPS.md` and ship as its
own focused PR.
