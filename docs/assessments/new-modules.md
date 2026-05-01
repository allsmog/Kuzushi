# New Built-in Modules — Assessment

_Snapshot: 2026-04-30 against `main`. Companion to GAPS.md._

This document audits the current built-in CopilotModule catalog and proposes
the next batch of modules to ship. The goal is to fill **real product gaps**
that operators expect from a security platform but Kuzushi currently lacks.

## What ships today

| ID | Category | Entry point | Notes |
|----|----------|-------------|-------|
| `sast` | defense | `core-sast.ts` | Umbrella — runs the full DAG |
| `semgrep` / `codeql` / `agentic-sast` / `taint-iris` / `threat-hunt` / `systems-hunt` / `triage` / `verify` / `patch` / `findings` / `context` / `pipeline` | defense | `*/` per submodule | The SAST family |
| `randori` / `tob` / `vuln-scout` / `shinsa` / `prompt-armor` | defense / governance | wraps Claude Code plugins | |
| `variant` | offense | `variant-hunter.ts` | LLM-guided 1-day spread |
| `ndiff` | intel | `n-day-diff-hunter.ts` | CVE/GHSA → variant hunt |
| `recon` | intel | `recon/core-recon.ts` | nmap / subdomain / http-fp |

## Gaps

Cross-checking against what operators expect from a security pipeline:

1. **No secret/credential scanner.** The codebase has logger redaction
   patterns (`sk-ant-`, `sk-`, `key-`, `AIza`) but no module that scans
   target repos for committed secrets. Every comparable platform
   (gitleaks, trufflehog, GitHub Advanced Security, Snyk) ships this on
   day one. Glaring omission.
2. **No IaC / config scanner.** Terraform misconfigurations,
   Dockerfile lints (`USER root`, `:latest` tags), permissive k8s
   manifests, GitHub Actions workflow risks (`pull_request_target` +
   checkout of PR head, etc.) — none covered.
3. **No SBOM / dependency-graph extractor.** `vuln-scout` probes for
   CVEs in deps via a Claude Code plugin, but there's no first-class
   "produce a normalized dependency graph + license inventory" tool that
   downstream modules (license risk, supply-chain) could consume.
4. **No license-risk module.** GPL contamination, missing `LICENSE`
   files, SPDX header drift — all unhandled.

## Top picks

Ranked by impact-per-hour:

| # | Module | Why | Cost |
|---|--------|-----|------|
| 1 | `secret-scan` | Closes a **glaring omission**. Deterministic regex + entropy detection produces real findings on real fixtures with no LLM cost. Independent of every other module. | small |
| 2 | `iac-scan` | High operator demand. Deterministic rule pack. Can ship a starter rule set (Dockerfile + GitHub Actions) and grow it. | medium |
| 3 | `license-scan` | Lower urgency than 1/2 but pure governance value. Deterministic, fast. | small |

## Decision

Ship **`secret-scan` end-to-end** (manifest + module + tests + fixtures +
wired into `createDefaultDagRegistry` for opt-in via shell `/use`).

Scaffold **`iac-scan` as manifest-only** with a TODO pointing at the next
PR. Do not wire into `createDefaultDagRegistry` until the rule pack is
written.

## `secret-scan` — design

- **ID:** `secret-scan`, **category:** `defense`, **rank:** `great`.
- **Tool:** `secret-scan:scan` — pure `ModuleTool` (not a `DagTool`).
  Walks the target directory, applies a curated regex pack to text
  files, and returns `Finding[]` plus a human-readable summary.
- **Detectors:** AWS access keys (`AKIA...`), AWS secret-access-key
  candidates (entropy-gated), GitHub PATs (`ghp_...`, `ghs_...`,
  `gho_...`, `ghu_...`, `ghr_...`), Slack tokens (`xox[bopars]-...`),
  Stripe live/test keys (`sk_live_`, `pk_live_`, `sk_test_`, `pk_test_`),
  Google API keys (`AIza...`), Anthropic keys (`sk-ant-...`), generic
  OpenAI keys (`sk-...` with high entropy), JWT (`eyJ...`-formatted),
  PEM private keys (`-----BEGIN ... PRIVATE KEY-----`), generic
  high-entropy assignments to suspicious variable names.
- **Filtering:** skips `.git/`, `node_modules/`, `vendor/`, common
  binary extensions, files >2MB. Honors per-finding entropy threshold
  for high-FP-risk patterns.
- **Output:** `Finding[]` with stable fingerprints (`secret-scan:<rule>:<path>:<line>:<digest>`),
  severity by rule, evidence quoting the matched line with the secret
  redacted to its first 4 chars + `***`.
- **No LLM dependency.** Runs in `kuzushi run` headless, in the shell
  via `/use secret-scan; run`, and (later) as a DAG node when wired in.
- **Model usage:** none. The deterministic detection means no
  `enforceAgentQuery` boundary to cross.

## `iac-scan` — manifest-only stub

- **ID:** `iac-scan`, **category:** `defense`.
- **Planned tools:** `iac-scan:dockerfile`, `iac-scan:github-actions`,
  `iac-scan:terraform`.
- **Status:** manifest + factory stub returning a `not-implemented`
  ToolResult with a pointer at the next PR. Not wired into
  `createDefaultDagRegistry` or `loadBuiltinModule`.
