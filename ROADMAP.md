# Kuzushi Roadmap — Path to World-Class

This roadmap started from the June 2026 deep audit and is maintained against
the live Rust product. The status snapshot below was reconciled on 2026-08-28;
code, tests, release workflows, and the npm registry remain the source of truth.

> **Stale companion docs.** `docs/assessments/silent-verdict-fallback-audit.md`
> (2026-07-07) no longer describes the tree: F1, F2, F5, and F6 are fixed; F7 is
> fixed apart from one residual defensive read; F3 and F4 are half-fixed — the
> degradation is now recorded, the fallback value still is not. See P1.4.

## North star

> The local-first evidence workbench where every finding carries verified
> evidence, an honest proof state, and a defensible next action — and the
> detection quality is a published number, not a claim.

**World-class, measurably:**

| Metric | Today | World-class |
| --- | --- | --- |
| `npm install -g kuzushi` installs the documented product | Registry `latest` is `0.24.0-alpha.12`; this tree is the unpublished `0.24.0-alpha.14` candidate | ✅ current release on all supported platforms |
| Findings with repo-verified evidence (span + content hash) | Every persisted evidence item is disk-verified at insert and downgraded on failure (`findings/persistence/open/finding_evidence.rs`); the finding's own file/line is still unverified | 100% of persisted findings |
| "Exploitable: confirmed" backed by runtime proof | Runtime-verified is reserved for proof level 4 | Preserve this invariant |
| Published detection numbers (TP/FP/cost) | `baseline.json` is `{}` | Scoreboard on real corpora + CWE-Bench-Java head-to-head |
| Stable finding identity across runs/toolchains | Durable target-scoped `fp3`, now description-independent (`crates/kuzushi-core/src/findings/domain/finding_identity.rs`, test `evidence_free_identity_ignores_title_and_message_wording`) | ✅ preserve this invariant |
| CI gating (`--fail-on`) + SARIF from the CLI | ✅ implemented and documented | Preserve in reference CI |
| Incident-grade reliability bugs | Tracked by executable gates and run-state tests, not a stale prose count | 0 open release blockers |

---

## Phase 0 — Ship the product that exists 🔴
**Goal: a stranger can install and run what the README describes.**
*~1–2 weeks. Nothing else matters while this is red.*

> **CI status (2026-08-28):** the `quality-gauntlet` job has not started since
> 2026-08-14. Every run since then reports "the job was not started because an
> Actions budget is preventing further use", and `main` carries no required
> status checks. A release needs the account Actions spend cap lifted first.

- [ ] **P0.1 Keep the native npm release current.** Registry `latest` is
  `0.24.0-alpha.12`; this tree is the `0.24.0-alpha.14` candidate.
  `0.24.0-alpha.13` was a failed attempt and was never published. Publish only
  after the candidate gate is green; per the 2026-08-28 decision recorded in
  `RELEASING.md`, the repository-visibility gate blocks going public, not the
  release tag.
  *Exit: `npm i -g kuzushi && kuzushi doctor` matches README on a clean machine.*
- [ ] **P0.2 Prove cross-platform release hardening.** The candidate workflow
  requires native builds and local-tarball installs on Linux x64, Linux arm64,
  macOS x64, macOS arm64, and Windows x64. Record the first green Alpha14
  candidate before treating that contract as proven, then add the
  installer/Homebrew distribution path.
  *Exit: one candidate receipt proves install on all five supported targets.*
- [ ] **P0.3 Reduce the default bridge dependency footprint.** The former
  GitHub-only Randori dependency is gone. LangChain and bridge dependencies
  remain in the default install; make them an explicit runtime extra without
  weakening the brokered KWP worker protocol or LangGraph bridge.
  *Exit: zero `github:` specifiers in the dependency graph; install < 30s, no native compile.*
- [x] **P0.4 CI gating semantics.** `kuzushi scan --fail-on <severity>` and
  `--sarif <path>` are implemented, documented, and covered by the reference
  workflow and scan-gate tests.
  *Exit: a GitHub Actions job fails on a high-severity finding and uploads SARIF to Code Scanning.*
- [ ] **P0.5 Finish the trust kit.** The README now states the local-first,
  zero-first-party-telemetry promise, and release publishing supports npm
  provenance — but it is **opt-in** behind the repo variable `NPM_PROVENANCE`
  (`release.yml` ~line 80), so a normal release publishes without it. Make
  provenance unconditional, remove or replace the quarantined historical root
  artifacts (see the RELEASING.md visibility gate), and keep release/security examples synchronized
  through executable documentation checks.
  *Exit: a security engineer's 10-minute diligence pass finds no incoherence.*
- [x] **P0.6 First-run wow, offline.** `kuzushi demo` scans a bundled fixture
  without a key, model, or external scanner, persists honest `signal_only`
  evidence, and hands the operator to the real findings workflow. Default scan
  output also reports skipped engines and their reasons.
  *Exit: install → demo finding with evidence in < 90 seconds, offline.*

## Phase 1 — Make the evidence promise true 🔴
**Goal: "evidence, not chat" is enforced by the type system and persistence layer, not by hope.**
*~4–6 weeks. This is the moat; everything in Phase 3 is unpublishable without it.*

- [ ] **P1.1 Validated evidence at the persistence boundary.** Producer-agnostic
  citation verification now runs at insert for **every** tool: each persisted
  `FindingEvidence` item that structurally claims a source location is checked
  against the target on disk and downgraded to `reasoning` with a capped
  confidence and a citation note when the path, line, or snippet does not hold
  (`findings/persistence/open/finding_evidence.rs`, reached from both insert
  paths in `finding_writes.rs`). It fails closed — an unavailable target root
  downgrades rather than passes. Three gaps remain:
  (a) the finding's *own* `file_path`/`start_line` is not grounded at insert;
  `GroundingStatus` is stamped only on the import paths
  (`findings/import/ledger_jsonl.rs`, `capabilities/fuzz_engine/import.rs`) and
  by the explicit `findings:ground` capability.
  (b) zero-evidence findings still persist silently — nothing at the persistence
  boundary rejects or flags them.
  (c) `FindingEvidence` carries no content hash, so evidence authentication lives
  on the v3 observation `blob_hash` / byte span rather than on the evidence row.
  *Exit: zero findings persist with an unverified own-location claim; an evidence-free finding is visibly degraded.*
- [x] **P1.2 Finish stable finding identity.** The old `DefaultHasher` path was
  replaced by target-scoped `fp3` identity, and the last description-sensitive
  locator is gone: evidence-free identity no longer depends on title or message
  wording (`crates/kuzushi-core/src/findings/domain/finding_identity.rs`, test
  `evidence_free_identity_ignores_title_and_message_wording`).
  *Exit: same bug, different LLM phrasing → same fingerprint; fingerprints byte-identical across Rust versions.*
- [ ] **P1.3 Dedup that actually dedups.** Two of three pieces landed. CWE-less
  findings now fall back to a closed vulnerability-class key
  (`findings/domain/extract_cwe.rs` ~170-183), and repeated hunts converge on one
  durable identity across runs via `FindingIdentityMatchTier::DedupKeyCrossRun`
  (`findings/persistence/open/finding_identities.rs`). Gaps: a
  `FindingClass::Other` classification still yields `dedup_key = None` — a
  deliberate refusal, since a wildcard class would merge unrelated findings that
  merely share a line bucket; and rows are deliberately **not** merged across
  runs (only the identity is shared) so a per-run `--fail-on` gate stays honest.
  *Exit (supersedes "zero duplicate rows"): every finding gets a dedup key; the same defect re-observed shares one durable identity.*
- [ ] **P1.4 Fail-loud structured output.** Two named fallbacks are fixed: the
  bridge no longer coerces an unparseable provider event to `{}` — it throws
  `invalidProviderResponseError()` (`scripts/langgraph-bridge/oauth-models.mjs`)
  — and a corrupted persisted verdict now errors with
  `unknown persisted proof verdict …` instead of deserializing to
  `NotReproduced` (`findings/persistence/open/triage_and_verification.rs:302`).
  Three remain: patch gating reads `/data/exploitable` with `unwrap_or(false)`
  (`modules/application/sast_scan/run_sast_verification_and_patch.rs` ~245); an
  unparseable classifier-gate response still scores a neutral `0.5`
  (`capabilities/classifier_gate/application/likely_vuln_classifier.rs` ~146 —
  it records a runtime diagnostic, but the neutral score is not a typed
  degradation carried on the finding); and the deep auditor synthesizes a
  `triggerable: false @ 0.25` vote out of unparseable output
  (`capabilities/deep_auditor/application/parse_vuln_analysis.rs` ~27).
  Replace each with a typed `ParseDegraded` surfaced in trace + finding
  provenance.
  *Exit: grep for `unwrap_or`/`.ok()`/`return {}` on LLM-output and verdict paths returns only documented, surfaced degradations.*
- [ ] **P1.5 Reliability triad** (incident-grade, all on the critical path):
  - Bridge: ✅ wall-clock timeout + kill on the bridge process
    (`kuzushi-openai/src/langgraph_runtime/bridge_process.rs`) and retry coverage
    for `next_step_blocking` (`transport_retry.rs`, wired through
    `next_step_bridge.rs`), so a transient 429 no longer kills a 10-step agent
    loop. MCP failure is a **typed permanent** failure — `mcp_timeout` is
    explicitly excluded from transient classification (`runtime_impl.rs`).
    Decision 2026-08-28: keep that fail-loud rather than degrade to a partial
    answer, so "MCP partial degradation" is closed as won't-do, not outstanding.
  - Findings store: ✅ WAL + `busy_timeout(5s)`
    (`findings/persistence/open/connection_and_schema.rs`) and a
    transaction-wrapped `insert_finding` (`finding_writes.rs`). `FindingStore`
    still has no Mutex — by design: it is `Send` but not `Sync`, and
    thread-confinement is documented on the type (`finding_store.rs`).
  - Atomic writes: ✅ `fs_atomic::write_atomic` (temp+rename) plus run-artifact
    retention (`run_artifacts/run_retention.rs`, `prune_run_artifacts`).
  *Exit: kill -9 during a concurrent scan corrupts nothing; a hung bridge surfaces as a timeout error within 5 minutes.*

## Phase 2 — Honest verification by default 🟠
**Goal: the proof ladder means what it says; LLM opinion can never masquerade as runtime proof.**
*~4–8 weeks, overlaps Phase 1.*

- [ ] **P2.1 Cap LLM verification below "confirmed".** Mostly landed.
  `is_empirically_verified` now requires the bwrap backend, an `Exploited`
  verdict, and a validated reproducer
  (`findings/domain/persisted_results.rs:363`); a model verdict maps to
  `ProofLadderKind::ModelAssessed` → `ProofConfidence::Unverified`
  (`findings/presentation/detail/proof_ladder.rs`); and only a `Confirmed`
  runtime result renders `RUNTIME VERIFIED`. Remaining: a raw
  `exploitable: bool` is still emitted and still gates patching — K2/K3 in
  `docs/plans/exploitability-research-consolidated-plan.md`.
  *Exit: it is impossible for a finding to display "exploitable: confirmed" without a PoV artifact on disk.*
- [ ] **P2.2 Consensus by default.** `verify_consensus.rs` machinery is still
  bypassed at the default `passes = 1`
  (`verification/adapters/verify_finding_input.rs` ~106). Decision recorded
  2026-08-28: raise the default to 3 (strict-majority, ties → not-exploitable is
  already correct) **after** the verdict-vocabulary split in P2.1/K2, and ship it
  with an explicit cost note — three passes roughly triples per-finding
  verification spend.
  *Exit: single-pass LLM verdicts no longer exist on the default path.*
- [ ] **P2.3 Audit the silent kills.** Half done. A non-faithful (payload-only)
  harness now classifies as `NotAttempted`, never `NotReproduced`
  (`verification/classification/mod.rs:48`). The prefilter still reports only an
  aggregate: `prefilter_triage_findings` partitions and keeps
  `dropped: dropped.len()`, discarding the dropped findings themselves
  (`modules/triage/run_triage.rs` ~304-320).
  *Exit (revised): every dropped finding is named, with its reason, in the run artifacts.*
- [ ] **P2.4 Auto-chain the ladder.** After triage TP + LLM-verify
  exploitable, the pipeline proposes `verify:exploit` (and in `--ci`,
  reports the gap explicitly: "confirmed-by-LLM, runtime proof pending").
  Note 2026-08-28: the ladder's own next-step text points at the wrong verb —
  `ModelAssessed.next_step` in
  `findings/presentation/detail/proof_ladder_labels.rs` says "run verify:finding
  with a runtime-backed mode"; it should name `verify:exploit`.
  *Exit: the golden path surfaces the next proof step without operator memory.*
- [ ] **P2.5 Strengthen the PoV engine.** Study/borrow from the open-source
  AIxCC systems (Trail of Bits **Buttercup** — Apache, libFuzzer/Jazzer +
  LLM test-case generation) for harness synthesis breadth; adopt ARVO-style
  reproduce-at-revision artifacts (triggering input + rebuildable harness
  stored with the finding). Landed: `PersistedVerification.provenance.reproducer`
  — a content-store `ObjectRef` pinned to a `ProofSnapshot` — is now **required**
  for empirical verification (`findings/domain/persisted_results.rs`).
  *Exit: a proof-level-4 finding ships with a third-party-reproducible artifact.*
- [ ] **P2.6 Hunter citation hygiene.** Largely satisfied by P1.1: citation
  verification at insert is producer-agnostic, so agentic-sast / carlini /
  systems-hunt evidence is checked and downgraded like everything else — no
  longer whitebox-static-only. Remaining: structured evidence tuples
  (source, sink, guard, path) instead of freeform "evidence" strings, and
  deep-auditor escalation for high-severity agentic findings.
  *Exit: hunter findings with non-existent file/line never reach the store (they get `evidence_unverified` at worst).*

## Phase 3 — Prove it in public 🟠
**Goal: detection quality is a number anyone can check. This is the credibility bar in 2026.**
*~6–12 weeks, then continuous. Infrastructure mostly exists — it has never produced a real number.*

- [ ] **P3.1 Real benchmark runs.** The TypeScript scoring harness and its
  empty baseline were removed with the TS surface; the scoring path is now the
  Rust `kuzushi-eval` recall scorer plus `experiments/recall-eval/`. Run the
  vendored corpora (juice-shop, govwa, owasp-benchmark, cve-corpus) with real
  models; publish `benchmarks/SCOREBOARD.md` with the three numbers
  practitioners demand: **detection rate, false-positive rate,
  cost-per-finding**. Wire a detection-regression gate into CI against the
  real baseline. Status 2026-08-28: `benchmarks/SCOREBOARD.md` does not exist,
  and `experiments/recall-eval/reports/HISTORY.md` holds exactly one row — a
  scaffolded 2026-05-06 self-test against synthetic mini-slices at `$0.00`.
  Nothing has actually run.
  *Exit: SCOREBOARD.md in the repo with real-LLM provenance; CI fails on detection regression.*
- [ ] **P3.2 CWE-Bench-Java head-to-head.** 120 manually-validated real CVEs;
  the citable format is "X of 120 vs CodeQL's 27 / IRIS's 55." Kuzushi's
  taint-iris lineage makes this the natural arena.
  *Exit: a published, reproducible run with the harness checked in.*
- [ ] **P3.3 Real-world disclosures with disclosed FP rates.** Hunt real OSS,
  disclose responsibly, publish maintainer-confirmed findings **with the
  false-positive count** (post-curl-bounty-shutdown, disclosed FP rates are
  what separate tools from slop). OWASP Benchmark scores alone are a red flag.
  *Exit: ≥5 maintainer-confirmed findings with public FP accounting.*
- [ ] **P3.4 Docs split: adoption-facing vs internal.** `docs/` is dominated
  by self-assessments and port plans. User docs: Get Started / First triage
  walkthrough / CI integration (promote `kuzushi-reference.yml`) / SARIF →
  Code Scanning / Models & cost / Suppressions & baselines. Move working
  notes to `docs/internal/`. README gets a TUI screenshot/GIF before the
  26-row command table.
  *Exit: the documented golden path is the tested golden path.*

## Phase 4 — Win the wedge 🟡
**Goal: own "Caido/Burp for code" — the local-first evidence workbench nobody else is building.**
*Ongoing, after 0–2.*

- [ ] **P4.1 Position on the proven local-first model.** Nobody monetizes
  scanner CLIs (free-CLI → SaaS is universal; raw SAST is being deliberately
  commoditized by the Opengrep consortium). The only local-first tools with
  proven willingness-to-pay are workbenches-as-workflow (Burp $449/yr,
  Caido $35/mo). Kuzushi's TUI + proof ladder + replayable runs is already
  that shape — market it as the operator's daily evidence workbench, not as
  another scanner.
- [ ] **P4.2 Double down on unique capabilities:** bring-your-own-model with
  no-silent-fallback; local-first privacy as a stated guarantee; the
  bug-bounty operator loop (program scope files, Burp/HAR import,
  engagement-gated offense — genuinely unique); the audit trail
  (proof states + expiring suppressions + replay) for compliance buyers.
- [ ] **P4.3 Narrow the surface.** 42 modules / 121 tools, several half-real.
  Mark experimental what is experimental (exploit-chain is an LLM-narrative
  prototype; pwn/HTB is roadmap). Maturity tiering shipped:
  `docs/module-maturity.md` defines core / labs / compatibility, and `is_core()`
  filters the default catalog and guided surfaces
  (`modules/builtins/with_v2_builtins/lookup.rs`). `pwn` and `fuzz` are already
  `Labs`; remaining: classify `exploit-chain` and re-count the catalog. The
  golden path —
  *scan → validated evidence → honest triage → runtime proof → patch → report*
  — must be bulletproof before breadth grows.
- [ ] **P4.4 Engineering hygiene track** (parallel, ongoing): split
  `modules/pwn/mod.rs` — now ~2,980 LOC, up from 2,327, so this is getting worse,
  not better; split the mixed-language route detector
  (`workspace/inventory/inspect_python_route_line.rs` — ~1,538 LOC, covered by
  route integration tests in `workspace/inventory/tests.rs`); add focused
  offense planner/persistence tests; centralize model price tables (still two
  hardcoded copies — `kuzushi-openai/src/anthropic_oauth/response.rs` ~37 and
  `kuzushi-core/src/capabilities/full_mode_multi/application/chunk_prompt.rs`
  ~189). ✅ bridge protocol-version handshake
  (`modules/dynamic_loader.rs::validate_dynamic_host_handshake`); ✅ sandbox
  honesty in doctor — no bwrap/podman on PATH warns and names the unisolated
  Plain backend (`kuzushi-cli/src/doctor/checks.rs` ~202-228).

---

## What we are explicitly NOT doing (until the above is green)

- New scan engines or detection modules (breadth dilutes; the engines we
  have aren't measured yet).
- New TUI views/features beyond the golden path (the TUI audit fixes landed;
  it's good enough).
- SaaS/cloud anything (the wedge is local-first; revisit after Phase 3
  credibility exists).
- Broad pentest automation / binary exploitation as product surfaces
  (roadmap-only, per README's own product-focus statement).

## Sequencing at a glance

```
Weeks  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 …
P0     ████████
P1        ████████████████
P2              ████████████████████
P3                       ████████████████████████ → continuous
P4                                ████████████ → ongoing
```

Phase 0 and P1.5 (reliability triad) are parallelizable on day one.
P3.1 (real benchmark run) can start as soon as P1.1–P1.3 land — publishing
numbers before stable identity/dedup would measure noise.
