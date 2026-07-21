# Kuzushi Roadmap — Path to World-Class

This roadmap started from the June 2026 deep audit and is maintained against
the live Rust product. The status snapshot below was reconciled on 2026-07-12;
code, tests, release workflows, and the npm registry remain the source of truth.

## North star

> The local-first evidence workbench where every finding carries verified
> evidence, an honest proof state, and a defensible next action — and the
> detection quality is a published number, not a claim.

**World-class, measurably:**

| Metric | Today | World-class |
| --- | --- | --- |
| `npm install -g kuzushi` installs the documented product | Native `0.24.0-alpha.6`; the repo is one alpha ahead | ✅ current release on all supported platforms |
| Findings with repo-verified evidence (span + content hash) | Producer-dependent, with unverified states surfaced honestly | 100% of persisted findings |
| "Exploitable: confirmed" backed by runtime proof | Runtime-verified is reserved for proof level 4 | Preserve this invariant |
| Published detection numbers (TP/FP/cost) | `baseline.json` is `{}` | Scoreboard on real corpora + CWE-Bench-Java head-to-head |
| Stable finding identity across runs/toolchains | Durable target-scoped `fp3`; evidence-free findings still use a normalized text locator | Remove the remaining description-sensitive fallback |
| CI gating (`--fail-on`) + SARIF from the CLI | ✅ implemented and documented | Preserve in reference CI |
| Incident-grade reliability bugs | Tracked by executable gates and run-state tests, not a stale prose count | 0 open release blockers |

---

## Phase 0 — Ship the product that exists 🔴
**Goal: a stranger can install and run what the README describes.**
*~1–2 weeks. Nothing else matters while this is red.*

- [ ] **P0.1 Keep the native npm release current.** Registry `latest` is the
  native `0.24.0-alpha.6`; this tree is `0.24.0-alpha.8`. Publish the current
  alpha only after its release gates are green.
  *Exit: `npm i -g kuzushi && kuzushi doctor` matches README on a clean machine.*
- [ ] **P0.2 Finish cross-platform release hardening.** `release.yml` now
  builds and stages Linux, macOS, and Windows binaries into the npm tarball;
  several matrix legs remain best-effort. Promote them to required after a
  green tagged release, then add the installer/Homebrew distribution path.
  *Exit: install succeeds on linux-x64, darwin-arm64, darwin-x64, win32-x64.*
- [ ] **P0.3 Reduce the default bridge dependency footprint.** The former
  GitHub-only Randori dependency is gone. LangChain and bridge dependencies
  remain in the default install; make them an explicit runtime extra without
  weakening the retained TypeScript module SDK.
  *Exit: zero `github:` specifiers in the dependency graph; install < 30s, no native compile.*
- [x] **P0.4 CI gating semantics.** `kuzushi scan --fail-on <severity>` and
  `--sarif <path>` are implemented, documented, and covered by the reference
  workflow and scan-gate tests.
  *Exit: a GitHub Actions job fails on a high-severity finding and uploads SARIF to Code Scanning.*
- [ ] **P0.5 Finish the trust kit.** The README now states the local-first,
  zero-first-party-telemetry promise and release publishing supports npm
  provenance. Make provenance the default and keep release/security examples
  synchronized through executable documentation checks.
  *Exit: a security engineer's 10-minute diligence pass finds no incoherence.*
- [x] **P0.6 First-run wow, offline.** `kuzushi demo` scans a bundled fixture
  without a key, model, or external scanner, persists honest `signal_only`
  evidence, and hands the operator to the real findings workflow. Default scan
  output also reports skipped engines and their reasons.
  *Exit: install → demo finding with evidence in < 90 seconds, offline.*

## Phase 1 — Make the evidence promise true 🔴
**Goal: "evidence, not chat" is enforced by the type system and persistence layer, not by hope.**
*~4–6 weeks. This is the moat; everything in Phase 3 is unpublishable without it.*

- [ ] **P1.1 Validated evidence at the persistence boundary.** Today
  `Finding::new_tool()` creates findings with empty evidence and persistence
  accepts them; LLM hunters' file/line citations are never checked against
  the repo. Only Semgrep findings get span-extraction + content-hash
  (`index_semgrep_findings_as_static_evidence.rs`). Extend that path to
  **every** tool: extract `SourceSpan`, pin `content_hash`, store on
  `FindingEvidence`. Citations that fail validation → finding persists as
  `evidence_unverified` and renders visibly degraded.
  *Exit: zero findings persist with unverified file/line claims; fabricated citations are caught at insert time (test: agent emits fake line → finding marked degraded).*
- [ ] **P1.2 Finish stable finding identity.** The old `DefaultHasher` path has
  been replaced by target-scoped `fp3` identity. Findings with validated
  evidence use normalized evidence content, but evidence-free findings still
  fall back to normalized title/message text. Replace that last
  description-sensitive locator and retain migration coverage.
  *Exit: same bug, different LLM phrasing → same fingerprint; fingerprints byte-identical across Rust versions.*
- [ ] **P1.3 Dedup that actually dedups.** Findings without an extractable CWE
  get `dedup_key = None` and bypass cross-engine merge entirely
  (`findings/domain/extract_cwe.rs`); dedup_key is scan-scoped so re-running
  any scanner duplicates everything. Make dedup keys CWE-independent
  (fall back to file+bucket) and add cross-scan dedup against prior runs.
  *Exit: running agentic-sast twice yields zero duplicate rows; semgrep + agentic reporting the same location merge regardless of CWE extraction.*
- [ ] **P1.4 Fail-loud structured output.** Unparseable LLM tool args become
  `{}` (`scripts/langgraph-bridge/oauth-models.mjs:178`); failed triage parses
  fall through `.ok()` to confidence-0.0; corrupted persisted verdicts
  deserialize to `NotReproduced` via `unwrap_or`
  (`findings/persistence/open/triage_and_verification.rs:91`). Replace every
  silent fallback on the verdict path with a typed `ParseDegraded` error
  surfaced in trace + finding provenance.
  *Exit: grep for `unwrap_or`/`.ok()`/`return {}` on LLM-output and verdict paths returns only documented, surfaced degradations.*
- [ ] **P1.5 Reliability triad** (incident-grade, all on the critical path):
  - Bridge: wall-clock timeout + kill on `wait_with_output()`
    (`kuzushi-openai/src/langgraph_runtime/bridge_process.rs:78`), stdin
    deadline in the bridge, retry coverage for `next_step_blocking`
    (one transient 429 currently kills a 10-step agent loop), MCP partial
    degradation instead of whole-query failure.
  - Findings store: WAL + `busy_timeout` + transaction-wrapped
    `insert_finding` (collision-check → upsert → DELETE+INSERT evidence are
    separate statements today; `FindingStore` has no Mutex — copy the
    `SpendLimiter` pattern from `spend/as_db_str.rs`).
  - Atomic writes: one `write_json_atomic` (temp+rename) helper replacing
    direct `fs::write` of `options.json` / `attachments.json` / `run.json`;
    add `.kuzushi/runs/` retention.
  *Exit: kill -9 during a concurrent scan corrupts nothing; a hung bridge surfaces as a timeout error within 5 minutes.*

## Phase 2 — Honest verification by default 🟠
**Goal: the proof ladder means what it says; LLM opinion can never masquerade as runtime proof.**
*~4–8 weeks, overlaps Phase 1.*

- [ ] **P2.1 Cap LLM verification below "confirmed".** `verify:finding` is
  LLM-opinion-only (no execution) yet returns `exploitable=true` that reads
  as confirmation; `verify:exploit` (real harness + sandbox + crash-signal
  classification) is never suggested by the pipeline. Cap `verify:finding`
  at static proof states; reserve "confirmed/exploited" for crash-backed
  proof level 4; rename operator-facing surfaces ("LLM assessment" vs
  "runtime proof").
  *Exit: it is impossible for a finding to display "exploitable: confirmed" without a PoV artifact on disk.*
- [ ] **P2.2 Consensus by default.** `verify_consensus.rs` machinery is
  bypassed at the default `passes=1`. Default LLM verification to 3 passes
  (strict-majority, ties → not-exploitable is already correct).
  *Exit: single-pass LLM verdicts no longer exist on the default path.*
- [ ] **P2.3 Audit the silent kills.** Prefilter drops findings below
  threshold with no record (`modules/triage/run_triage.rs` —
  `prefilter_triage_findings` silently discards); harness-synthesis fallback
  ("payload-only" harness that never calls the suspect function) exits
  cleanly and reads as NotReproduced. Log every drop with reason; mark
  payload-only harness results as `HarnessIncomplete`, never `NotReproduced`.
  *Exit: every finding that entered triage can be accounted for in the run artifacts.*
- [ ] **P2.4 Auto-chain the ladder.** After triage TP + LLM-verify
  exploitable, the pipeline proposes `verify:exploit` (and in `--ci`,
  reports the gap explicitly: "confirmed-by-LLM, runtime proof pending").
  *Exit: the golden path surfaces the next proof step without operator memory.*
- [ ] **P2.5 Strengthen the PoV engine.** Study/borrow from the open-source
  AIxCC systems (Trail of Bits **Buttercup** — Apache, libFuzzer/Jazzer +
  LLM test-case generation) for harness synthesis breadth; adopt ARVO-style
  reproduce-at-revision artifacts (triggering input + rebuildable harness
  stored with the finding).
  *Exit: a proof-level-4 finding ships with a third-party-reproducible artifact.*
- [ ] **P2.6 Hunter citation hygiene.** Always-on citation validation for
  agentic-sast/carlini/systems-hunt (today only whitebox-static mode checks
  snippets); structured evidence tuples (source, sink, guard, path) instead
  of freeform "evidence" strings; deep-auditor escalation for high-severity
  agentic findings.
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
  real baseline.
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
  prototype; pwn/HTB is roadmap). The golden path —
  *scan → validated evidence → honest triage → runtime proof → patch → report*
  — must be bulletproof before breadth grows.
- [ ] **P4.4 Engineering hygiene track** (parallel, ongoing): split
  `modules/pwn/mod.rs` (2,327 LOC); split the mixed-language route detector
  (`workspace/inventory/inspect_python_route_line.rs` — 1,543 LOC, covered by
  route integration tests in `workspace/inventory/tests.rs`); add focused
  offense planner/persistence tests; centralize model price tables (two stale
  hardcoded copies); bridge protocol-version handshake; macOS sandbox
  honesty in doctor (no bwrap → say so and clamp).

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
