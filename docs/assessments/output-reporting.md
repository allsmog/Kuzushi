# Output & reporting — operational-weakness assessment

> Audit date: 2026-04-30. Scope: PR comment, CI stream, finding/chain
> shape, evidence pack metadata, finding aliases. Reviewer perspective:
> "I'm a SOC analyst / PR reviewer who has never run Kuzushi — does the
> artefact help me do my job?"
>
> Status note: this is a historical TypeScript-era audit. The Rust
> PR-comment path now renders diff-scoped findings, alias deep links,
> truncation notes, CWE columns, evidence previews, and exploit-chain story
> sections from `result.json`. The Rust scan event path emits structured
> elapsed-time CI lines from `crates/kuzushi-cli/src/presentation/scan_ci.rs`,
> including summary, error, and exit lines. Rust `run.json`/`summary.json` now
> carry available reproducibility metadata: Kuzushi version, platform,
> optional build-provided git identifiers, target git metadata, model, config
> hash slots, prompt/house-rule digests, threat-model digest, and environment
> fingerprints. The Rust PR-comment CLI reads that metadata for footer stamps
> when `--run-id` is supplied, and uses recorded LLM audit calls for per-phase
> cost hints.

## Top-10 operational weaknesses

| #  | Where                                   | Current behaviour                                                                                                                  | What's missing                                                                                                                                  | Confidence |
| -- | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| 1  | `src/report-pr-comment.ts:32-54`        | Historical TypeScript issue; Rust PR comments now render a "New in this PR" section from diff-scoped input while preserving stable global aliases. | Keep coverage in `findings/presentation/pr_comment/tests.rs::diff_section_preserves_global_stable_aliases`.                                     | resolved   |
| 2  | `src/report-pr-comment.ts:83-98`        | Historical TypeScript issue; Rust PR comments include alias deep links, CWE, location, evidence preview rows, and optional remediation hints when producers provide them. | Keep improving fix guidance quality at producer boundaries.                                                                                       | resolved   |
| 3  | `src/report-pr-comment.ts:32`           | Historical TypeScript issue; Rust PR comments include explicit top-N truncation notes.                                             | Keep top-N behavior visible in footer coverage.                                                                                                  | resolved   |
| 4  | `src/report-pr-comment.ts:67-81`        | Historical TypeScript issue; Rust PR comments group recorded LLM audit cost by phase when run metadata is available.               | Keep `pr_comment_tests.rs` coverage for phase-cost extraction from `run.json`.                                                                    | resolved   |
| 5  | `src/report-pr-comment.ts` (no chains)  | Historical TypeScript issue; Rust PR comments render exploit-chain story sections from `result.json`.                              | Continue improving chain narratives as producers add richer step evidence.                                                                        | resolved   |
| 6  | `src/ui/ci-stream.ts:88-90`             | Historical TypeScript issue; `src/ui/ci-stream.ts` is deleted. Rust CI output now uses elapsed timestamps from a captured `Instant`. | Keep `crates/kuzushi-cli/src/tests.rs::ci_line_uses_relative_timestamp_and_prefix` covering the structured prefix.                              | resolved   |
| 7  | `src/ui/ci-stream.ts:77-83`             | Historical TypeScript issue; the Rust scan CI path emits `summary:`, `error:`, and `exit:` lines.                                  | Continue enriching result bodies from canonical run artifacts as scan/report metadata grows.                                                    | resolved   |
| 8  | `src/ui/state.ts:239-293` `ActionableFinding` | Historical TypeScript UI issue; current Rust findings have optional store IDs, fingerprints, CWE projection, proof state, verification, evidence, suppression, snooze, remediation, and reference metadata. | Keep lifecycle metadata surfaced through operator views as those workflows mature.                                                                | resolved   |
| 9  | `src/types.ts:307-318` `ExploitChain`   | Historical TypeScript issue; current schemas and Rust exploit-chain outputs carry optional `filePath` and `startLine` on steps.    | Keep direct step-location coverage in exploit-chain output and PR-comment tests.                                                                  | resolved   |
| 10 | `src/bus/workers/audit-worker.ts:94-107` `run.json` | Historical TypeScript issue; Rust `run.json`/`summary.json` now carry Kuzushi version, platform, build git IDs, target git metadata, model, config hash, prompt/house-rule digests, threat-model digest, environment fingerprints, and LLM audit calls when available. | Keep new reproducibility metadata reflected in `docs/architecture/kuzushi-artifacts.md` and Markdown reports.                                    | resolved   |

Lower-priority observations:
- Severity scoring is normalized in Rust report artifact summaries, so mixed
  scanner labels such as `ERROR`, `Warning`, `HIGH`, and `note` roll up into
  canonical `high`, `medium`, and `info` buckets. Keep producer-level severity
  enums narrow as scanner surfaces mature.
- `/since <ref>` does not affect `summary.json` — the "diff scope" only lives in the shell view.
- `run.json` is the machine-readable run metadata contract in
  `schemas/run.summary.schema.json`; richer per-artifact schemas should be
  added only for producer-declared artifacts or shared canonical files, not for
  retired synthesized snapshots.

## Sample current PR comment vs. proposed PR comment

### Current (top-of-tree, before this change)

```markdown
### 🔐 Kuzushi scan · `acme-api` · [run](https://ci.example/runs/7f3a)

**3** tp · **1** fp · 🔓 **1 exploitable**

💸 **$0.30** total · ⏱ 1m 30s · 🧪 2 PoCs · 🧬 4 variants

| # | Severity | Title | Location |
|---|----------|-------|----------|
| F-0001 | 🟥 CRIT | ssrf on /admin/fetch | `src/api/admin.ts:88` |
| F-0002 | 🟧 HIGH | deser on upload queue | `src/worker/queue.ts:55` |

<sub>Generated by [Kuzushi](https://github.com/allsmog/Kuzushi). Findings truncated to top 10.</sub>
```

Issues a reviewer hits:
- Two findings, eleven words of context. Not enough to act on.
- No way to know which of these are *new in this PR*.
- `🔐` and `💸` are decorative; the alias column is just the index.
- No remediation, no CWE, no rationale snippet.
- The exploit chain that linked `admin.ts:88 → queue.ts:55` is invisible.

### Proposed

```markdown
### Kuzushi security scan · `acme-api` · [run](https://ci.example/runs/7f3a)

🟥 **1 critical** · 🟧 **1 high** · 🔓 **1 exploitable** · 🆕 **1 new in this PR**

`triage $0.10 · verify $0.20 · poc $0.00` — total **$0.30** in 1m 30s

#### 🔗 Exploit chain (1)

**C-01 · CRIT · 2 steps** — Unauthenticated SSRF on `/admin/fetch` lets an
external attacker stage a payload that the upload queue then deserialises
under worker creds.

1. **entry** `src/api/admin.ts:88` — SSRF on `/admin/fetch` (F-0001)
2. **sink**  `src/worker/queue.ts:55` — Deserialisation in upload queue (F-0002)

> **Impact:** RCE as the worker process. **Preconditions:** none.

#### 🆕 New in this PR (1)

| ID | Severity | CWE | Title | Location |
|----|---------|-----|-------|----------|
| [F-0001](https://ci.example/runs/7f3a#F-0001) | 🟥 CRIT | CWE-918 | ssrf on /admin/fetch | `src/api/admin.ts:88` |

> Validate that the URL host is on an allow-list before fetch; reject
> private-IP / link-local ranges; drop `Authorization` on cross-origin redirects.

#### Top findings (2 of 2)

| ID | Severity | CWE | Title | Location |
|----|---------|-----|-------|----------|
| [F-0001](https://ci.example/runs/7f3a#F-0001) | 🟥 CRIT | CWE-918 | ssrf on /admin/fetch | `src/api/admin.ts:88` |
| [F-0002](https://ci.example/runs/7f3a#F-0002) | 🟧 HIGH | CWE-502 | deser on upload queue | `src/worker/queue.ts:55` |

<sub>Generated by [Kuzushi 0.20.0](https://github.com/allsmog/Kuzushi) · run `7f3a` · model `claude-sonnet-4-6` · git `a1b2c3d`. Showing top 10; 0 truncated.</sub>
```

What changed:
- Counts split by severity bucket — reviewer sees the shape immediately.
- Per-phase cost broken out so cost spikes are debuggable.
- "Exploit chain" section tells the *story* before drowning the reviewer in a table.
- "New in this PR" section is the lead when scoped to a diff (`opts.changedFiles`).
- Each row links to a deep anchor on the run dashboard.
- Per-finding remediation hint when the finding has one.
- Footer cites version + git sha for reproducibility.

## Sample current CI stream vs. proposed CI stream

### Current

```
[2026-04-30T14:20:01Z] scan: acme-api started
[2026-04-30T14:20:01Z] phase: (init) → scanning
[2026-04-30T14:20:12Z] stage: scan → done [8.3s]
[2026-04-30T14:21:20Z] summary: 3 tp · 1 fp · $0.30 · 78.0s
```

Issues:
- No exit-code-equivalent line, so a CI parser can't disambiguate "scan finished cleanly" from "scan finished with criticals".
- `failedTasks` never surfaces.
- Timestamp is wall-clock at write — not the event time.
- No structured tag for `grep -E '^\[.*\] (error|fail|critical):'`.

### Proposed

```
[2026-04-30T14:20:01Z] scan: acme-api started run=7f3a kuzushi=0.20.0 model=claude-sonnet-4-6 git=a1b2c3d
[2026-04-30T14:20:01Z] phase: (init) → scanning
[2026-04-30T14:20:12Z] stage: scan → done [8.3s] (12 candidate findings)
[2026-04-30T14:20:45Z] finding: F-0001 tp critical CWE-918 src/api/admin.ts:88 ssrf on /admin/fetch
[2026-04-30T14:21:00Z] error: stage=verify task=verify-payload msg="rate limit; retried 2x"
[2026-04-30T14:21:20Z] summary: 1 critical · 1 high · 1 fp · $0.30 · 78.0s
[2026-04-30T14:21:20Z] result: fail (1 critical, 1 high) exit_hint=1
```

Each line is now greppable:

```bash
# all errors:
grep '^\[.*\] error:' build.log
# final verdict:
grep '^\[.*\] result:' build.log
# everything CRIT or HIGH:
grep -E '^\[.*\] finding:.*(critical|high)' build.log
```
