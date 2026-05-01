# Output & reporting — operational-weakness assessment

> Audit date: 2026-04-30. Scope: PR comment, CI stream, finding/chain
> shape, evidence pack metadata, finding aliases. Reviewer perspective:
> "I'm a SOC analyst / PR reviewer who has never run Kuzushi — does the
> artefact help me do my job?"

## Top-10 operational weaknesses

| #  | Where                                   | Current behaviour                                                                                                                  | What's missing                                                                                                                                  | Confidence |
| -- | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| 1  | `src/report-pr-comment.ts:32-54`        | Header → counts → cost → table. No diff-aware "new in this PR" section even though `/since` exists.                                | A `newSinceRef`/`changedFiles` scope so `buildPrComment` can render a "🆕 New in this PR" lead block above the global table.                    | high       |
| 2  | `src/report-pr-comment.ts:83-98`        | Findings table = severity / title / location only. No CWE, no rationale snippet, no remediation hint, no per-finding link to run. | Add CWE column when known; one-line rationale below each row; hyperlink the alias to `runUrl#F-NNNN`; emit code-block of file path, language-tagged. | high       |
| 3  | `src/report-pr-comment.ts:32`           | Top-N truncation hardcoded "and the rest are dropped on the floor".                                                                | Append a "+ N more findings" footer line so reviewers know the table is truncated and where to read the rest.                                   | high       |
| 4  | `src/report-pr-comment.ts:67-81`        | Cost line lumps `triage + verify + poc + variant`. Reviewer can't see where the spend went.                                        | Surface per-phase spend when > 0; show triage / verify / poc as `$x.xx triage · $y.yy verify`.                                                  | medium     |
| 5  | `src/report-pr-comment.ts` (no chains)  | Exploit chains never make it into the PR comment, despite being the highest-value output of a Kuzushi run.                         | Add a chain section above the findings table when `summary.exploitChains.length > 0`, rendered as the **story**: entry → step → impact.        | high       |
| 6  | `src/ui/ci-stream.ts:88-90`             | Timestamp is `new Date().toISOString()` at write time, not the event timestamp. Replays / OOO events look wrong.                   | Prefer `state.summary?.runStartedAt` / event timestamp when available; keep wall-clock as fallback.                                             | medium     |
| 7  | `src/ui/ci-stream.ts:77-83`             | End summary is the only "final" line. No exit-code line, no failure-mode line, no `failedTasks` enumeration.                       | Emit a final `result:` line with verdict counts + exit hint, and a per-failed-task `error:` line, both prefixed with a structured tag a CI grep can latch onto. | high       |
| 8  | `src/ui/state.ts:239-293` `ActionableFinding` | No stable `id` separate from `fingerprint`, no `suppressed`/`snoozedUntil`, no `remediation` hint, no `cwe[]`, no link to a guide. | Add optional `id`, `cwe`, `remediation`, `references[]`, `suppressed`, `snoozedUntil`, `firstSeenAt`. All optional → backwards-compatible.        | high       |
| 9  | `src/types.ts:307-318` `ExploitChain`   | Steps lack `filePath` / `startLine` so the renderer has to dereference each fingerprint to draw the path.                          | Add optional `filePath` and `startLine` on each step — keep fingerprint as the canonical join key; `narrative` summary at top level.            | medium     |
| 10 | `src/bus/workers/audit-worker.ts:94-107` `run.json` | Persists `runId`, `context`, `config`, `scanOpts` but no `kuzushiVersion`, `gitSha`, `model`, `configHash`. Triage analyst three weeks later can't reproduce. | Compute and store `kuzushiVersion`, `gitSha`, `gitBranch`, `model`, `configHash` (sha256 of canonical config JSON), `nodeVersion`, `platform`. | high       |

Lower-priority observations, not addressed in this PR but noted:
- Severity scoring is inconsistent across modules (some use `critical` lowercase, some `CRITICAL` uppercase, scanners emit `severity: string` with no enum). Worth documenting + adding a normalizer.
- `/since <ref>` does not affect `summary.json` — the "diff scope" only lives in the shell view.
- No machine-readable schema for `summary.json` — operators have to read TypeScript to know the shape.

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
