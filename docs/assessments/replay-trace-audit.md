# Replay / Trace / Audit — Critical Assessment

Status: 2026-04-30. Audits the on-disk artefacts under `.kuzushi/runs/<runId>/`,
the `pipeline_runs` SQLite table, and the verbs that consume them
(`/show runs`, `/replay`, `/trace`, `kuzushi runs list|show|compare`).
Some sample payloads preserve legacy TypeScript scan arguments for audit
context; they are not current Rust CLI examples.

The goal is to answer: **can an operator reproduce, query, diff, and prune
past runs from disk alone?**

---

## 1 · Inventory of what is persisted

### 1.1 Per-run dir — `.kuzushi/runs/<runId>/`

| File              | Producer                                | Trigger              | Always-on? |
| ----------------- | --------------------------------------- | -------------------- | ---------- |
| `scan.jsonl`      | `registerScanEventLog` (audit-worker)   | `scan:agent-activity`| **yes**    |
| `run.json`        | `registerAuditWorker`                   | `pipeline:start`     | gated on `auditLog` |
| `triage.jsonl`    | `registerAuditWorker`                   | `triage:*`           | gated on `auditLog` |
| `verify.jsonl`    | `registerAuditWorker`                   | `verification:*`     | gated on `auditLog` |
| `stats.json`      | `registerAuditWorker`                   | `pipeline:complete`  | gated on `auditLog` |
| `summary.json`    | _missing today_ — referenced in CLAUDE.md and mocks but never written | — | — |

### 1.2 SQLite — `.kuzushi/findings.sqlite3`

`pipeline_runs` row carries: `runId`, `repo`, `moduleId`, `toolName`,
`resumeLabel`, `startedAt`, `status`, `configJson`, `scanOptsJson`,
`findingsJson`, `contextJson`, `totalCostUsd`, `completedAt`, `updatedAt`,
`metricsJson`, `assertionsJson`, `promptHash`. Findings live in `findings`,
keyed by `fingerprint` and scoped to `repo` (not `runId`).

### 1.3 Field-level reproducibility / queryability gaps

| Field needed for "reproducible from disk alone" | Persisted today?                |
| ----------------------------------------------- | ------------------------------- |
| `runId` / `startedAt` / `completedAt`           | yes (sqlite + run.json)         |
| `status` / `totalCostUsd`                       | yes (sqlite)                    |
| Full `KuzushiConfig`                            | yes (`configJson`, `run.json`)  |
| Resolved `ScanOpts`                             | yes (`scanOptsJson`, `run.json`) |
| **Kuzushi version**                             | **no**                          |
| **Effective model id** (post-resolution)        | **no** — only inside config blob |
| **Agent runtime backend**                       | inside config blob (not surfaced) |
| **Config hash** (post-CLI overlay)              | **no**                          |
| **Git sha + dirty flag** of the scanned repo    | **no**                          |
| **CLI invocation argv**                         | **no**                          |
| **Env vars that affected behaviour** (`KUZUSHI_*`) | **no**                       |
| **Prompt-override fingerprints** (`.kuzushi/prompts/`) | **no**                  |
| **House-rules fingerprints** (`.kuzushi/house-rules/`) | **no**                  |
| **Threat-model digest** (`.kuzushi/threat-model.json`) | **no**                  |
| **Loaded module specifiers** (`--load`, package paths) | **no**                  |
| Findings list                                   | yes (`findingsJson`)            |
| Per-event audit trail                           | partial — only when `--audit-log` |

Cross-run query story today: **shell-only**. No `kuzushi runs query`,
no `findings search` across runs. Operators can `grep` JSONL files but
they have heterogeneous shapes (one event per line, but the payload
shape varies by `eventType`).

There is no retention policy: `.kuzushi/runs/` grows forever. There is no
`runs prune`, no disk-budget. Tests under `tests/copilot/` exercise
`replay`/`trace` formatters but not retention or run-metadata roundtrip.

---

## 2 · Top 8 improvements

| # | Change                                                                                                       | Where                                                            | Confidence |
| - | ------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------- | ---------- |
| 1 | Write `summary.json` on every run with reproducibility metadata (kuzushi version, git sha, model, config hash, argv, prompt/house-rules fingerprints, finding counts). | `src/bus/workers/audit-worker.ts`, new `src/copilot/run-metadata.ts` | **high**   |
| 2 | Make `summary.json` always-on (decouple from `auditLog`); the gated triage/verify JSONL stay opt-in. | `src/bus/workers/audit-worker.ts:74`                              | **high**   |
| 3 | Add `kuzushi runs prune --older-than <duration>` and `--keep-last <n>`, with `--dry-run`. | new `src/cli/commands/runs-prune.ts`, wired in `src/cli.ts:1357`  | **high**   |
| 4 | Add `kuzushi runs diff <a> <b>` showing new / fixed / drifted findings (already had `compare-runs` for metrics; this is finding-set diff). | new `src/cli/commands/runs-diff.ts`, wired in `src/cli.ts`         | **high**   |
| 5 | Improve `/show runs` to surface duration, finding count, status; add `--status` filter parity with `kuzushi runs list`. | `src/copilot/replay.ts:44`, `src/copilot/shell.ts:7141`           | **high**   |
| 6 | Add `--json` and `--all` flags to `/trace` for jq-friendliness (one stable-shape event per line). | `src/copilot/replay.ts`, `src/copilot/shell.ts:7189`              | **high**   |
| 7 | Add `kuzushi runs replay <runId> --json` and `kuzushi runs trace <runId> [--json]` so the same affordances exist outside the shell. | `src/cli.ts` (under `runsCmd`)                                    | **high**   |
| 8 | Persist `kuzushiVersion` + `gitSha` columns on `pipeline_runs` so SQL-level queries don't need to join JSONL. | new migration `src/migrations/107_*.ts`, `src/store.ts:53`         | medium — schema migration touches every existing DB |

Out-of-scope but worth mentioning:

- **Resumability** is already implemented via `pipeline_runs.contextJson`
  + `findingsJson` checkpoints (`hasRunCheckpoint`, `getLatestResumableRun`)
  and exercised by `--resume`. Not changed here.
- **External tooling**: the JSONL is already line-delimited; once
  improvement 6 lands, it's directly consumable by Splunk/Elastic.

---

## 3 · Run-metadata schema proposal — `summary.json` v1

```jsonc
{
  "schemaVersion": 1,
  "runId": "2026-04-30-7f3a1b2c",
  "status": "complete",                       // pipeline_runs.status
  "startedAt": "2026-04-30T14:20:12.000Z",
  "completedAt": "2026-04-30T14:28:54.000Z",
  "durationMs": 522000,
  "totalCostUsd": 0.4231,

  // Reproducibility — every field needed to re-run the same scan
  "reproducibility": {
    "kuzushiVersion": "0.20.0",               // from package.json
    "kuzushiCommit": "abc123e",               // optional: dist-time git sha
    "model": "anthropic:claude-opus-4-7",     // ctx.config.model post-CLI overlay
    "agentRuntimeBackend": "claude",
    "configHash": "sha256:1f4a…",             // hash of the post-overlay KuzushiConfig
    "scanArgs": ["./repo", "--preset", "deep"],
    "envFingerprint": {                       // only KUZUSHI_* / *_API_KEY presence
      "KUZUSHI_DEBUG": "1",
      "ANTHROPIC_API_KEY": "<set>"
    },
    "git": {
      "sha": "f00d1234…",
      "branch": "main",
      "dirty": false
    },
    "promptOverrides": [                      // sha256 of every .kuzushi/prompts/<m>/<v>.md
      { "module": "core-sast", "verb": "triage", "sha256": "…" }
    ],
    "houseRules": [                           // sha256 of every .kuzushi/house-rules/<m>.md
      { "module": "randori", "sha256": "…" }
    ],
    "threatModelSha256": "…",                 // .kuzushi/threat-model.json digest
    "loadedModules": ["builtin:core-sast", "file:///abs/path"]
  },

  // Findings — denormalised summary, full list still in findings.sqlite3
  "findings": {
    "total": 17,
    "bySeverity": { "critical": 1, "high": 4, "medium": 8, "low": 4 },
    "byVerdict":  { "tp": 9, "fp": 3, "needs_more_info": 5 }
  },

  // Repo identity
  "repo": {
    "root": "/abs/path/to/repo",
    "name": "acme-api"
  }
}
```

Old runs without `summary.json` continue to work — readers fall back to
`run.json` + `pipeline_runs` for everything except `reproducibility`. New
fields are additive; nothing in the v0 schema is renamed or removed.

---

## 4 · Diff design — `kuzushi runs diff <a> <b>`

Reads `pipeline_runs.findingsJson` for both runs, fingerprint-keys them,
emits four sets:

- **new** — fingerprint present in B, absent from A
- **fixed** — fingerprint present in A, absent from B
- **drifted** — same fingerprint, differing `verdict` / `displaySeverity` / `confidence`
- **stable** — count only

Output is a plain table by default and a structured JSON object under
`--json` so it composes with `jq`.

---

## 5 · Cleanup design — `kuzushi runs prune`

Two retention strategies (operator picks one):

- `--older-than <duration>` — `7d`, `30d`, `12h`. Wall-clock vs. `startedAt`.
- `--keep-last <n>` — preserves N most recent runs per repo.

Implementation deletes the run dir under `.kuzushi/runs/<runId>/` and the
matching `pipeline_runs` row. `--dry-run` lists what would be deleted.
Default behaviour skips runs in active state (`scanning` / `running` /
`triaging` / `verifying`) for safety.
