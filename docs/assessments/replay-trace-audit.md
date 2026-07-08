# Replay / Trace / Audit — Critical Assessment

Status: Rust-current replay/trace assessment. Rust scan, shell tool
dispatch, and headless `kuzushi run` write shared `.kuzushi/v3/runs/<runId>/`
artifacts; older design examples below are retained only where explicitly
marked as proposals.

The goal is to answer: **can an operator reproduce, query, diff, and prune
past runs from disk alone?**

---

## 1 · Inventory of what is persisted

### 1.1 Per-run dir — `.kuzushi/v3/runs/<runId>/`

| File              | Producer                                | Trigger              | Always-on? |
| ----------------- | --------------------------------------- | -------------------- | ---------- |
| `run.json`        | Rust run artifact substrate             | scan/tool run start and completion | **yes** |
| `summary.json`    | Rust run artifact substrate             | scan/tool run start and completion | **yes** |
| `events.jsonl`    | Rust run events                         | scan/tool lifecycle  | **yes** |
| `trace.jsonl`     | Rust `TraceHandle` / TUI broadcast sink | traced tool/runtime steps | **yes** |
| `input.json`      | Rust tool-run recorder                  | prepared direct tool input | tool runs |
| `result.json`     | Rust tool-run recorder                  | direct tool result envelope | tool runs |
| `failures.json`   | Rust failure handoff writer             | run start / failed tool output | **yes** |
| `report.md`       | report producer or placeholder writer   | run start / report output | **yes** |
| `report.sarif`    | optional SARIF-capable producers        | producer output      | optional |
| `artifacts.json`  | Rust artifact manifest writer           | artifact registration | **yes** |
| producer-declared sidecars | individual tool producers | explicit artifact declaration | optional |

### 1.2 SQLite — `.kuzushi/v3/index.sqlite3`

The Rust findings store carries finding rows and supporting workspace state.
Run-level reproducibility and trace data live under `.kuzushi/v3/runs/<runId>/`;
CLI and TUI replay surfaces consume that on-disk format directly.

### 1.3 Field-level reproducibility / queryability gaps

| Field needed for "reproducible from disk alone" | Persisted today?                |
| ----------------------------------------------- | ------------------------------- |
| `runId` / `startedAt` / `completedAt`           | yes (`run.json` / `summary.json`) |
| `status` / `totalCostUsd`                       | yes (`run.json` / `summary.json`) |
| Full `KuzushiConfig`                            | no full dump; config hash is recorded |
| Resolved scan/tool input                        | yes (`input.json` / `result.json` where available) |
| **Kuzushi version**                             | yes (`kuzushiVersion`)           |
| **Effective model id** (post-resolution)        | yes when configured or emitted by runtime metadata |
| **Agent runtime backend**                       | partial; provider/runtime are present in LLM audit entries |
| **Config hash** (post-CLI overlay)              | yes (`configHash`)               |
| **Git sha + dirty flag** of the scanned repo    | yes in Rust `run.json` / `summary.json` as `targetGit` when target is a git worktree |
| **CLI invocation argv**                         | yes (`cliArgs`, bounded and redacted) |
| **Env vars that affected behaviour** (`KUZUSHI_*`) | yes in Rust `run.json` / `summary.json` as hashes or `<set>` for secret-looking keys |
| **Prompt-override fingerprints** (`.kuzushi/prompts/`) | yes in Rust `run.json` / `summary.json` when present |
| **House-rules fingerprints** (`.kuzushi/house-rules/`) | yes in Rust `run.json` / `summary.json` when present |
| **Threat-model digest** (`.kuzushi/threat-model.json`) | yes in Rust `run.json` / `summary.json` when present |
| **Loaded module specifiers** (`--load`, package paths) | yes (`loadedModules`; Rust static registry entries are recorded as `builtin:<id>`) |
| Findings list                                   | yes (v3 findings projection; some producers may also declare JSON exports) |
| Per-event audit trail                           | yes (`events.jsonl`, `trace.jsonl`) |

Cross-run query story today: **shell-only**. No `kuzushi runs query`,
no `findings search` across runs. Operators can `grep` JSONL files but
they have heterogeneous shapes (one event per line, but the payload
shape varies by `eventType`).

Retention is now operator-controlled through `kuzushi runs prune` with
`--older-than-days`, `--keep-last`, and `--dry-run`. The command deletes only
safe run-id directories, repairs `.kuzushi/v3/latest`, and is covered by focused
Rust CLI tests. A disk-budget policy is still future work.

---

## 2 · Top 8 improvements

| # | Change                                                                                                       | Where                                                            | Confidence |
| - | ------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------- | ---------- |
| 1 | Keep `summary.json` always-on with reproducibility metadata. Rust now covers version, platform, build git ids, target git metadata, model, config hash, LLM-call metadata, bounded/redacted CLI argv, env fingerprints, prompt override fingerprints, house-rules fingerprints, and threat-model digest. | `crates/kuzushi-core/src/run_artifacts/` | **high** |
| 2 | Keep the small canonical run bundle always-on and independent of optional producer output. Domain snapshots are explicit artifacts or result-envelope data, not synthesized leaves. | `crates/kuzushi-core/src/run_artifacts/` | **high** |
| 3 | Add `kuzushi runs prune --older-than-days <n>` and `--keep-last <n>`, with `--dry-run`. Implemented in Rust with safe run-id checks and `.kuzushi/v3/latest` repair. | `crates/kuzushi-cli/src/application/runs.rs` | **high** |
| 4 | Add `kuzushi runs diff <a> <b>` showing new / fixed / drifted findings. Implemented in Rust against declared finding exports when present, with plain and JSON output. | `crates/kuzushi-cli/src/application/runs_diff.rs` | **high** |
| 5 | Improve `/show runs` to surface duration, finding count, status. Rust CLI `kuzushi runs list` and `kuzushi runs show` now show completed-run duration; `kuzushi runs list --status <status[,status]>` filters by run status with explicit status validation. | `crates/kuzushi-tui/src/ui_view_models/run_trace.rs`, `crates/kuzushi-cli/src/application/runs.rs`, and `crates/kuzushi-cli/src/presentation/runs_output.rs` | **high** |
| 6 | Keep `kuzushi runs trace <runId> --json` jq-friendly and consider an `--all` variant only if trace/event files diverge. | `crates/kuzushi-cli/src/application/runs.rs` | **high** |
| 7 | Shell `/replay <runId>` and `/trace <runId>` should keep consuming the same `.kuzushi/v3/runs/<runId>/` artifacts as CLI `kuzushi runs show/trace`. | `crates/kuzushi-tui/src/ui_view_models/run_trace.rs` | **high** |
| 8 | If SQL-level run queries become product scope, add Rust migrations for selected run metadata instead of reintroducing retired store paths. | future Rust persistence migration | medium |

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

  // Findings — denormalised summary, full list still in index.sqlite3
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

## 4 · Diff surface — `kuzushi runs diff <a> <b>`

Reads declared finding exports for both runs when producers provide them,
fingerprint-keys the finding snapshots, and emits four sets:

- **new** — fingerprint present in B, absent from A
- **fixed** — fingerprint present in A, absent from B
- **drifted** — same fingerprint, differing `verdict` / `displaySeverity` / `severity` / `confidence`
- **stable** — count only

Output is a plain table by default and a structured JSON object under
`--json` so it composes with `jq`.

---

## 5 · Cleanup surface — `kuzushi runs prune`

Two retention strategies are implemented and can be combined:

- `--older-than-days <n>` — wall-clock retention against run `startedAt`.
- `--keep-last <n>` — preserves N most recent runs per repo.

Implementation deletes the run dir under `.kuzushi/v3/runs/<runId>/` and the
latest pointer is repaired to the newest remaining run, or removed when no runs
remain. `--dry-run` lists what would be deleted without touching disk. The
implementation refuses unsafe run ids containing empty, relative, or path
separator components before deletion.
