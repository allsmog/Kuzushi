# Column Ownership Matrix — Phase A Coordination

Seed doc for the 5 parallel research agents working on the data-model cleanup (plan: `/home/node/.claude/plans/ok-i-want-to-synchronous-crescent.md`).

## Ownership by dimension

Each agent owns one dimension across ALL tables. Every column has five owners — one per dimension.

| Dimension | Owner | Questions it answers |
|---|---|---|
| Naming + type-shape (DB↔TS boundary) | **Agent 1** | What is this column called in SQL vs TS? Which TS type maps to this row? |
| Liveness (kept vs dropped) | **Agent 2** | Is this column actually read and written by live code? Can it be dropped? |
| Migration mechanics + reset | **Agent 3** | How does the v100 reset work? What's the migration style guide? |
| Constraints (CHECK, NOT NULL, UNIQUE, FK) | **Agent 4** | What DB-level integrity rules apply to this column? |
| Normalization (JSON vs relational, snapshot vs live) | **Agent 5** | Does this column belong as a scalar, as a relational join, or as JSON? Should this table split/merge? |

## Tables in scope

All tables in `/workspaces/Kuzushi/src/store.ts` + the per-module stores + `schema_version`:

| Table | Source file | Migration |
|---|---|---|
| `findings` | `src/store.ts` | 001 + additive 002–024 |
| `pipeline_runs` | `src/store.ts` | 001 + 008, 009, 014, 015, 023 |
| `calibration_weights` | `src/store.ts` | 010 |
| `trajectories` | `src/trajectory-memory.ts` | 011 |
| `finding_assertions` | `src/store.ts` | 015 |
| `dynamic_analysis_runs` | `src/store/dynamic-analysis.ts` | 017, 020 |
| `patch_results` | `src/store/patch-results.ts` | 017, 020 |
| `crypto_behavioral_runs` | `src/store/crypto-behavioral.ts` | 018 |
| `code_graph_nodes` | `src/agents/tasks/code-graph/store.ts` | 019 |
| `code_graph_edges` | same | 019 |
| `code_graph_paths` | same | 019 |
| `workspaces` | `src/workspace/manager.ts` | 025 |
| `workspace_snapshots` | same | 025 |
| `schema_version` | `src/migrations/runner.ts` | bookkeeping |
| `intel_documents` + `intel_fts` | `src/intel/store.ts` | ad-hoc (NOT in migrations) |

## Conflict resolution

Decisions interact. Examples:

- Agent 2 flags `adjusted_score` as "written once, never read meaningfully" → drop. Agent 5 independently flags it as denormalization of `score`. **These agree.** No conflict.
- Agent 2 flags `triage_details_json` as "only read in one narrow code path" → drop. Agent 5 proposes extracting fields from it into relational columns. **Conflict:** extraction wins over drop, because extracted data is live.
- Agent 4 specifies a CHECK constraint on a column Agent 2 proposes dropping. **No conflict:** if A2 drops it in Phase B, A4's constraint simply doesn't apply.
- Agent 1 proposes renaming `triage_cost_usd` → `triage_cost`. Agent 5 proposes merging `triage_cost_usd` + `verify_cost_usd` + `poc_*_cost_usd` into a normalized `finding_costs` side-table. **Conflict:** A5 structural change wins; A1's naming rule applies to the new table.

**Process:** each agent flags cross-dimension observations in a `## Cross-cutting observations` section of their doc. Do NOT resolve other agents' dimensions. The main thread resolves in Phase B using the precedence: **A5 (structural) > A2 (liveness) > A4 (constraints) > A1 (naming) > A3 (mechanics)**.

## Constraints on Phase A agents

- **No code edits.** Agents are READ-ONLY on `/workspaces/Kuzushi/src/` and `/workspaces/Kuzushi/tests/`.
- **No new migration files** under `src/migrations/`. Draft SQL goes inside the assessment doc.
- **Only writes allowed** are to `/workspaces/Kuzushi/docs/data-model/0N-<topic>.md` (the agent's own assessment doc).
- Cite evidence with `path/to/file.ts:lineno` so the main thread can verify.
- Each doc ends with a `## Draft SQL` section containing proposed `CREATE TABLE` / `ALTER` / etc. for the v100 fresh schema.
