export { runMigrations } from "./runner.js";
export type { Migration } from "./types.js";

import { migration100 } from "./100_schema_reset.js";
import { migration101 } from "./101_workspace_entities.js";
import { migration102 } from "./102_session_aliases.js";
import { migration103 } from "./103_schedules.js";
import { migration104 } from "./104_workspace_integrity_guards.js";
import { migration105 } from "./105_finding_actor_fingerprint.js";
import { migration106 } from "./106_pipeline_resume_metadata.js";
import { migration107 } from "./107_pipeline_runs_branch_pr.js";
import type { Migration } from "./types.js";

/**
 * All registered migrations for fresh databases.
 *
 * Legacy migrations 001–025 live in `./_legacy/` as historical reference;
 * they are not imported here. Pre-v100 user databases are migrated by the
 * reset branch in `initDb()`, which renames the old file to
 * `findings.sqlite3.bak-v<N>-<UTC-ts>` and re-opens a fresh DB that v100
 * populates. See `docs/data-model/03-migration-hygiene.md`.
 */
export const allMigrations: Migration[] = [
  migration100,
  migration101,
  migration102,
  migration103,
  migration104,
  migration105,
  migration106,
  migration107,
];
