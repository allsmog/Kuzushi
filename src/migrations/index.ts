export type { Migration } from "./types.js";
export { runMigrations } from "./runner.js";

import { migration001 } from "./001_initial_schema.js";
import { migration002 } from "./002_add_scanner_column.js";
import { migration003 } from "./003_add_triage_cost_column.js";
import { migration004 } from "./004_add_triage_details_column.js";
import { migration005 } from "./005_add_verification_columns.js";
import { migration006 } from "./006_add_poc_harness_columns.js";
import { migration007 } from "./007_add_poc_execution_columns.js";
import { migration008 } from "./008_pipeline_runs_status_values.js";
import { migration009 } from "./009_add_pipeline_runs_context.js";
import { migration010 } from "./010_add_calibration_schema.js";
import { migration011 } from "./011_add_trajectories_table.js";
import { migration012 } from "./012_add_finding_provenance_columns.js";
import type { Migration } from "./types.js";

/** All registered migrations in version order. */
export const allMigrations: Migration[] = [
  migration001,
  migration002,
  migration003,
  migration004,
  migration005,
  migration006,
  migration007,
  migration008,
  migration009,
  migration010,
  migration011,
  migration012,
];
