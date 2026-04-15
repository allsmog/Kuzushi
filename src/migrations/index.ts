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
import { migration013 } from "./013_add_composite_confidence_columns.js";
import { migration014 } from "./014_add_metrics_column.js";
import { migration015 } from "./015_add_assertion_tracking.js";
import { migration016 } from "./016_add_structured_finding_evidence.js";
import { migration017 } from "./017_add_dynamic_and_patch_persistence.js";
import { migration018 } from "./018_add_crypto_behavioral_runs.js";
import { migration019 } from "./019_add_code_graph_tables.js";
import { migration020 } from "./020_add_verified_patch_status.js";
import { migration021 } from "./021_add_incremental_scanning_support.js";
import { migration022 } from "./022_add_verdict_index.js";
import { migration023 } from "./023_expand_pipeline_status_constraint.js";
import { migration024 } from "./024_rename_scanner_to_task_id.js";
import { migration025 } from "./025_add_workspaces_table.js";
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
  migration013,
  migration014,
  migration015,
  migration016,
  migration017,
  migration018,
  migration019,
  migration020,
  migration021,
  migration022,
  migration023,
  migration024,
  migration025,
];
