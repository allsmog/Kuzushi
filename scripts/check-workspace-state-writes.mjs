#!/usr/bin/env node

import { readFileSync } from "node:fs";
import path from "node:path";

const root = process.cwd();
const contracts = [
  ["crates/kuzushi-core/src/modules/context/attack_surface_routes.rs", "save_context_snapshot"],
  ["crates/kuzushi-core/src/modules/entry_points_module.rs", "write_entry_points_json"],
  ["crates/kuzushi-core/src/modules/threat_intel_module.rs", "write_candidates_payload"],
  ["crates/kuzushi-core/src/modules/pwn/mod.rs", "save_state"],
  ["crates/kuzushi-core/src/capabilities/scene_snapshots.rs", "write_scene_snapshot"],
  ["crates/kuzushi-core/src/capabilities/threat_leads/mod.rs", "write_threat_leads"],
  [
    "crates/kuzushi-core/src/capabilities/threat_intel/application/harvest_render.rs",
    "write_catalog_with_append",
  ],
  [
    "crates/kuzushi-core/src/capabilities/taint_iris_next/application/source_sink_discovery.rs",
    "persist_taint_iris_next_discovered_signals",
  ],
  [
    "crates/kuzushi-core/src/capabilities/uaf_hunt/persistence/store.rs",
    "write_uaf_hunt_transcript",
  ],
  [
    "crates/kuzushi-core/src/capabilities/vendor_assessment/application/storage.rs",
    "write_state_path",
  ],
  [
    "crates/kuzushi-core/src/suppressions/persistence/suppressions_file.rs",
    "save_suppression_rules",
  ],
  ["crates/kuzushi-core/src/proof/suppressions/suppression_store.rs", "save_whitebox_suppressions"],
  ["crates/kuzushi-core/src/workspace/tool_shelf.rs", "save_tool_shelf"],
  ["crates/kuzushi-cli/src/application/scan.rs", "write_scan_scope_file"],
  ["crates/kuzushi-tui/src/app/task_durations.rs", "save"],
  [
    "crates/kuzushi-tui/src/app/line_editor/is_word_char/history_persistence.rs",
    "write_history_file",
  ],
  ["crates/kuzushi-core/src/workspace/application/nested_scope.rs", "save_nested_project_scopes"],
  ["crates/kuzushi-core/src/workspace/application/project_model.rs", "save_project_model_document"],
  ["crates/kuzushi-core/src/attachments/reparse_source.rs", "save_store"],
  [
    "crates/kuzushi-core/src/workspace/application/load_program_scope.rs",
    "write_program_scope_scaffold",
  ],
  ["crates/kuzushi-core/src/options/option_store_persistence.rs", "save_to_path"],
  ["crates/kuzushi-core/src/config/config_file_io.rs", "write_config_body"],
  ["crates/kuzushi-core/src/run_artifacts/canonical_run_markers.rs", "write_marker_text"],
  ["crates/kuzushi-core/src/prompt_stack/mod.rs", "save_prompt_mutations"],
];

const readContracts = [
  ["crates/kuzushi-core/src/workspace/application/nested_scope.rs", "load_nested_project_scopes"],
  ["crates/kuzushi-core/src/workspace/application/project_model.rs", "load_project_model_document"],
  ["crates/kuzushi-core/src/attachments/reparse_source.rs", "load_store"],
  ["crates/kuzushi-core/src/workspace/application/load_program_scope.rs", "load_program_scope"],
  ["crates/kuzushi-core/src/options/option_store_persistence.rs", "load_from_path"],
  ["crates/kuzushi-core/src/config/config_file_io.rs", "read_optional_config"],
  ["crates/kuzushi-core/src/prompt_stack/mod.rs", "load_prompt_mutations"],
  ["crates/kuzushi-core/src/workspace/tool_shelf.rs", "load_tool_shelf"],
  ["crates/kuzushi-core/src/proof/suppressions/suppression_store.rs", "load_whitebox_suppressions"],
  [
    "crates/kuzushi-core/src/suppressions/persistence/suppressions_file.rs",
    "load_suppression_rules",
  ],
  ["crates/kuzushi-core/src/capabilities/scene_snapshots.rs", "read_scene_snapshot"],
  ["crates/kuzushi-core/src/run_artifacts/canonical_run_markers.rs", "read_marker_text"],
  ["crates/kuzushi-core/src/run_artifacts/run_events.rs", "next_event_number_from_path"],
  [
    "crates/kuzushi-tui/src/app/workspace_context/context_snapshot_views.rs",
    "load_context_snapshot_view",
  ],
  [
    "crates/kuzushi-tui/src/app/line_editor/is_word_char/history_persistence.rs",
    "load_persisted_history",
  ],
  ["crates/kuzushi-tui/src/app/task_durations.rs", "read_history"],
  [
    "crates/kuzushi-tui/src/app/prompts/tune_action_count/house_rules.rs",
    "house_rules_state_for_path",
  ],
  [
    "crates/kuzushi-tui/src/app/prompts/tune_action_count/prompt_edit_show.rs",
    "prompt_override_text",
  ],
];

const removalContracts = [
  [
    "crates/kuzushi-tui/src/app/prompts/tune_action_count/house_rules.rs",
    "remove_house_rules_file",
  ],
  [
    "crates/kuzushi-tui/src/app/prompts/tune_action_count/prompt_diff_reset.rs",
    "remove_prompt_override",
  ],
];

const rawWritePattern =
  /(?:std::)?fs::(?:write|create_dir_all)\s*\(|(?:File|OpenOptions)::(?:create|new)\s*\(|\.write_all\s*\(/;
const rawReadPattern =
  /(?:std::)?fs::(?:read|read_to_string|metadata)\s*\(|(?:File|OpenOptions)::open\s*\(|\.exists\s*\(/;

function functionBody(source, functionName) {
  const start = source.search(new RegExp(`\\bfn\\s+${functionName}\\s*\\(`));
  if (start < 0) return null;
  const openingBrace = source.indexOf("{", start);
  if (openingBrace < 0) return null;
  return balancedBlock(source, openingBrace);
}

function balancedBlock(source, openingBrace) {
  let depth = 0;
  for (let index = openingBrace; index < source.length; index += 1) {
    depth += braceDelta(source[index]);
    if (depth === 0) return source.slice(openingBrace, index + 1);
  }
  return null;
}

function braceDelta(character) {
  if (character === "{") return 1;
  if (character === "}") return -1;
  return 0;
}

const failures = [];
for (const [file, functionName] of contracts) {
  const source = readFileSync(path.join(root, file), "utf8");
  const body = functionBody(source, functionName);
  if (body === null) {
    failures.push(`${file} is missing ${functionName}()`);
    continue;
  }
  if (!body.includes("write_workspace_state_file")) {
    failures.push(`${file}:${functionName} must use write_workspace_state_file()`);
  }
  if (rawWritePattern.test(body)) {
    failures.push(`${file}:${functionName} must not perform raw filesystem writes`);
  }
}

for (const [file, functionName] of readContracts) {
  const source = readFileSync(path.join(root, file), "utf8");
  const body = functionBody(source, functionName);
  if (body === null) {
    failures.push(`${file} is missing ${functionName}()`);
    continue;
  }
  const usesSafeReader = [
    "read_optional_workspace_text",
    "read_workspace_text",
    "read_utf8_text",
    "read_run_artifact_text",
  ].some((token) => body.includes(token));
  if (!usesSafeReader) {
    failures.push(`${file}:${functionName} must use a bounded no-follow reader`);
  }
  if (rawReadPattern.test(body)) {
    failures.push(`${file}:${functionName} must not perform raw filesystem reads`);
  }
}

for (const [file, functionName] of removalContracts) {
  const source = readFileSync(path.join(root, file), "utf8");
  const body = functionBody(source, functionName);
  if (body === null) {
    failures.push(`${file} is missing ${functionName}()`);
    continue;
  }
  if (!body.includes("remove_workspace_state_file")) {
    failures.push(`${file}:${functionName} must use remove_workspace_state_file()`);
  }
  if (/(?:std::)?fs::remove_file\s*\(/.test(body)) {
    failures.push(`${file}:${functionName} must not remove state with raw filesystem calls`);
  }
}

if (failures.length > 0) {
  console.error("Workspace-state write contract failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(
  `workspace-state I/O contract passed (${contracts.length} writers, ${readContracts.length} readers, ${removalContracts.length} removers)`,
);
