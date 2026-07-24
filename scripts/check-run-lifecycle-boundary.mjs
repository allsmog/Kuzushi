#!/usr/bin/env node
import { readFileSync } from "node:fs";
import path from "node:path";
import { hasActiveRustModule } from "./rust-source-markers.mjs";

const root = process.cwd();
function readSource(file) {
  return readFileSync(path.join(root, file), "utf8");
}

const required = [
  ["crates/kuzushi-core/src/run_lifecycle/domain/item.rs", "pub enum RunItemV1"],
  ["crates/kuzushi-core/src/run_lifecycle/application/reducer.rs", "pub fn reduce_run_items"],
  [
    "crates/kuzushi-core/src/run_lifecycle/persistence/writer_commit.rs",
    'context("sync run-item batch")',
  ],
  ["crates/kuzushi-tui/src/app/view_state/activity.rs", "run_projection"],
  ["crates/kuzushi-tui/src/renderer/views/runs/replay_lines.rs", "RunProjectionSource::TypedV1"],
];

const requiredRustModules = [
  ["crates/kuzushi-tui/src/app/tests.rs", "run_lifecycle_semantic_equivalence_tests"],
];

const forbidden = [
  [
    "crates/kuzushi-tui/src/app/scan/start_scan/scan_startup.rs",
    "seed_from_registry",
    "typed Scan runs must receive task instances from the runtime stream",
  ],
  [
    "crates/kuzushi-tui/src/renderer/views/runs/replay_lines.rs",
    "load_run_result_summary",
    "typed replay renderers must not reopen result.json",
  ],
  [
    "crates/kuzushi-tui/src/renderer/plain/render_plain_app.rs",
    "load_run_result_summary",
    "plain rendering must consume the shared projection",
  ],
];

const failures = [];
for (const [file, marker] of required) {
  if (!readSource(file).includes(marker)) {
    failures.push(`${file} must retain semantic lifecycle marker ${marker}`);
  }
}
for (const [file, moduleName] of requiredRustModules) {
  if (!hasActiveRustModule(readSource(file), moduleName)) {
    failures.push(`${file} must actively register Rust module ${moduleName}`);
  }
}
for (const [file, marker, reason] of forbidden) {
  if (readSource(file).includes(marker)) {
    failures.push(`${file} contains forbidden ${marker}: ${reason}`);
  }
}

if (failures.length > 0) {
  console.error("Run lifecycle boundary contract failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("run lifecycle boundary contract passed");
