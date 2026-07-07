#!/usr/bin/env node
import { readFileSync } from "node:fs";
import path from "node:path";

const root = process.cwd();

const pairedFiles = [
  {
    file: "crates/kuzushi-core/src/modules/builtins/with_v2_builtins/execution.rs",
    needles: [
      "prepare_tool_input_for_dispatch(name, input, ctx, option_store)?",
      "dispatch_prepared_tool_with_runtime(name, input, ctx, runtime)",
    ],
  },
  {
    file: "crates/kuzushi-cli/src/application/scan_prepare.rs",
    needles: ["prepare_tool_input_for_dispatch("],
  },
  {
    file: "crates/kuzushi-cli/src/application/scan.rs",
    needles: ["dispatch_prepared_tool_with_runtime("],
  },
  {
    file: "crates/kuzushi-cli/src/application/run_tool_prepare.rs",
    needles: ["prepare_tool_input_for_dispatch(&self.tool"],
  },
  {
    file: "crates/kuzushi-cli/src/application/run_tool.rs",
    needles: ["dispatch_prepared_tool_with_runtime("],
  },
  {
    file: "crates/kuzushi-tui/src/app/tool_runner/run_tool/dispatch.rs",
    needles: ["prepare_tool_input_for_dispatch(", "start_background_tool("],
  },
  {
    file: "crates/kuzushi-tui/src/app/workers/run_background_tool.rs",
    needles: ["dispatch_prepared_tool_with_runtime(tool_name, input, &ctx, runtime_ref)"],
  },
  {
    file: "crates/kuzushi-tui/src/app/tool_runner/run_tool/prereq_flow.rs",
    needles: ["prepare_tool_input_for_dispatch(", "start_background_tool("],
  },
  {
    file: "crates/kuzushi-tui/src/app/onboarding/runner.rs",
    needles: ["prepare_tool_input_for_dispatch(", "start_background_tool("],
  },
];

const failures = pairedFiles.flatMap(({ file, needles }) => {
  const source = readFileSync(path.join(root, file), "utf8");
  return needles
    .filter((needle) => !source.includes(needle))
    .map((needle) => `${file} must keep shared dispatch-boundary token ${needle}`);
});

if (failures.length > 0) {
  console.error("Dispatch boundary contract failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("dispatch boundary contract passed");
