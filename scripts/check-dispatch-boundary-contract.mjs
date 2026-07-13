#!/usr/bin/env node
import { readFileSync } from "node:fs";
import path from "node:path";

const root = process.cwd();

const pairedFiles = [
  {
    file: "crates/kuzushi-core/src/modules/builtins/with_v2_builtins/execution.rs",
    needles: [
      "let input = self.prepare_dispatch_input(name, input, ctx, option_store)?;",
      "self.dispatch_prepared_input_with_runtime(input, ctx, runtime)",
      "let prepared = self.prepare_dispatch_input(name, input, ctx, None)?;",
      "self.dispatch_prepared_input_with_runtime(prepared, ctx, runtime)",
    ],
  },
  {
    file: "crates/kuzushi-cli/src/application/scan_prepare.rs",
    needles: ["prepare_tool_input_for_dispatch("],
  },
  {
    file: "crates/kuzushi-cli/src/application/scan.rs",
    needles: [
      "prepare_dispatch_input(SCAN_TOOL, execution.input, execution.ctx, None)",
      "execution.registry.dispatch_prepared_input_with_runtime(",
    ],
  },
  {
    file: "crates/kuzushi-cli/src/application/run_tool_prepare.rs",
    needles: ["prepare_dispatch_input(&self.tool"],
  },
  {
    file: "crates/kuzushi-cli/src/application/run_tool.rs",
    needles: [
      "authorize_explicit_cli_tool(run.input.clone())",
      "dispatch_prepared_input_with_runtime(",
    ],
    forbidden: ["prepare_dispatch_input(&run.tool"],
  },
  {
    file: "crates/kuzushi-tui/src/app/tool_runner/run_tool/dispatch.rs",
    needles: [
      "prepare_dispatch_input(",
      "start_authorized_prepared_background_tool(",
      "authorization: ExecutionAuthorization",
    ],
    forbidden: ["prepare_tool_input_for_dispatch("],
  },
  {
    file: "crates/kuzushi-tui/src/app/tool_runner/run_tool/background.rs",
    needles: [
      "prepare_dispatch_input(tool_name, input, &ctx, Some(self.option_store()))",
      "start_authorized_prepared_background_tool(",
    ],
  },
  {
    file: "crates/kuzushi-tui/src/app/workers/run_background_tool.rs",
    needles: [
      "authorize_background_prepared_input(input, authorization)",
      "dispatch_prepared_input_with_runtime(prepared, &ctx, runtime_ref)",
    ],
    forbidden: ["prepare_dispatch_input(tool_name"],
  },
  {
    file: "crates/kuzushi-tui/src/app/tool_runner/run_tool/prereq_flow.rs",
    needles: [
      "start_prepared_prereq_chain(",
      "start_authorized_prepared_background_tool(",
      "mark_final_chain_tool_dispatched()",
    ],
    forbidden: ["prepare_tool_input_for_dispatch("],
  },
  {
    file: "crates/kuzushi-tui/src/app/onboarding/runner.rs",
    needles: [
      "prepare_tool_input(tool_name, input, Some(self.option_store()))",
      "prepare_background_tool_input(",
      "start_authorized_prepared_background_tool(",
    ],
    forbidden: ["prepare_tool_input_for_dispatch("],
  },
];

const failures = pairedFiles.flatMap(({ file, needles, forbidden = [] }) => {
  const source = readFileSync(path.join(root, file), "utf8");
  const missing = needles
    .filter((needle) => !source.includes(needle))
    .map((needle) => `${file} must keep shared dispatch-boundary token ${needle}`);
  const bypasses = forbidden
    .filter((needle) => source.includes(needle))
    .map((needle) => `${file} must not re-prepare prepared input via ${needle}`);
  return [...missing, ...bypasses];
});

if (failures.length > 0) {
  console.error("Dispatch boundary contract failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("dispatch boundary contract passed");
