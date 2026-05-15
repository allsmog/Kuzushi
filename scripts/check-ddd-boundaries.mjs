#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const root = repoRoot();
const failures = [];

const boundaries = [
  ["context", ["crates/kuzushi-core/src/context.rs"]],
  ["threat_model", ["crates/kuzushi-core/src/threat_model.rs"]],
  ["attack_surface", ["crates/kuzushi-core/src/attack_surface.rs"]],
  ["modules", ["crates/kuzushi-core/src/modules"]],
  ["recommender", ["crates/kuzushi-core/src/capabilities/module_recommender"]],
  ["findings", ["crates/kuzushi-core/src/findings"]],
  ["proof", ["crates/kuzushi-core/src/proof"]],
  ["run_trace", ["crates/kuzushi-core/src/run_trace.rs"]],
  ["scanners", ["crates/kuzushi-core/src/scanners.rs"]],
  ["triage", ["crates/kuzushi-core/src/triage.rs"]],
  ["verify", ["crates/kuzushi-core/src/verify.rs"]],
  ["patch", ["crates/kuzushi-core/src/patch.rs", "crates/kuzushi-core/src/remediation/patch"]],
  ["report", ["crates/kuzushi-core/src/report.rs", "crates/kuzushi-core/src/report"]],
  ["failure", ["crates/kuzushi-core/src/run_artifacts/run_failures.rs"]],
  ["ui_view_models", ["crates/kuzushi-tui/src/ui_view_models.rs"]],
  ["ui_theme", ["crates/kuzushi-tui/src/ui_theme.rs"]],
  ["ui_views", ["crates/kuzushi-tui/src/ui_views.rs"]],
];

const rules = [
  {
    name: "context builds repository facts without scanner runtime or tool execution",
    roots: [
      "crates/kuzushi-core/src/context.rs",
      "crates/kuzushi-core/src/repository_inventory.rs",
      "crates/kuzushi-core/src/static_context.rs",
      "crates/kuzushi-core/src/workspace/inventory",
      "crates/kuzushi-core/src/evidence/context",
      "crates/kuzushi-core/src/modules/context",
    ],
    forbidden:
      /\b(crate::(?:scan|scanners|verification|verify|triage|remediation|patch|report)|AgentRuntime|AgentQueryRequest|TracedRuntime|Command::new|std::process::Command|execute_tool|execute_tool_with_runtime|ratatui|crossterm)\b/,
  },
  {
    name: "attack surface ranks repository entrypoints without scanner runtime or tool execution",
    roots: [
      "crates/kuzushi-core/src/attack_surface.rs",
      "crates/kuzushi-core/src/workspace/attack_surface",
    ],
    forbidden:
      /\b(crate::(?:scan|scanners|runtime|modules|verification|verify|triage|remediation|patch|report)|AgentRuntime|AgentQueryRequest|TracedRuntime|Command::new|std::process::Command|execute_tool|execute_tool_with_runtime|ratatui|crossterm)\b/,
  },
  {
    name: "threat model domain stays deterministic without runtime or dispatch dependencies",
    roots: ["crates/kuzushi-core/src/capabilities/threat_model/domain"],
    forbidden:
      /\b(crate::(?:scan|scanners|runtime|modules|verification|verify|triage|remediation|patch|report)|AgentRuntime|AgentQueryRequest|TracedRuntime|Command::new|std::process::Command|execute_tool|execute_tool_with_runtime|ratatui|crossterm)\b/,
  },
  {
    name: "findings never call scanners, LLM runtimes, renderers, or subprocesses",
    roots: ["crates/kuzushi-core/src/findings"],
    forbidden:
      /\b(crate::(?:scan|scanners|runtime|modules|verification)|std::process|Command::new|ratatui|crossterm)\b/,
  },
  {
    name: "proof validates claims without scanner runtime dispatch or presentation dependencies",
    roots: ["crates/kuzushi-core/src/proof"],
    forbidden:
      /\b(crate::(?:scan|scanners|modules|verification|verify|triage|remediation|patch|report)|AgentRuntime|AgentQueryRequest|TracedRuntime|Command::new|std::process::Command|execute_tool|execute_tool_with_runtime|ratatui|crossterm)\b/,
  },
  {
    name: "scanners normalize findings without triage or verification",
    roots: [
      "crates/kuzushi-core/src/scanners.rs",
      "crates/kuzushi-core/src/scan",
      "crates/kuzushi-core/src/dep_hygiene.rs",
      "crates/kuzushi-core/src/secret_scan.rs",
      "crates/kuzushi-core/src/iac_scan.rs",
    ],
    forbidden:
      /\b(TriageOutcome|TriageVerdict|triage:run|crate::(?:modules::triage|verification|verify))\b/,
  },
  {
    name: "triage attaches verdicts without scanner verification patch or report dispatch",
    roots: ["crates/kuzushi-core/src/triage.rs", "crates/kuzushi-core/src/modules/triage"],
    forbidden:
      /\b(crate::(?:scan|scanners|verification|verify|patch|remediation|report)|verify:finding|patch:finding|report:build|Command::new|std::process|execute_tool|execute_tool_with_runtime)\b/,
  },
  {
    name: "verify attaches proof without scanner triage patch report or tool dispatch",
    roots: ["crates/kuzushi-core/src/verify.rs", "crates/kuzushi-core/src/verification"],
    forbidden:
      /\b(crate::(?:scan|scanners|modules::triage|triage|remediation|patch|report)|execute_tool|execute_tool_with_runtime)\b/,
  },
  {
    name: "patch suggests remediation without scanner triage verify report or tool dispatch",
    roots: ["crates/kuzushi-core/src/patch.rs", "crates/kuzushi-core/src/remediation/patch"],
    forbidden:
      /\b(crate::(?:scan|scanners|modules::triage|triage|verification|verify|report|capabilities::module_recommender)|execute_tool|execute_tool_with_runtime)\b/,
  },
  {
    name: "report boundary reads artifacts and findings without execution",
    roots: [
      "crates/kuzushi-core/src/report.rs",
      "crates/kuzushi-core/src/report",
      "crates/kuzushi-core/src/findings/presentation/reporting",
      "crates/kuzushi-core/src/findings/presentation/pr_comment",
    ],
    forbidden:
      /\b(crate::(?:scan|scanners|runtime|modules|verification)|AgentRuntime|Command::new|std::process)\b/,
  },
  {
    name: "recommender plans modules but does not execute them",
    roots: ["crates/kuzushi-core/src/capabilities/module_recommender"],
    forbidden:
      /\b(execute_tool|execute_tool_with_runtime|AgentRuntime|TracedRuntime|start_background_tool|run_background_tool)\b/,
  },
  {
    name: "failure handoff stays bounded to run artifacts",
    roots: ["crates/kuzushi-core/src/run_artifacts/run_failures.rs"],
    forbidden:
      /\b(AgentRuntime|TracedRuntime|execute_tool|execute_tool_with_runtime|Command::new|std::process|crate::(?:scan|scanners|verification|modules::registry))\b/,
  },
  {
    name: "run trace records artifacts without scanner runtime or tool execution",
    roots: ["crates/kuzushi-core/src/run_trace.rs", "crates/kuzushi-core/src/run_artifacts"],
    forbidden:
      /\b(crate::(?:scan|scanners|verification|verify|triage|remediation|patch|report|modules::registry|capabilities::module_recommender)|AgentRuntime|AgentQueryRequest|TracedRuntime|Command::new|std::process::Command|execute_tool|execute_tool_with_runtime)\b/,
  },
  {
    name: "TUI renderers consume view models without stores or runtime dispatch",
    roots: ["crates/kuzushi-tui/src/renderer"],
    forbidden:
      /\b(FindingStore|AgentRuntime|execute_tool|execute_tool_with_runtime|std::process|Command::new|ProcessCommand)\b/,
  },
  {
    name: "TUI view models and views do not execute modules",
    roots: [
      "crates/kuzushi-tui/src/ui_view_models.rs",
      "crates/kuzushi-tui/src/ui_view_models",
      "crates/kuzushi-tui/src/ui_views.rs",
      "crates/kuzushi-tui/src/ui_theme.rs",
    ],
    forbidden:
      /\b(AgentRuntime|TracedRuntime|execute_tool|execute_tool_with_runtime|start_background_tool|run_background_tool|Command::new|ProcessCommand)\b/,
  },
  {
    name: "TUI runtime wording avoids validated without proof",
    roots: ["crates/kuzushi-tui/src"],
    forbidden: /\bvalidated\b/i,
  },
  {
    name: "TUI catalog cockpit renderers do not parse artifacts directly",
    roots: ["crates/kuzushi-tui/src/renderer/views/catalog"],
    forbidden: /\b(std::fs|serde_json|read_to_string|PathBuf|Path::new|\.exists\()/,
  },
  {
    name: "TUI runs ledger renderer reads past-run view models",
    roots: [
      "crates/kuzushi-tui/src/renderer/views/runs/runs_lines.rs",
      "crates/kuzushi-tui/src/renderer/views/runs/runs_row.rs",
    ],
    forbidden: /\b(std::fs|serde_json|read_dir|read_to_string|PathBuf|Path::new|\.exists\()/,
  },
  {
    name: "TUI replay and trace renderers read run-trace view models",
    roots: [
      "crates/kuzushi-tui/src/renderer/views/runs/replay_lines.rs",
      "crates/kuzushi-tui/src/renderer/views/runs/trace_step_line.rs",
    ],
    forbidden: /\b(std::fs|serde_json|read_dir|read_to_string|PathBuf|Path::new|\.exists\()/,
  },
  {
    name: "TUI module detail renderers read prompt view models",
    roots: ["crates/kuzushi-tui/src/renderer/views/module/module_lines.rs"],
    forbidden: /\b(std::fs|read_dir|read_to_string|PathBuf|Path::new|\.exists\()/,
  },
  {
    name: "TUI module detail renderer reads module detail view model",
    roots: ["crates/kuzushi-tui/src/renderer/views/module/module_lines.rs"],
    forbidden:
      /kuzushi_core::(?:BuiltinModule|ToolDescriptor)|\.registry\.modules\(|\.tools\(\)|\.metadata\(\)/,
  },
  {
    name: "TUI catalog renderer reads catalog view model",
    roots: ["crates/kuzushi-tui/src/renderer/views/catalog/catalog_lines"],
    forbidden:
      /kuzushi_core::(?:BuiltinModule|ToolDescriptor)|\bModuleKind\b|\.registry\.modules\(|\.tools\(\)|\.metadata\(\)/,
  },
  {
    name: "TUI catalog navigation reads catalog view model",
    roots: ["crates/kuzushi-tui/src/app/catalog"],
    forbidden:
      /kuzushi_core::(?:BuiltinModule|ToolDescriptor)|\bModuleKind\b|\.registry\.modules\(|\.tools\(\)|\.metadata\(\)|catalog_category/,
  },
  {
    name: "TUI plain config renderer reads catalog view model",
    roots: ["crates/kuzushi-tui/src/renderer/plain/plain_config_lines.rs"],
    forbidden:
      /kuzushi_core::(?:BuiltinModule|ToolDescriptor)|\bModuleKind\b|\.registry\.modules\(|\.metadata\(\)/,
  },
  {
    name: "TUI options renderers read options view model",
    roots: [
      "crates/kuzushi-tui/src/renderer/views/options/mod.rs",
      "crates/kuzushi-tui/src/renderer/plain/plain_options_lines.rs",
    ],
    forbidden:
      /kuzushi_core::(?:OptionSpec|OptionType|ToolDescriptor)|\.registry\.resolve_tool\(|\.options\b/,
  },
  {
    name: "TUI tools renderer reads tools view model",
    roots: ["crates/kuzushi-tui/src/renderer/views/system/tools_lines.rs"],
    forbidden: /kuzushi_core::ToolDescriptor|\.registry\.tools\(|\.tools\(\)/,
  },
  {
    name: "TUI auth renderer reads auth view model",
    roots: [
      "crates/kuzushi-tui/src/renderer/views/system/auth_lines.rs",
      "crates/kuzushi-tui/src/renderer/views/system/auth_provider_rows.rs",
    ],
    forbidden: /\bstd::env|oauth_provider_status|\.config\.runtime\.api_key_env/,
  },
  {
    name: "TUI threat renderers read threat-model view models",
    roots: ["crates/kuzushi-tui/src/renderer/shared/threat_model/current_threat_model_doc.rs"],
    forbidden: /\b(load_persistent_threat_model|std::env|std::path|PathBuf|read_to_string)\b/,
  },
];

for (const [name, candidates] of boundaries) {
  if (!hasBoundary(candidates)) failures.push(`missing DDD boundary: ${name}`);
}

for (const rule of rules) {
  failures.push(...ruleFailures(rule));
}

if (failures.length > 0) {
  console.error("Kuzushi DDD boundary check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(
  `DDD boundary check passed for ${boundaries.length} boundaries and ${rules.length} rules.`,
);

function repoRoot() {
  try {
    return execFileSync("git", ["rev-parse", "--show-toplevel"], {
      encoding: "utf8",
    }).trim();
  } catch {
    return process.cwd();
  }
}

function hasBoundary(candidates) {
  return candidates.some((candidate) => existsSync(path.join(root, candidate)));
}

function ruleFailures(rule) {
  const files = ruleFiles(rule);
  const missingRoots =
    files.length === 0
      ? [`${rule.name}: no production Rust files matched roots ${rule.roots.join(", ")}`]
      : [];
  return missingRoots.concat(
    files
      .filter((file) => rule.forbidden.test(sourceWithoutTestModule(file)))
      .map((file) => `${rule.name}: ${file}`),
  );
}

function ruleFiles(rule) {
  return trackedFiles()
    .filter((file) => isProductionRust(file))
    .filter((file) => rule.roots.some((candidate) => isUnder(file, candidate)));
}

function trackedFiles() {
  const files = [
    ...gitLines(["ls-files"]),
    ...gitLines(["ls-files", "--others", "--exclude-standard"]),
  ];
  return [...new Set(files)].filter((file) => existsSync(path.join(root, file))).sort();
}

function gitLines(args) {
  return execFileSync("git", args, { cwd: root, encoding: "utf8" })
    .split(/\r?\n/)
    .map((file) => file.trim())
    .filter(Boolean);
}

function sourceWithoutTestModule(file) {
  return readFileSync(path.join(root, file), "utf8").split(/\n#\[cfg\(test\)\]/)[0];
}

function isProductionRust(file) {
  return (
    file.endsWith(".rs") &&
    !file.endsWith("/tests.rs") &&
    !file.endsWith("_tests.rs") &&
    !file.includes("/tests/")
  );
}

function isUnder(file, candidate) {
  return file === candidate || file.startsWith(`${candidate}/`);
}
