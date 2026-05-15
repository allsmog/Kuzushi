#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const root = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();
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
  { name: "TUI run alias renderer reads run-trace view model", roots: ["crates/kuzushi-tui/src/renderer/views/runs/trace_step_line.rs"], forbidden: /\b(sorted_finding_aliases|app\.findings|Finding|\.fingerprint|\.title)\b/ },
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
  { name: "TUI module progress renderer reads SAST task view model", roots: ["crates/kuzushi-tui/src/renderer/views/module/append_progress_section.rs"], forbidden: /\b(option_store|sast_task_rows|serde_json|crate::app::SastTaskRow)\b/ },
  { name: "TUI chrome cards read chrome-card view models", roots: ["crates/kuzushi-tui/src/renderer/chrome/cards/render_threat_patch_card.rs", "crates/kuzushi-tui/src/renderer/chrome/cards/confirm_card_height.rs", "crates/kuzushi-tui/src/renderer/chrome/cards/render_plan_card.rs", "crates/kuzushi-tui/src/renderer/section_slot.rs"], forbidden: /\b(pending_threat_patch|serde_json|crate::app::ThreatPatch|pending_confirm|ConfirmKind|PendingConfirm|advisory\.pending_confirm|advisory\.throttle|advisory\.budget_halt|is_budget_halted|ThrottleAdvisory|crate::app::BudgetHalt)\b/ },
  { name: "TUI plan prereq and patch renderers read review view models", roots: ["crates/kuzushi-tui/src/renderer/chrome/cards/render_plan_card.rs", "crates/kuzushi-tui/src/renderer/chrome/cards/render_prereq_prompt_card.rs", "crates/kuzushi-tui/src/renderer/chrome/cards/render_threat_patch_card.rs", "crates/kuzushi-tui/src/renderer/plain/render_plain_app.rs", "crates/kuzushi-tui/src/renderer/views/patch/patch_lines.rs"], forbidden: /\b(pending_plan|PlanProposal|PlanChange|plan_change_skipped|plan_cursor_clamped|pending_prereq_prompt|PendingPrereqPrompt|PrereqPlanStep|pending_patch|PendingPatch)\b/ },
  { name: "TUI actor detail renderer reads actor-detail view model", roots: ["crates/kuzushi-tui/src/renderer/views/editor/actor_detail_lines.rs"], forbidden: /\b(actor_detail_filter|crate::app::LogLine|scan_status|\.log\b|\.scan\b)\b/ },
  { name: "TUI session history renderer reads session story view models", roots: ["crates/kuzushi-tui/src/renderer/views/chat/history_lines.rs"], forbidden: /\b(command_history|is_scan_paused)\b|\.scan\b|\.log\b/ },
  { name: "TUI agent chat renderer reads agent chat view model", roots: ["crates/kuzushi-tui/src/renderer/views/chat/agent_chat_lines"], forbidden: /\b(AgentChatView|ChatTurn|display_model_selector)\b|app\.agent_chat|\.config\b/ },
  { name: "TUI findings renderers read findings view models", roots: ["crates/kuzushi-tui/src/renderer/views/findings"], forbidden: /\bFinding\b|sorted_finding_aliases|stable_finding_alias|project_finding|proof_state_label|runtime_validation_label|finding_(?:location|verdict_label|confidence_label|cwe_label|source_label|evidence_preview)|app\.findings|app\.selected_finding|findings_cursor|context_view/ },
  { name: "TUI module findings preview reads findings view model", roots: ["crates/kuzushi-tui/src/renderer/views/module/append_findings_preview.rs"], forbidden: /\bShellApp\b|app\.findings|sorted_finding_aliases|finding_location|kuzushi_core::Finding/ },
  { name: "TUI transcript chrome reads transcript view model", roots: ["crates/kuzushi-tui/src/renderer/chrome/transcript/mod.rs"], forbidden: /\.log\b/ },
  { name: "TUI config renderers read config view model", roots: ["crates/kuzushi-tui/src/renderer/views/system/config_lines.rs", "crates/kuzushi-tui/src/renderer/plain/plain_config_lines.rs"], forbidden: /\b(runtime_backend_label|display_model_selector|model_choices|model_choice_display_selector|bridge_command_status|model_auth_status|auth_env_summary|oauth_summary|\.config\b|session_thinking_level|session_cost_usd|last_tool_cost_usd|selected_model_index)\b/ },
  { name: "TUI auth and cost renderers read auth/config/cost view models", roots: ["crates/kuzushi-tui/src/renderer/views/system/auth_lines.rs", "crates/kuzushi-tui/src/renderer/views/system/cost_lines.rs"], forbidden: /\b(runtime_backend_label|display_model_selector|format_session_cost|\.config\b|session_thinking_level|session_cost_usd|last_tool_cost_usd|session_budget_usd)\b/ },
  { name: "TUI run timeline renderer reads run timeline view model", roots: ["crates/kuzushi-tui/src/renderer/views/runs/runs_lines.rs"], forbidden: /\b(past_runs_model|scan_status|ScanPanelState|\.scan\b)\b/ },
  { name: "TUI prompt-tuning renderer reads prompt-tuning view models", roots: ["crates/kuzushi-tui/src/renderer/views/editor/tune_lines.rs"], forbidden: /\b(read_house_rules|TuneAction|tune_cursor_clamped|prompts_cursor_clamped|focused_module|PROMPT_VERB_NAMES|crate::app::ShellApp)\b/ },
  { name: "TUI catalog renderer reads catalog view model", roots: ["crates/kuzushi-tui/src/renderer/views/catalog/catalog_lines"], forbidden: /kuzushi_core::(?:BuiltinModule|ToolDescriptor)|\bModuleKind\b|\.registry\.modules\(|\.tools\(\)|\.metadata\(\)/ },
  { name: "TUI compact catalog reads catalog view model", roots: ["crates/kuzushi-tui/src/renderer/views/catalog/catalog_lines/collapsed_state.rs", "crates/kuzushi-tui/src/renderer/shared/catalog/catalog_next_hint.rs"], forbidden: /\bShellApp\b|app\.|sorted_finding_aliases|Severity::|first_finding_|context_view|\.findings\b/ },
  { name: "TUI context renderers read context snapshot view model", roots: ["crates/kuzushi-tui/src/renderer/views/workspace/context_lines.rs", "crates/kuzushi-tui/src/renderer/plain/plain_context_lines.rs"], forbidden: /app\.context_view|ContextSnapshotView|running_tool_name|spinner_glyph|\.snapshot_path|files_indexed|generated_slices|stale_slices/ },
  { name: "TUI workspace renderers read workspace view model", roots: ["crates/kuzushi-tui/src/renderer/views/workspace/workspace_lines.rs", "crates/kuzushi-tui/src/renderer/plain/plain_context_lines.rs"], forbidden: /app\.workspace_view|crate::app::WorkspaceView|app\.findings|SeverityCounts|Severity::|\.root\b|\.state_dir\b|\.findings_db\b|\.findings_count\b|\.last_export\b/ },
  { name: "TUI knowledge base renderers read knowledge-base view model", roots: ["crates/kuzushi-tui/src/renderer/views/workspace/knowledge_base_lines.rs", "crates/kuzushi-tui/src/renderer/plain/plain_knowledge_base_lines.rs"], forbidden: /app\.kb_view|KnowledgeBaseView|SUPPORTED_ATTACHMENT_MODULES|AttachmentKind|KnownArtifact|AttachmentRecord|\.module_id\b|\.store_path\b|\.attachments\b|\.artifacts\b/ },
  { name: "TUI help renderers read help view model", roots: ["crates/kuzushi-tui/src/renderer/views/help/mod.rs", "crates/kuzushi-tui/src/renderer/plain/plain_sast_tasks_lines.rs"], forbidden: /shell_command_specs|shell_help_examples|ShellCommandCategory|ShellCommandSpec|help_category_blurb|help_alias_text|first_finding_scan_command|app\.target/ },
  { name: "TUI catalog navigation reads catalog view model", roots: ["crates/kuzushi-tui/src/app/catalog"], forbidden: /kuzushi_core::(?:BuiltinModule|ToolDescriptor)|\bModuleKind\b|\.registry\.modules\(|\.tools\(\)|\.metadata\(\)|catalog_category/ },
  { name: "TUI plain config renderer reads catalog view model", roots: ["crates/kuzushi-tui/src/renderer/plain/plain_config_lines.rs"], forbidden: /kuzushi_core::(?:BuiltinModule|ToolDescriptor)|\bModuleKind\b|\.registry\.modules\(|\.metadata\(\)/ },
  { name: "TUI options renderers read options view model", roots: ["crates/kuzushi-tui/src/renderer/views/options/mod.rs", "crates/kuzushi-tui/src/renderer/plain/plain_options_lines.rs", "crates/kuzushi-tui/src/renderer/plain/plain_sast_tasks_lines.rs"], forbidden: /kuzushi_core::(?:OptionSpec|OptionType|ToolDescriptor)|\.registry\.resolve_tool\(|\.options\b|option_store|sast_task_rows|serde_json/ },
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
      "crates/kuzushi-tui/src/renderer/views/system/config_lines.rs",
    ],
    forbidden: /\bstd::env|oauth_provider_status|\.config\.runtime\.api_key_env/,
  },
  {
    name: "TUI prompt renderer reads prompt view model",
    roots: ["crates/kuzushi-tui/src/renderer/chrome/prompt/mod.rs"],
    forbidden: /\bstd::env|KUZUSHI_CLI_NAME|binary_stem/,
  },
  {
    name: "TUI viewport helpers do not own routing view model",
    roots: ["crates/kuzushi-tui/src/renderer/views/viewport_lines.rs"],
    forbidden: /\bRoutingMode\b|routing_mode\(/,
  },
  {
    name: "TUI status helpers read view-status view model",
    roots: ["crates/kuzushi-tui/src/renderer/shared/status/mod.rs"],
    forbidden: /\bShellView::|ThreatView::|view_status_segment\(/,
  },
  {
    name: "TUI threat renderers read threat-model view models",
    roots: ["crates/kuzushi-tui/src/renderer/views/threat", "crates/kuzushi-tui/src/renderer/shared/threat_model"],
    forbidden:
      /\b(load_persistent_threat_model|threat_model_doc\(|serde_json|std::env|std::path|PathBuf|read_to_string)\b/,
  },
];

for (const [name, candidates] of boundaries) if (!hasBoundary(candidates)) failures.push(`missing DDD boundary: ${name}`);

for (const rule of rules) {
  failures.push(...ruleFailures(rule));
}

if (failures.length > 0) {
  console.error("Kuzushi DDD boundary check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`DDD boundary check passed for ${boundaries.length} boundaries and ${rules.length} rules.`);

function hasBoundary(candidates) {
  return candidates.some((candidate) => existsSync(path.join(root, candidate)));
}

function ruleFailures(rule) {
  const files = ruleFiles(rule);
  if (files.length === 0) {
    return [`${rule.name}: no production Rust files matched roots ${rule.roots.join(", ")}`];
  }
  return files
    .filter((file) => rule.forbidden.test(sourceWithoutTestModule(file)))
    .map((file) => `${rule.name}: ${file}`);
}

function ruleFiles(rule) {
  return trackedFiles()
    .filter((file) => isProductionRust(file))
    .filter((file) => rule.roots.some((candidate) => isUnder(file, candidate)));
}

function trackedFiles() {
  const files = [...gitLines(["ls-files"]), ...gitLines(["ls-files", "--others", "--exclude-standard"])];
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
  return file.endsWith(".rs") && !file.endsWith("/tests.rs") && !file.endsWith("_tests.rs") && !file.includes("/tests/");
}

function isUnder(file, candidate) {
  return file === candidate || file.startsWith(`${candidate}/`);
}
