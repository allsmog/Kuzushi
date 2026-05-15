#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

const root = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim(), failures = [];

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
      /\b(FindingStore|AgentRuntime|execute_tool|execute_tool_with_runtime|std::process|Command::new|ProcessCommand|kuzushi_core::Severity)\b/,
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
    forbidden: /\b(std::fs|serde_json|read_to_string|PathBuf|Path::new|\.exists\()|\.glyph\b|\.state\b|artifact\.label\b|artifact\.path\b|surface\.(?:high_risk|max_risk_score|risk_tiers|top_surface)\b|risk_tier_summary|tier_rank/,
  },
  {
    name: "TUI runs ledger renderer reads past-run view models",
    roots: ["crates/kuzushi-tui/src/renderer/views/runs/runs_lines.rs", "crates/kuzushi-tui/src/renderer/views/runs/runs_row.rs"],
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
      /kuzushi_core::(?:BuiltinModule|ToolDescriptor)|\.registry\.modules\(|\.tools\(\)|\.metadata\(\)|app\.focused_module|\bmodule_detail_model\(|ModuleToolModel|\.description\b|\.headless\b|module\.(?:visible_tools|stored_options|prompts|log_count)\b|OPTIONS ·|PROMPTS ·|STATS · this session|No shell tools are exposed/,
  },
  { name: "TUI module progress renderer reads module-progress view model", roots: ["crates/kuzushi-tui/src/renderer/views/module/append_progress_section.rs"], forbidden: /\b(option_store|sast_task_rows|serde_json|crate::app::SastTaskRow|sast_tasks_model|app\.(?:focused_module|scan_progress))\b/ },
  { name: "TUI recent module activity renderer reads activity view model", roots: ["crates/kuzushi-tui/src/renderer/views/module/recent_module_activity_lines.rs"], forbidden: /\b(LogLine|recon_snapshot|carlini_snapshot|agentic_sast_snapshot|\.log\b|crate::app::ReconSnapshot|kuzushi_core::(?:CarliniThreatHuntReport|AgenticSastReport|ReconService|Finding)|ModuleActivityRow::(?:Transcript|ReconService|ReconHost|Finding))\b|\.(?:prefix|body|host|port|service|banner|label|state|rule_id|location)\b/ },
  {
    name: "TUI context progress renderer reads context snapshot view model",
    roots: ["crates/kuzushi-tui/src/renderer/views/module/append_sast_pipeline_progress.rs"],
    forbidden: /app\.context_view|ContextSnapshotView|\.snapshot_path|\.exists\b/,
  },
  {
    name: "TUI module run renderer reads module-run view model",
    roots: ["crates/kuzushi-tui/src/renderer/views/module/from_app.rs"],
    forbidden:
      /app\.(?:target|live_activity|findings|scan|spinner_phase)\b|ScanPanelState|running_tool_name|module_run_target|module_run_stage|module_run_findings|run_label_without_id|ModuleRunSummary::from_app/,
  },
  { name: "TUI chrome cards read chrome-card view models", roots: ["crates/kuzushi-tui/src/renderer/chrome/cards/render_threat_patch_card.rs", "crates/kuzushi-tui/src/renderer/chrome/cards/confirm_card_height.rs", "crates/kuzushi-tui/src/renderer/chrome/cards/render_plan_card.rs", "crates/kuzushi-tui/src/renderer/section_slot.rs"], forbidden: /\b(pending_threat_patch|serde_json|crate::app::ThreatPatch|pending_confirm|ConfirmKind|PendingConfirm|advisory\.pending_confirm|advisory\.throttle|advisory\.budget_halt|is_budget_halted|ThrottleAdvisory|crate::app::BudgetHalt|app\.shell_view|ShellView::)\b/ },
  { name: "TUI plan prereq and patch renderers read review view models", roots: ["crates/kuzushi-tui/src/renderer/chrome/cards/render_plan_card.rs", "crates/kuzushi-tui/src/renderer/chrome/cards/render_prereq_prompt_card.rs", "crates/kuzushi-tui/src/renderer/chrome/cards/render_threat_patch_card.rs", "crates/kuzushi-tui/src/renderer/plain/render_plain_app.rs", "crates/kuzushi-tui/src/renderer/views/patch/patch_lines.rs"], forbidden: /\b(pending_plan|PlanProposal|PlanChange|plan_change_skipped|plan_cursor_clamped|pending_prereq_prompt|PendingPrereqPrompt|PrereqPlanStep|pending_patch|PendingPatch)\b/ },
  { name: "TUI actor detail renderer reads actor-detail view model", roots: ["crates/kuzushi-tui/src/renderer/views/editor/actor_detail_lines.rs"], forbidden: /\b(actor_detail_filter|crate::app::LogLine|scan_status|\.log\b|\.scan\b)\b/ },
  { name: "TUI session history renderer reads session story view models", roots: ["crates/kuzushi-tui/src/renderer/views/chat/history_lines.rs"], forbidden: /\b(command_history|is_scan_paused)\b|\.scan\b|\.log\b|row_model\.(?:number|command)\b|(?:scan|event)\.(?:label|body)\b/ },
  { name: "TUI agent chat renderer reads agent chat view model", roots: ["crates/kuzushi-tui/src/renderer/views/chat/agent_chat_lines"], forbidden: /\b(AgentChatView|ChatTurn|display_model_selector|FailureToLlmContext)\b|app\.agent_chat|\.config\b|failure_handoff_context|\.failed_stage\b|\.cause\b|\.allowed_proof_level\b|\.artifacts_available\b|\.missing_artifacts\b|\.next_files_or_artifacts_to_inspect\b|\.recovery_options\b|\.claims_forbidden\b|\.fallback_prompt\b/ },
  { name: "TUI findings renderers read findings view models", roots: ["crates/kuzushi-tui/src/renderer/views/findings"], forbidden: /\bFinding\b|sorted_finding_aliases|stable_finding_alias|project_finding|proof_state_label|runtime_validation_label|finding_(?:location|verdict_label|confidence_label|cwe_label|source_label|evidence_preview)|app\.findings|app\.selected_finding|findings_cursor|context_view/ },
  { name: "TUI module findings preview reads findings view model", roots: ["crates/kuzushi-tui/src/renderer/views/module/append_findings_preview.rs"], forbidden: /\bShellApp\b|app\.findings|sorted_finding_aliases|finding_location|kuzushi_core::Finding|model\.(?:rows|total|triaged|pending)\b|\.iter\(\)\.take\(8\)|FINDINGS ·/ },
  { name: "TUI transcript chrome reads transcript view model", roots: ["crates/kuzushi-tui/src/renderer/chrome/transcript/mod.rs"], forbidden: /\.log\b/ },
  { name: "TUI plain activity and command result read view models", roots: ["crates/kuzushi-tui/src/renderer/plain/render_plain_app.rs"], forbidden: /app\.(?:log|live_activity|shell_view)|ShellView::|LogLine\b|LiveActivity\b|PlainLiveActivityRow\b|TranscriptRow\b|transcript_model_from_log_index|plain_live_activity_rows|plain_log_line|COMMAND RESULT|LIVE ACTIVITY|["']command:|["']logs:|phase:|subject:|detail:|PREREQUISITE PLAN|final tool:|review required before prerequisites|actions: approve|writes:|risk:|cost:/ },
  { name: "TUI config renderers read config view model", roots: ["crates/kuzushi-tui/src/renderer/views/system/config_lines.rs", "crates/kuzushi-tui/src/renderer/plain/plain_config_lines.rs"], forbidden: /\b(runtime_backend_label|display_model_selector|model_choices|model_choice_display_selector|bridge_command_status|model_auth_status|auth_env_summary|oauth_summary|\.config\b|session_thinking_level|session_cost_usd|last_tool_cost_usd|selected_model_index)\b|\.label\b|\.value\b|\.selected\b|\.index\b|\.effort\b|\.auth\b|row\.model\b|["'](?:CONFIG|MODELS)|detail\(["'](?:backend|provider|model|reasoning|auth envs|oauth|base url|bridge|cost|onboarding)|\["", "#", "model", "effort", "auth"\]|Up\/Down select|Enter choose|model <n> \[xhigh\]|auth login openai\|anthropic/ },
  { name: "TUI auth and cost renderers read auth/config/cost view models", roots: ["crates/kuzushi-tui/src/renderer/views/system/auth_lines.rs", "crates/kuzushi-tui/src/renderer/views/system/cost_lines.rs"], forbidden: /\b(runtime_backend_label|display_model_selector|format_session_cost|\.config\b|session_thinking_level|session_cost_usd|last_tool_cost_usd|session_budget_usd)\b|\.label\b|\.used\b|\.cap\b|\.percent\b|\.budget_text\b|\.session_text\b|\.last_tool_text\b/ },
  { name: "TUI run timeline renderer reads run timeline view model", roots: ["crates/kuzushi-tui/src/renderer/views/runs/runs_lines.rs"], forbidden: /\b(past_runs_model|scan_status|ScanPanelState|\.scan\b|\.run_id\b|\.status\b|\.status_kind\b|\.findings\b|\.target\b)\b/ },
  { name: "TUI threat DFD renderer reads threat DFD view model", roots: ["crates/kuzushi-tui/src/renderer/views/threat/threat_lines/dfd.rs"], forbidden: /node\.(?:id|node_type|trust_zone)\b|nodes\.(?:is_empty|len)\b|into_iter\(\)\.take\(8\)|NODES FROM threat-model\.json/ },
  { name: "TUI threat story renderer reads threat story view model", roots: ["crates/kuzushi-tui/src/renderer/views/threat/threat_lines/stories.rs"], forbidden: /story\.(?:id|severity|title|attack|location)\b|stories\.(?:len|into_iter)\b|into_iter\(\)\.take\(8\)|ATTACKER STORIES|ThreatStoryRow\b/ },
  { name: "TUI threat scope renderer reads threat scope view model", roots: ["crates/kuzushi-tui/src/renderer/views/threat/threat_lines/scope.rs"], forbidden: /bucket\.(?:severity|label|items|item_count)\b|buckets\.(?:iter|len)\b|items\.(?:is_empty|iter|len)\b|SCOPE ·/ },
  { name: "TUI threat stride renderer reads threat stride view model", roots: ["crates/kuzushi-tui/src/renderer/views/threat/threat_lines/stride.rs"], forbidden: /row\.(?:letter|severity|category|count|description|issue_count)\b|\.iter\(\)\.map\(\|row\| row\.count\)/ },
  { name: "TUI activity renderers read activity chrome view models", roots: ["crates/kuzushi-tui/src/renderer/views/activity/activity_lines.rs", "crates/kuzushi-tui/src/renderer/views/activity/render_activity_view.rs"], forbidden: /\b(DagTaskState|PaneFocus|ActivitySession|pane_focus|activity_header_text|compact_activity_run_id|pane_focus_label|paused_header_segment|verbose_header_segment|focus_task|steps_done|last_label|focus_footer_body|focused_task_row|focus_footer_empty_body|key_hints_for_width|append_narrow_cancel_hint|feed_placeholder_text|hidden_subsystem_event_count|hidden_event_module|plural_suffix|paused_feed_line|push_pause_feed_row|session\.paused|task_scroll|feed_scroll|feed_auto_tail|clamp_scroll|session\.tasks|session\.events|session\.verbose_subsystems|dag_row_text|dag_subsystems_row_text|dag_state_style|feed_event_text|feed_event_style|activity_pane_widths|pane_title_text|pane_header_line|activity_keybind_hint_line|focus_footer_line|combined_activity_pane_line|combined_pane_line|ActivityPaneRow|pad_to)\b|app\.activity|footer\.body\b|plain_header|fit\(body|hint\.(?:key|hint)\b|title\.label|format!\("──|format!\(" ──|press p to resume|no run active|Constraint::Length\(2\)|Constraint::Percentage\(46\)|Constraint::Percentage\(54\)/ },
  { name: "TUI prompt-tuning renderer reads prompt-tuning view models", roots: ["crates/kuzushi-tui/src/renderer/views/editor/tune_lines.rs"], forbidden: /\b(read_house_rules|TuneAction|tune_cursor_clamped|prompts_cursor_clamped|focused_module|PROMPT_VERB_NAMES|crate::app::ShellApp)\b/ },
  { name: "TUI catalog renderer reads catalog view model", roots: ["crates/kuzushi-tui/src/renderer/views/catalog/catalog_lines", "crates/kuzushi-tui/src/renderer/views/catalog/recommend_lines.rs"], forbidden: /kuzushi_core::(?:BuiltinModule|ToolDescriptor)|\bModuleKind\b|\.registry\.modules\(|\.tools\(\)|\.metadata\(\)|catalog_expanded|compact_catalog_width|priority_glyph|\.priority\b|\.requires_runtime\b|\.tool\b|\.reason\b|\.recommendations\b|module\.(?:id|description)\b|short_sentence\(|["']RECOMMEND["']|detail\(["'](?:recommendations|run)["']|no recommendations artifact|module-recommender:recommend|trace <run>|recommend reads the latest|generate it through/ },
  { name: "TUI home renderer reads home view model", roots: ["crates/kuzushi-tui/src/renderer/views/catalog/home_lines.rs"], forbidden: /detail\(["'](?:target|latest run|run status|modules|findings)["']|["']HOME["']|rails:|quickstart|scan \.|model\.(?:target|latest_run|run_status|module_count|finding_count)\b/ },
  { name: "TUI compact catalog reads catalog view model", roots: ["crates/kuzushi-tui/src/renderer/views/catalog/catalog_lines/collapsed_state.rs", "crates/kuzushi-tui/src/renderer/shared/catalog/catalog_next_hint.rs"], forbidden: /\bShellApp\b|app\.|sorted_finding_aliases|Severity::|first_finding_|context_view|\.findings\b/ },
  { name: "TUI context renderers read context snapshot view model", roots: ["crates/kuzushi-tui/src/renderer/views/workspace/context_lines.rs", "crates/kuzushi-tui/src/renderer/plain/plain_context_lines.rs"], forbidden: /app\.context_view|ContextSnapshotView|running_tool_name|spinner_glyph|\.snapshot_path|files_indexed|generated_slices|stale_slices/ },
  { name: "TUI workspace renderers read workspace view model", roots: ["crates/kuzushi-tui/src/renderer/views/workspace/workspace_lines.rs", "crates/kuzushi-tui/src/renderer/plain/plain_context_lines.rs"], forbidden: /app\.workspace_view|crate::app::WorkspaceView|app\.findings|SeverityCounts|Severity::|\.root\b|\.state_dir\b|\.findings_db\b|\.findings_count\b|\.last_export\b/ },
  { name: "TUI knowledge base renderers read knowledge-base view model", roots: ["crates/kuzushi-tui/src/renderer/views/workspace/knowledge_base_lines.rs", "crates/kuzushi-tui/src/renderer/plain/plain_knowledge_base_lines.rs"], forbidden: /app\.kb_view|KnowledgeBaseView|SUPPORTED_ATTACHMENT_MODULES|AttachmentKind|KnownArtifact|AttachmentRecord|\.module_id\b|\.store_path\b|\.attachments\b|\.artifacts\b|row\.(?:label|value)\b|artifact\.(?:state|path|description)\b|record\.(?:id|kind|source|status)\b|["']KB ATTACHMENTS|detail\(["'](?:module|store|supported)|kb \[module\]|attach <path-or-url>|detach <id>|reparse <id>/ }, { name: "TUI plain knowledge base reads plain KB view model", roots: ["crates/kuzushi-tui/src/renderer/plain/plain_knowledge_base_lines.rs"], forbidden: /\b(?:knowledge_base_model|KnowledgeBaseModel|KnowledgeBaseArtifactRow|KnowledgeBaseAttachmentRow)\b|["'](?:KB ATTACHMENTS|KNOWN ARTIFACTS|ATTACHED)|module:|store:|supported:|No known Rust|No attachments yet|Next: kb/ },
  { name: "TUI help renderers read help view model", roots: ["crates/kuzushi-tui/src/renderer/views/help/mod.rs", "crates/kuzushi-tui/src/renderer/plain/plain_sast_tasks_lines.rs"], forbidden: /shell_command_specs|shell_help_examples|ShellCommandCategory|ShellCommandSpec|help_category_blurb|help_alias_text|first_finding_scan_command|app\.target|\.command\b|\.aliases\b|\.description\b/ },
  { name: "TUI plain help reads plain help view model", roots: ["crates/kuzushi-tui/src/renderer/plain/plain_sast_tasks_lines.rs"], forbidden: /\b(?:help_model|HelpCategoryModel|HelpCommandRow)\b|["']HELP|Examples:|aliases \/ examples| - \{\}/ },
  { name: "TUI plain context/workspace read plain view models", roots: ["crates/kuzushi-tui/src/renderer/plain/plain_context_lines.rs"], forbidden: /\b(?:context_snapshot_model|ContextSnapshotDetails|ContextSnapshotModel|workspace_model|WorkspaceModel)\b|["'](?:CONTEXT|WORKSPACE)|snapshot:|findings db:|No context snapshot|No active workspace|Next: (?:context|workspace)/ },
  { name: "TUI catalog navigation reads catalog view model", roots: ["crates/kuzushi-tui/src/app/catalog"], forbidden: /kuzushi_core::(?:BuiltinModule|ToolDescriptor)|\bModuleKind\b|\.registry\.modules\(|\.tools\(\)|\.metadata\(\)|catalog_category/ },
  { name: "TUI plain context strip reads context-strip view model", roots: ["crates/kuzushi-tui/src/renderer/plain/plain_config_lines.rs"], forbidden: /\b(?:catalog_model|context_strip_model)\b|target:| mods\b/ },
  { name: "TUI plain config summary reads plain config view model", roots: ["crates/kuzushi-tui/src/renderer/plain/plain_config_lines.rs"], forbidden: /\b(?:config_model|ConfigModel|ConfigModelRow)\b|["'](?:CONFIG|MODELS)|runtime:|provider:|reasoning:|onboarding:|Next: model/ },
  { name: "TUI plain config renderer reads catalog view model", roots: ["crates/kuzushi-tui/src/renderer/plain/plain_config_lines.rs"], forbidden: /kuzushi_core::(?:BuiltinModule|ToolDescriptor)|\bModuleKind\b|\.registry\.modules\(|\.metadata\(\)/ },
  { name: "TUI plain options summary reads plain options view model", roots: ["crates/kuzushi-tui/src/renderer/plain/plain_options_lines.rs"], forbidden: /\b(?:options_model|OptionRow|OptionsModelStatus)\b|["'](?:OPTIONS|option|value|default|req|type|aliases|description|tool:|view:)|Unknown tool|Canonical keys|Next: set/ },
  { name: "TUI options renderers read options view model", roots: ["crates/kuzushi-tui/src/renderer/views/options/mod.rs", "crates/kuzushi-tui/src/renderer/plain/plain_options_lines.rs", "crates/kuzushi-tui/src/renderer/plain/plain_sast_tasks_lines.rs"], forbidden: /kuzushi_core::(?:OptionSpec|OptionType|ToolDescriptor)|\.registry\.resolve_tool\(|\.options\b|option_store|sast_task_rows|serde_json|OptionsModelStatus|\b(?:OptionRow|SastTaskRow)\b|default_value|option_type|\.aliases\b|\.description\b|row\.(?:label|value|state|id|cost|scan_task|notes)\b|["'](?:OPTIONS|SAST TASKS|state|id|cost|scan|notes|option|value|default|req|type|aliases|description)|detail\(["'](?:tool|view|mode|selected)|Unknown tool|legend:|set <key>|\/task (?:block|allow|toggle|mode|reset)/ },
  { name: "TUI plain SAST tasks reads plain SAST view model", roots: ["crates/kuzushi-tui/src/renderer/plain/plain_sast_tasks_lines.rs"], forbidden: /\b(?:sast_tasks_model|SastTasksModel|SastTaskRow)\b|["'](?:SAST TASKS|state|id|cost|scan|notes|mode:|selected:)|Next: task/ },
  {
    name: "TUI tools renderer reads tools view model",
    roots: ["crates/kuzushi-tui/src/renderer/views/system/tools_lines.rs"],
    forbidden: /kuzushi_core::ToolDescriptor|\.registry\.tools\(|\.tools\(\)|\.name\b|\.headless\b|\.description\b/,
  },
  {
    name: "TUI auth renderer reads auth view model",
    roots: [
      "crates/kuzushi-tui/src/renderer/views/system/auth_lines.rs",
      "crates/kuzushi-tui/src/renderer/views/system/auth_provider_rows.rs",
      "crates/kuzushi-tui/src/renderer/views/system/config_lines.rs",
    ],
    forbidden: /\bstd::env|oauth_provider_status|\.config\.runtime\.api_key_env|AuthProviderState|\.name\b|\.state\b|\.detail\b/,
  },
  {
    name: "TUI prompt renderer reads prompt view model",
    roots: ["crates/kuzushi-tui/src/renderer/chrome/prompt/mod.rs"],
    forbidden:
      /\bstd::env|KUZUSHI_CLI_NAME|binary_stem|prompt_brand|routing_mode|RoutingMode|prompt_text|app\.(?:focused_module|input|cursor)\b/,
  },
  {
    name: "TUI viewport helpers do not own routing view model",
    roots: ["crates/kuzushi-tui/src/renderer/views/viewport_lines.rs"],
    forbidden: /\bRoutingMode\b|routing_mode\(/,
  },
  { name: "TUI app and shell view renderers read routing view model", roots: ["crates/kuzushi-tui/src/renderer/render_app.rs", "crates/kuzushi-tui/src/renderer/views/shell_view_lines.rs"], forbidden: /\bShellView::|app\.(?:shell_view|catalog_expanded|modules_scroll|scroll_offset|help_scroll|tools_scroll|kb_scroll|history_scroll)\b/ },
  { name: "TUI status helpers read view-status view model", roots: ["crates/kuzushi-tui/src/renderer/shared/status/mod.rs"], forbidden: /\bShellView::|ThreatView::|view_status_segment\(/ },
  {
    name: "TUI threat renderers read threat-model view models",
    roots: ["crates/kuzushi-tui/src/renderer/views/threat", "crates/kuzushi-tui/src/renderer/shared/threat_model"],
    forbidden:
      /\b(load_persistent_threat_model|threat_model_doc\(|serde_json|std::env|std::path|PathBuf|read_to_string)\b/,
  },
  { name: "TUI threat nav renderer reads threat-navigation view model", roots: ["crates/kuzushi-tui/src/renderer/shared/threat_model/threat_nav.rs"], forbidden: /ThreatView::/ },
  { name: "TUI threat panel renderer reads threat-navigation view model", roots: ["crates/kuzushi-tui/src/renderer/views/threat/threat_lines/mod.rs"], forbidden: /ThreatView::/ },
];

for (const [name, candidates] of boundaries) if (!hasBoundary(candidates)) failures.push(`missing DDD boundary: ${name}`);

for (const rule of rules) failures.push(...ruleFailures(rule));

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
  if (files.length === 0) return [`${rule.name}: no production Rust files matched roots ${rule.roots.join(", ")}`];
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
