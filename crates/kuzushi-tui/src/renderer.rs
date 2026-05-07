use std::collections::BTreeMap;

use kuzushi_core::modules::{ModuleKind, OptionSpec, OptionType};
use kuzushi_core::{
    sorted_finding_aliases, stable_finding_alias, AttachmentKind, Finding, Severity,
    SUPPORTED_ATTACHMENT_MODULES,
};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Frame, Line, Span, Style};
use ratatui::widgets::Paragraph;

use crate::app::{LogLine, ScanPanelState, ShellApp, ShellView, ThreatView};
use crate::commands::{
    shell_command_specs, shell_help_examples, ShellCommandCategory, ShellCommandSpec,
};
use crate::theme;

pub fn render_app(frame: &mut Frame<'_>, app: &ShellApp) {
    let area = frame.area();
    if area.height == 0 || area.width == 0 {
        return;
    }

    let prompt_height = 1;
    let transcript_height = if matches!(app.shell_view, ShellView::ModuleRun) {
        0
    } else if area.height >= 12 {
        2
    } else {
        0
    };
    let keybind_height = if area.height >= 8 { 2 } else { 0 };
    let status_height = if area.height >= 6 { 1 } else { 0 };
    let throttle_height = if app.advisory.throttle.is_some() && area.height >= 5 {
        1
    } else {
        0
    };
    let budget_height = if app.is_budget_halted() && area.height >= 5 {
        2
    } else {
        0
    };
    let plan_height = plan_card_height(app, area);
    let threat_patch_height = threat_patch_card_height(app, area);
    let fixed_height = prompt_height
        + transcript_height
        + keybind_height
        + status_height
        + throttle_height
        + budget_height
        + plan_height
        + threat_patch_height;
    let max_view_height = area.height.saturating_sub(fixed_height).max(1);
    let view_area = Rect {
        height: max_view_height,
        ..area
    };
    let view_lines = shell_view_lines(app, view_area);
    let view_height = (view_lines.len() as u16).clamp(1, max_view_height);

    let mut constraints = vec![Constraint::Length(view_height), Constraint::Min(0)];
    if throttle_height > 0 {
        constraints.push(Constraint::Length(throttle_height));
    }
    if status_height > 0 {
        constraints.push(Constraint::Length(status_height));
    }
    if keybind_height > 0 {
        constraints.push(Constraint::Length(keybind_height));
    }
    if budget_height > 0 {
        constraints.push(Constraint::Length(budget_height));
    }
    if plan_height > 0 {
        constraints.push(Constraint::Length(plan_height));
    }
    if threat_patch_height > 0 {
        constraints.push(Constraint::Length(threat_patch_height));
    }
    if transcript_height > 0 {
        constraints.push(Constraint::Length(transcript_height));
    }
    constraints.push(Constraint::Length(prompt_height));

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    let mut index = 0;
    render_lines(frame, chunks[index], view_lines);
    index += 1;
    index += 1;

    if throttle_height > 0 {
        render_throttle_banner(frame, chunks[index], app);
        index += 1;
    }
    if status_height > 0 {
        render_status_footer(frame, chunks[index], app);
        index += 1;
    }
    if keybind_height > 0 {
        render_keybind_footer(frame, chunks[index], app);
        index += 1;
    }
    if budget_height > 0 {
        render_cost_cap_halt(frame, chunks[index], app);
        index += 1;
    }
    if plan_height > 0 {
        render_plan_card(frame, chunks[index], app);
        index += 1;
    }
    if threat_patch_height > 0 {
        render_threat_patch_card(frame, chunks[index], app);
        index += 1;
    }
    if transcript_height > 0 {
        render_transcript(frame, chunks[index], app);
        index += 1;
    }
    render_prompt(frame, chunks[index], app);
}

fn threat_patch_card_height(app: &ShellApp, area: Rect) -> u16 {
    if area.height < 6 {
        return 0;
    }
    let Some(patch) = &app.pending_threat_patch else {
        return 0;
    };
    let body = (patch.unsupported.len() + 1) as u16;
    let height = 3 + body;
    height.min(area.height.saturating_sub(4))
}

fn render_threat_patch_card(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(patch) = app.pending_threat_patch.as_ref() else {
        return;
    };
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::styled(
        fit(
            &format!("◆ THREAT PATCH · goal: {}", patch.goal),
            area.width as usize,
        ),
        theme::accent(),
    ));
    lines.push(Line::styled(
        fit(
            &format!("  summary: {}", patch.summary),
            area.width as usize,
        ),
        theme::primary(),
    ));
    let key_count = match &patch.patch {
        serde_json::Value::Object(map) => map.len(),
        _ => 0,
    };
    lines.push(Line::styled(
        fit(
            &format!("  patch: {key_count} top-level key(s)"),
            area.width as usize,
        ),
        theme::success(),
    ));
    for note in &patch.unsupported {
        lines.push(Line::styled(
            fit(&format!("  ! unsupported: {note}"), area.width as usize),
            theme::warn(),
        ));
    }
    lines.push(Line::styled(
        fit("/threats apply   /threats reject", area.width as usize),
        theme::label(),
    ));
    render_lines(frame, area, lines);
}

fn plan_card_height(app: &ShellApp, area: Rect) -> u16 {
    if area.height < 6 {
        return 0;
    }
    let Some(plan) = &app.pending_plan else {
        return 0;
    };
    let body = (plan.changes.len() + plan.unsupported.len()) as u16;
    let height = 3 + body;
    height.min(area.height.saturating_sub(4))
}

pub fn render_plain_app(app: &ShellApp, width: usize) -> String {
    let lines = render_plain_lines(app, width);
    if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    }
}

pub fn render_plain_command_result(
    app: &ShellApp,
    width: usize,
    command: &str,
    log_start: usize,
) -> String {
    let lines = render_plain_command_result_lines(app, width, command, log_start);
    if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    }
}

fn shell_view_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    match &app.shell_view {
        ShellView::Catalog if app.catalog_expanded => {
            viewport_lines(catalog_lines(app, area), area.height, app.modules_scroll)
        }
        ShellView::Catalog => catalog_lines(app, area),
        ShellView::Module => module_lines(app, area),
        ShellView::ModuleRun => module_run_lines(app, area),
        ShellView::Findings => findings_lines(app, area),
        ShellView::Finding => finding_detail_lines(app, area),
        ShellView::Tune => tune_lines(app, area),
        ShellView::Threat(view) => threat_lines(app, area, *view),
        ShellView::ThreatEditor => threat_editor_lines(app, area),
        ShellView::PromptsEditor => prompts_lines(app, area),
        ShellView::ActorDetail(index) => actor_detail_lines(app, area, *index),
        ShellView::Runs => runs_lines(app, area),
        ShellView::Replay(run_id) => replay_lines(app, area, run_id),
        ShellView::Trace(run_id) => trace_lines(app, area, run_id),
        ShellView::Help => viewport_lines(help_lines(app, area), area.height, app.help_scroll),
        ShellView::Config => config_lines(app, area),
        ShellView::Tools => viewport_lines(tools_lines(app, area), area.height, app.tools_scroll),
        ShellView::Options(view) => options_lines(app, area, view),
        ShellView::SastTasks => sast_tasks_lines(app, area),
        ShellView::Context => context_lines(app, area),
        ShellView::Workspace => workspace_lines(app, area),
        ShellView::KnowledgeBase => {
            viewport_lines(knowledge_base_lines(app, area), area.height, app.kb_scroll)
        }
        ShellView::AgentChat => agent_chat_lines(app, area),
        ShellView::History => {
            viewport_lines(history_lines(app, area), area.height, app.history_scroll)
        }
        ShellView::Story => story_lines(app, area),
    }
}

fn viewport_lines(
    lines: Vec<Line<'static>>,
    visible_height: u16,
    scroll: usize,
) -> Vec<Line<'static>> {
    let visible = visible_height as usize;
    if visible == 0 {
        return Vec::new();
    }
    if lines.len() <= visible {
        return lines;
    }
    let start = scroll.min(lines.len().saturating_sub(visible));
    lines.into_iter().skip(start).take(visible).collect()
}

fn viewport_start_for_cursor(total_rows: usize, visible_rows: usize, cursor: usize) -> usize {
    if total_rows <= visible_rows || visible_rows == 0 {
        return 0;
    }
    let max_start = total_rows.saturating_sub(visible_rows);
    let margin = visible_rows.saturating_sub(1) / 2;
    cursor.saturating_sub(margin).min(max_start)
}

fn render_plain_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let width = width.max(40);
    let mut lines = match &app.shell_view {
        ShellView::Options(view) => plain_options_lines(app, width, view),
        ShellView::SastTasks => plain_sast_tasks_lines(app, width),
        ShellView::Context => plain_context_lines(app, width),
        ShellView::Workspace => plain_workspace_lines(app, width),
        ShellView::KnowledgeBase => plain_knowledge_base_lines(app, width),
        ShellView::Config => plain_config_lines(app, width),
        ShellView::Help => plain_help_lines(app, width),
        _ => {
            let area = Rect::new(0, 0, width.min(u16::MAX as usize) as u16, u16::MAX);
            shell_view_lines(app, area)
                .into_iter()
                .map(line_to_plain_text)
                .collect()
        }
    };

    lines = finalize_plain_lines(lines, width);
    trim_plain_lines(lines)
}

fn render_plain_command_result_lines(
    app: &ShellApp,
    width: usize,
    command: &str,
    log_start: usize,
) -> Vec<String> {
    let width = width.max(40);
    let mut lines = vec![
        plain_divider("COMMAND RESULT", width),
        format!("command: {command}"),
        "logs:".to_string(),
    ];
    let log_start = log_start.min(app.log.len());
    for line in &app.log[log_start..] {
        lines.extend(plain_log_lines(line));
    }
    lines.push(String::new());
    lines.push(plain_divider("VIEW", width));
    lines.extend(render_plain_lines(app, width));

    let lines = finalize_plain_lines(lines, width);
    trim_plain_lines(lines)
}

fn plain_log_lines(line: &LogLine) -> Vec<String> {
    let mut lines = Vec::new();
    let body_lines = if line.body.is_empty() {
        vec![""]
    } else {
        line.body.lines().collect::<Vec<_>>()
    };
    for (index, body) in body_lines.into_iter().enumerate() {
        if line.prefix == ">" {
            if index == 0 {
                lines.push(format!("> {body}"));
            } else {
                lines.push(format!("  {body}"));
            }
        } else if index == 0 {
            lines.push(format!("{}: {body}", line.prefix));
        } else {
            lines.push(format!("  {body}"));
        }
    }
    lines
}

fn plain_options_lines(
    app: &ShellApp,
    width: usize,
    view: &crate::app::OptionsView,
) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    lines.push(String::new());
    lines.push(plain_divider("OPTIONS", width));
    lines.push(format!("tool: {}", view.tool_name));
    lines.push(format!("view: {}", options_filter_label(view.filter)));

    let Some(tool) = app.registry.resolve_tool(&view.tool_name) else {
        lines.push(String::new());
        lines.push("Unknown tool. Next: tools".to_string());
        return lines;
    };

    let stored = app.option_store.effective_stored_values(&tool.name);
    let specs = tool
        .options
        .iter()
        .filter(|spec| option_visible(spec, view.filter, stored.get(&spec.name).is_some()))
        .collect::<Vec<_>>();

    if specs.is_empty() {
        lines.push(String::new());
        lines.push(
            match view.filter {
                crate::app::OptionsFilter::Standard => "No standard options. Next: show advanced",
                crate::app::OptionsFilter::Advanced => "No advanced options for this tool.",
                crate::app::OptionsFilter::Missing => "No missing required options for this tool.",
            }
            .to_string(),
        );
        return lines;
    }

    lines.push(String::new());
    let widths = option_table_widths(width.min(u16::MAX as usize) as u16);
    lines.push(table_text(
        &["option", "value", "default", "req", "type", "description"],
        &widths,
    ));
    for spec in specs {
        let current = stored.get(&spec.name);
        let required = if spec.required && current.is_none() && spec.default.is_none() {
            "missing"
        } else if spec.required {
            "yes"
        } else {
            "no"
        };
        let description = option_description(spec);
        let current = current
            .map(format_json_value)
            .unwrap_or_else(|| "-".to_string());
        let default = spec
            .default
            .as_ref()
            .map(format_json_value)
            .unwrap_or_else(|| "-".to_string());
        lines.push(table_text(
            &[
                &spec.name,
                &current,
                &default,
                required,
                option_type_label(spec.option_type),
                &fit(&description, widths.get(5).copied().unwrap_or(16)),
            ],
            &widths,
        ));
    }
    lines.push(String::new());
    lines.push(
        "Next: set <key> <value>, setg <key> <value>, show advanced, show missing".to_string(),
    );
    lines
}

fn plain_sast_tasks_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let rows = app.sast_task_rows();
    let enabled = rows.iter().filter(|row| row.selected).count();
    let blocked = rows.iter().filter(|row| row.source == "blocked").count();
    let mode = app
        .option_store
        .effective_stored_values("sast:scan")
        .get("taskMode")
        .and_then(serde_json::Value::as_str)
        .filter(|mode| *mode == "manual")
        .map(|_| "manual allowlist")
        .unwrap_or("auto + denylist");

    lines.push(String::new());
    lines.push(plain_divider("SAST TASKS", width));
    lines.push(format!("mode: {mode}"));
    lines.push(format!(
        "selected: {enabled}/{} enabled, {blocked} blocked",
        rows.len()
    ));
    lines.push(String::new());
    let widths = sast_task_table_widths(width.min(u16::MAX as usize) as u16);
    lines.push(table_text(
        &["state", "id", "cost", "scan", "notes"],
        &widths,
    ));
    for row in rows {
        lines.push(table_text(
            &[
                row.state,
                row.id,
                row.cost,
                row.scan_task,
                &fit(row.notes, widths.get(4).copied().unwrap_or(20)),
            ],
            &widths,
        ));
    }
    lines.push(String::new());
    lines.push(
        "Next: task block <id>, task allow <id>, task toggle [id], task mode auto|manual|toggle"
            .to_string(),
    );
    lines
}

fn plain_help_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    lines.push(String::new());
    lines.push(plain_divider("HELP", width));
    lines.push(
        "Input: ? opens help; ?text, /ask <question>, and ask <question> enter agent mode."
            .to_string(),
    );
    let examples = shell_help_examples();
    if !examples.is_empty() {
        lines.push(format!("Examples: {}", examples.join(" | ")));
    }

    for category in ShellCommandCategory::ORDER {
        lines.push(String::new());
        lines.push(category.label().to_string());
        lines.push("command | aliases / examples | description".to_string());
        for spec in shell_command_specs()
            .iter()
            .filter(|spec| spec.category == category)
        {
            lines.push(format!("{} - {}", spec.command, spec.description));
            let aliases = plain_help_alias_text(spec);
            if aliases != "-" {
                lines.push(format!("  aliases / examples: {aliases}"));
            }
        }
    }

    lines
}

fn plain_help_alias_text(spec: &ShellCommandSpec) -> String {
    let mut aliases = Vec::new();
    for alias in spec.aliases {
        if *alias == spec.command || aliases.contains(alias) {
            continue;
        }
        aliases.push(*alias);
    }
    if aliases.is_empty() {
        "-".to_string()
    } else {
        aliases.join(", ")
    }
}

fn plain_context_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let view = &app.context_view;

    lines.push(String::new());
    lines.push(plain_divider("CONTEXT", width));
    lines.push(format!(
        "snapshot: {}",
        view.snapshot_path
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| ".kuzushi/context-snapshot.json".to_string())
    ));
    lines.push(format!(
        "state: {}",
        if view.exists { "present" } else { "missing" }
    ));
    lines.push(format!("status: {}", view.status));

    if view.exists {
        lines.push(format!(
            "target: {}",
            view.target.as_deref().unwrap_or("unknown")
        ));
        lines.push(format!(
            "discovery: {}",
            view.discovery.as_deref().unwrap_or("unknown")
        ));
        lines.push(format!(
            "files: indexed={} total={}",
            view.files_indexed
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".to_string()),
            view.total_files
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".to_string())
        ));
        lines.push(format!("languages: {}", join_or_dash(&view.languages)));
        lines.push(format!("frameworks: {}", join_or_dash(&view.frameworks)));
        lines.push(format!(
            "generated: {}",
            join_or_dash(&view.generated_slices)
        ));
        lines.push(format!("stale: {}", join_or_dash(&view.stale_slices)));
    } else {
        lines.push(String::new());
        lines.push(
            "No context snapshot exists yet. Next: context build writes .kuzushi/context-snapshot.json."
                .to_string(),
        );
    }

    lines.push(String::new());
    lines.push("Next: context build, context status, context regen repo".to_string());
    lines
}

fn plain_workspace_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let view = &app.workspace_view;

    lines.push(String::new());
    lines.push(plain_divider("WORKSPACE", width));
    lines.push(format!("status: {}", view.status));
    lines.push(format!(
        "target: {}",
        view.root
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| "none".to_string())
    ));
    lines.push(format!(
        "state: {}",
        view.state_dir
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| ".kuzushi/v2".to_string())
    ));
    lines.push(format!(
        "findings db: {}",
        view.findings_db
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| ".kuzushi/v2/findings.sqlite3".to_string())
    ));
    lines.push(format!(
        "findings: {}",
        view.findings_count
            .map(|count| count.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    ));
    lines.push(format!(
        "last export: {}",
        view.last_export
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| "none".to_string())
    ));
    if view.root.is_none() {
        lines.push(String::new());
        lines.push(
            "No active workspace. Next: scan <target> or kuzushi shell --target .".to_string(),
        );
    }
    lines.push(String::new());
    lines.push("Next: workspace status, workspace export findings findings.json".to_string());
    lines
}

fn plain_knowledge_base_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let module_id = app.kb_view.module_id.as_str();
    let attachments = app
        .kb_view
        .attachments
        .iter()
        .filter(|record| record.module_id == module_id)
        .collect::<Vec<_>>();
    let store = app
        .kb_view
        .store_path
        .as_ref()
        .map(|path| compact_target_path(&path.display().to_string()))
        .unwrap_or_else(|| ".kuzushi/v2/attachments.json".to_string());

    lines.push(String::new());
    lines.push(plain_divider("KB ATTACHMENTS", width));
    lines.push(format!("module: {module_id}"));
    lines.push(format!("store: {store}"));
    lines.push(format!(
        "supported: {}",
        SUPPORTED_ATTACHMENT_MODULES.join(", ")
    ));

    lines.push(String::new());
    lines.push(plain_divider("KNOWN ARTIFACTS", width));
    if app.kb_view.artifacts.is_empty() {
        lines.push("No known Rust artifacts for this module.".to_string());
    } else {
        let widths = kb_artifact_widths(width.min(u16::MAX as usize) as u16);
        lines.push(table_text(&["state", "path", "description"], &widths));
        for artifact in &app.kb_view.artifacts {
            lines.push(table_text(
                &[
                    if artifact.exists {
                        "present"
                    } else {
                        "missing"
                    },
                    &fit(&artifact.path, widths.get(1).copied().unwrap_or(24)),
                    &fit(&artifact.description, widths.get(2).copied().unwrap_or(20)),
                ],
                &widths,
            ));
        }
    }

    lines.push(String::new());
    lines.push(plain_divider("ATTACHED", width));
    if attachments.is_empty() {
        lines.push(
            "No attachments yet. Next: attach <repo-relative-path> or attach <url>".to_string(),
        );
    } else {
        let widths = kb_attachment_widths(width.min(u16::MAX as usize) as u16);
        lines.push(table_text(&["id", "kind", "source", "status"], &widths));
        for record in attachments {
            let kind = match &record.kind {
                AttachmentKind::Path => "path",
                AttachmentKind::Url => "url",
            };
            lines.push(table_text(
                &[
                    &record.id,
                    kind,
                    &fit(&record.source, widths.get(2).copied().unwrap_or(22)),
                    &fit(&record.status, widths.get(3).copied().unwrap_or(18)),
                ],
                &widths,
            ));
        }
    }
    lines.push(String::new());
    lines.push("Next: kb [module], attach <path-or-url>, detach <id>, reparse <id>".to_string());
    lines
}

fn plain_config_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    lines.push(String::new());
    lines.push(plain_divider("CONFIG", width));
    lines.push(format!(
        "runtime: {}",
        crate::app::runtime_backend_label(&app.config)
    ));
    lines.push(format!("provider: {}", app.provider_label()));
    lines.push(format!(
        "model: {}",
        app.config.model.as_deref().unwrap_or("unconfigured")
    ));
    lines.push(format!(
        "reasoning: {}",
        app.session_thinking_level.as_deref().unwrap_or("default")
    ));
    lines.push(format!(
        "cost: {}",
        app.last_tool_cost_usd
            .map(|cost| format!("last ${cost:.4}; session ${:.4}", app.session_cost_usd))
            .unwrap_or_else(|| "unavailable until a tool reports costUsd".to_string())
    ));
    if app.config.model.is_none() {
        lines.push("onboarding: model <n> selects an explicit provider:model; no fallback model is selected.".to_string());
    }

    lines.push(String::new());
    lines.push(plain_divider("MODELS", width));
    lines.push(table_text(
        &["#", "model", "effort", "auth"],
        &plain_model_widths(width),
    ));
    let widths = plain_model_widths(width);
    for choice in crate::app::model_choices() {
        lines.push(table_text(
            &[
                &choice.index.to_string(),
                &fit(choice.id, widths.get(1).copied().unwrap_or(28)),
                choice.thinking_level,
                &fit(
                    &model_auth_status(choice),
                    widths.get(3).copied().unwrap_or(18),
                ),
            ],
            &widths,
        ));
    }
    lines.push(String::new());
    lines.push(
        "Next: model <n> [xhigh], auth login openai-codex, auth login anthropic, cost".to_string(),
    );
    lines
}

fn plain_context_strip(app: &ShellApp, width: usize) -> Vec<String> {
    let target = app
        .target
        .as_ref()
        .map(|path| {
            format!(
                "target:{}",
                compact_target_path(&path.display().to_string())
            )
        })
        .unwrap_or_else(|| "target:none".to_string());
    let module = if matches!(app.shell_view, ShellView::AgentChat) {
        "agent".to_string()
    } else {
        app.focused_module
            .clone()
            .unwrap_or_else(|| "catalog".to_string())
    };
    vec![fit(
        &format!(
            "{} | {target} | {module} | {} | {} mods",
            routing_mode_segment(app),
            findings_count_summary(&app.findings),
            app.registry.modules().count()
        ),
        width,
    )]
}

fn plain_model_widths(width: usize) -> Vec<usize> {
    let number = 3;
    let effort = 6;
    let model = if width < 88 { 28 } else { 34 };
    let gaps = 6;
    let auth = width.saturating_sub(number + model + effort + gaps).max(14);
    vec![number, model, effort, auth]
}

fn plain_divider(title: &str, width: usize) -> String {
    let safe_width = width.max(8);
    let title = format!(" {title} ");
    let remaining = safe_width.saturating_sub(title.chars().count());
    let left = remaining / 2;
    let right = remaining.saturating_sub(left);
    format!("{}{}{}", "-".repeat(left), title, "-".repeat(right))
}

fn line_to_plain_text(line: Line<'static>) -> String {
    line.spans
        .into_iter()
        .map(|span| span.content.into_owned())
        .collect::<String>()
}

fn finalize_plain_lines(lines: Vec<String>, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    for line in lines {
        let line = sanitize_plain_line(&line);
        if line.chars().count() <= width {
            out.push(line);
        } else if should_truncate_plain_line(&line) {
            out.push(sanitize_plain_line(&fit(&line, width)));
        } else {
            out.extend(
                wrap_text(&line, width)
                    .into_iter()
                    .map(|line| sanitize_plain_line(&line)),
            );
        }
    }
    out
}

fn should_truncate_plain_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }
    if line.starts_with("mode:") {
        return true;
    }
    if trimmed.chars().all(|ch| {
        ch == '-' || ch == ' ' || ch == '/' || ch.is_ascii_uppercase() || ch.is_ascii_digit()
    }) {
        return true;
    }

    let padded_column_gaps = line.matches("  ").count();
    padded_column_gaps >= 3
}

fn sanitize_plain_line(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            '\u{2500}'..='\u{257f}' => '-',
            '·' => '|',
            _ => ch,
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoutingMode {
    Shell,
    Module,
    Agent,
    Plan,
    Run,
}

fn routing_mode(app: &ShellApp) -> RoutingMode {
    if app.scan.as_ref().is_some_and(|scan| scan.running)
        || matches!(app.shell_view, ShellView::ModuleRun)
    {
        RoutingMode::Run
    } else if matches!(app.shell_view, ShellView::AgentChat)
        || app.agent_chat.as_ref().is_some_and(|agent| agent.running)
    {
        RoutingMode::Agent
    } else if app.planner_running || app.pending_plan.is_some() {
        RoutingMode::Plan
    } else if app.focused_module.is_some() {
        RoutingMode::Module
    } else {
        RoutingMode::Shell
    }
}

fn routing_mode_segment(app: &ShellApp) -> String {
    match routing_mode(app) {
        RoutingMode::Shell => "mode:shell",
        RoutingMode::Module => "mode:module",
        RoutingMode::Agent => "mode:agent",
        RoutingMode::Plan => "mode:plan",
        RoutingMode::Run => "mode:run",
    }
    .to_string()
}

fn trim_plain_lines(mut lines: Vec<String>) -> Vec<String> {
    while lines.first().is_some_and(|line| line.trim().is_empty()) {
        lines.remove(0);
    }
    while lines.last().is_some_and(|line| line.trim().is_empty()) {
        lines.pop();
    }
    lines
}

fn catalog_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(Line::from(vec![
        Span::styled("KUZUSHI · CATALOG", theme::heading()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled("kuzushi shell", theme::muted()),
    ]));
    lines.push(blank());

    let modules = app.registry.modules().collect::<Vec<_>>();
    if modules.is_empty() {
        lines.push(styled("[!] No modules loaded", theme::warn()));
        lines.push(muted("Run kuzushi modules to inspect the native registry."));
        return lines;
    }

    if !app.catalog_expanded {
        if app.target.is_none() {
            lines.push(styled(
                "[!] no target selected; `scan .` uses the current directory",
                theme::warn(),
            ));
        } else if app.findings.is_empty() {
            lines.push(styled(
                "[!] active target has no persisted findings yet",
                theme::warn(),
            ));
        }
        lines.push(next_action_line(
            &app.first_finding_hint(),
            area.width as usize,
        ));
        lines.push(muted(&fit(
            "Quickstart: quickstart · Context: context build · Runtime: model",
            area.width as usize,
        )));
        lines.push(muted(
            "Type help, modules, use <module>, scan, or run <tool> [json].",
        ));
        return lines;
    }

    if let Some(module) = modules
        .iter()
        .find(|module| module.metadata().id == "sast")
        .or_else(|| {
            modules
                .iter()
                .find(|module| module.metadata().id == "semgrep")
        })
        .or_else(|| modules.first())
    {
        let hint = format!(
            "Run {} against the active target — {}",
            module.metadata().id,
            short_sentence(&module.metadata().description, 88)
        );
        lines.push(next_action_line(&hint, area.width as usize));
        lines.push(blank());
    }

    let mut grouped: BTreeMap<&'static str, Vec<_>> = BTreeMap::new();
    for module in modules {
        grouped
            .entry(catalog_module_category(
                &module.metadata().id,
                module.metadata().kind,
            ))
            .or_default()
            .push(module);
    }

    for category in ["OFFENSE", "INTEL", "GOVERNANCE", "DEFENSE"] {
        let Some(rows) = grouped.get(category) else {
            continue;
        };
        let (_, blurb) = module_category_blurb(category);
        let widths = module_table_widths(area.width);
        lines.push(divider(category, area.width));
        lines.push(indent(
            muted(&fit(blurb, area.width.saturating_sub(2) as usize)),
            2,
        ));
        lines.push(table_header(&["id", "description"], &widths));
        for module in rows {
            lines.push(catalog_module_row(
                &module.metadata().id,
                &module.metadata().description,
                app.focused_module.as_deref() == Some(module.metadata().id.as_str()),
                &widths,
            ));
        }
        lines.push(blank());
    }

    lines
}

fn module_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let Some(module_id) = &app.focused_module else {
        return catalog_lines(app, area);
    };
    let Some(module) = app
        .registry
        .modules()
        .find(|module| module.metadata().id == *module_id)
    else {
        return catalog_lines(app, area);
    };

    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(transcript_line(
        ">",
        &format!("/use {}", module.metadata().id),
        false,
    ));
    let primary_tool = module
        .tools()
        .first()
        .map(|tool| tool.name.as_str())
        .unwrap_or("no-tool");
    lines.push(transcript_line(
        "use",
        &format!(
            "focused module {} · primary tool {}",
            module.metadata().id,
            primary_tool
        ),
        false,
    ));
    lines.push(Line::from(vec![
        Span::styled(module.metadata().id.clone(), theme::heading()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(module.metadata().name.clone(), theme::muted()),
    ]));
    lines.push(indent(
        muted(&short_sentence(
            &module.metadata().description,
            area.width.saturating_sub(2) as usize,
        )),
        2,
    ));
    lines.push(blank());

    if module.tools().is_empty() {
        lines.push(muted("No shell tools are exposed by this module."));
    } else {
        lines.push(divider("TOOLS", area.width));
        for tool in module.tools() {
            lines.push(tool_console_row(
                &tool.name,
                &tool.description,
                tool.headless,
                area.width,
            ));
        }
    }

    lines.push(blank());
    let activity_label = match module.metadata().id.as_str() {
        "recon" => Some("RECENT RECON ACTIVITY"),
        "carlini-threat-hunt" => Some("RECENT THREAT-HUNT ACTIVITY"),
        "agentic-sast" => Some("RECENT AGENTIC-SAST ACTIVITY"),
        _ => None,
    };
    if let Some(label) = activity_label {
        let recent: Vec<(String, String)> = recent_module_log(app, module.metadata().id.as_str(), 8);
        if !recent.is_empty() {
            lines.push(section_header_line(label, area.width));
            for (prefix, body) in &recent {
                for body_line in body.lines() {
                    lines.push(transcript_line(prefix, body_line, false));
                }
            }
            lines.push(blank());
        }
    }
    lines.extend(module_playbook_lines(
        module.metadata().id.as_str(),
        area.width,
    ));

    lines
}

/// Pull the most recent N log lines that look like they came from the given
/// module (by prefix or body match). Returns oldest-first.
fn recent_module_log(app: &ShellApp, module_id: &str, take: usize) -> Vec<(String, String)> {
    let module_id = module_id.to_string();
    let mut matches: Vec<(String, String)> = app
        .log
        .iter()
        .rev()
        .filter(|line| {
            line.prefix == module_id
                || line.prefix.starts_with(&format!("{module_id}:"))
                || line.body.contains(&format!("{module_id}:"))
                || (module_id == "recon"
                    && (line.prefix == "tool" || line.prefix == "result")
                    && line.body.contains("recon"))
        })
        .take(take)
        .map(|line| (line.prefix.clone(), line.body.clone()))
        .collect();
    matches.reverse();
    matches
}

fn module_run_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let scan = app.scan.as_ref();
    let target = scan
        .map(|scan| compact_target_path(&scan.target.display().to_string()))
        .or_else(|| {
            app.target
                .as_ref()
                .map(|path| compact_target_path(&path.display().to_string()))
        })
        .unwrap_or_else(|| "target:none".to_string());
    let stage = scan.map(scan_status).unwrap_or_else(|| "idle".to_string());
    let findings = scan
        .map(|scan| scan.findings_count)
        .unwrap_or(app.findings.len());
    let run = scan
        .and_then(|scan| scan.run_id.as_ref())
        .map(|run_id| format!("run {}", short(run_id)))
        .unwrap_or_else(|| {
            if scan.is_some() {
                "run pending".to_string()
            } else {
                "tool run".to_string()
            }
        });

    lines.push(blank());
    lines.push(Line::from(vec![
        Span::styled(run_state_glyph(scan), run_state_style(scan)),
        Span::raw(" "),
        Span::styled(target, theme::label()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::raw(stage),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(format!("{findings} finding(s)"), theme::muted()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(run, theme::muted()),
    ]));
    lines.push(blank());

    let active_stage = scan.map(|scan| scan.stage.as_str()).unwrap_or("idle");
    let scan_running = scan.is_some_and(|s| s.running);
    let scan_done =
        scan.is_some() && !scan_running && scan.and_then(|s| s.error.as_ref()).is_none();
    lines.push(divider("SCAN PROGRESS", area.width));

    let sast_rows = app.sast_task_rows();
    let show_per_task = sast_rows.iter().any(|r| r.selected)
        && app.focused_module.as_deref() == Some("sast")
        && (scan_running || scan_done);
    if show_per_task {
        for row in &sast_rows {
            if !row.selected {
                continue;
            }
            let (kind, done_count, total, status) = if scan_done {
                (ProgressKind::Done, 1usize, 1usize, "done".to_string())
            } else {
                (ProgressKind::Active, 0usize, 1usize, "running…".to_string())
            };
            lines.push(progress_bar_line(row.id, done_count, total, &status, kind));
        }
        lines.push(progress_bar_line(
            "triage",
            if scan_done && findings > 0 { 0 } else { 0 },
            findings.max(1),
            if findings > 0 {
                "queued after scan"
            } else {
                "waiting for findings"
            },
            if findings > 0 {
                ProgressKind::Active
            } else {
                ProgressKind::Failing
            },
        ));
    } else {
        lines.push(pipeline_row(
            if active_stage.contains("context") {
                "⏵"
            } else {
                "✓"
            },
            "context:build",
            if active_stage.contains("context") {
                "active"
            } else {
                "ready"
            },
        ));
        lines.push(pipeline_row(
            if scan_running {
                "⏵"
            } else if scan.is_some() {
                "✓"
            } else {
                "○"
            },
            "sast:scan",
            active_stage,
        ));
        lines.push(pipeline_row(
            "○",
            "triage:run",
            if findings > 0 {
                "queued after scan"
            } else {
                "waiting for findings"
            },
        ));
    }

    if let Some(error) = scan.and_then(|scan| scan.error.as_ref()) {
        lines.push(blank());
        lines.push(transcript_line("error", error, false));
    }

    if !app.findings.is_empty() {
        lines.push(blank());
        let triaged = app.findings.iter().filter(|f| f.triage.is_some()).count();
        let pending = app.findings.len().saturating_sub(triaged);
        let header = format!(
            "FINDINGS · {triaged} triaged · {pending} pending",
        );
        lines.push(section_header_line(&header, area.width));
        let aliases = sorted_finding_aliases(&app.findings);
        for (alias, finding) in aliases.into_iter().take(8) {
            lines.push(compact_finding_row(
                &alias,
                finding.severity,
                &finding.title,
                &finding_location(&finding),
                area.width,
            ));
        }
        if app.findings.len() > 8 {
            lines.push(Line::from(vec![
                Span::raw("   "),
                Span::styled(
                    format!("… {} more · ", app.findings.len() - 8),
                    theme::muted(),
                ),
                Span::styled("/findings", theme::accent()),
                Span::styled(" to drill in", theme::muted()),
            ]));
        }
    }

    lines.push(blank());
    lines.push(divider("TRANSCRIPT", area.width));
    let body_budget = area.height.saturating_sub(lines.len() as u16) as usize;
    let transcript = transcript_lines(app, body_budget.saturating_sub(1).max(0));
    lines.extend(transcript);
    if scan_running && body_budget > 0 {
        lines.push(streaming_cursor_line());
    }
    lines
}

/// One-row streaming cursor block — a single styled cell at the end of the
/// transcript that mirrors the design's `<span className="cursor">` from the
/// running mockups (sast-running.jsx, carlini-running.jsx, agentic-sast-running.jsx).
fn streaming_cursor_line() -> Line<'static> {
    Line::from(vec![
        Span::raw(" "),
        Span::styled(
            " ",
            Style::default().fg(theme::TERM_BG).bg(theme::T_PRIMARY),
        ),
    ])
}

fn findings_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(Line::from(vec![
        Span::styled("filters ", theme::label()),
        Span::styled("[all] ", theme::selection()),
        Span::styled("[critical] [high] [medium] [low]", theme::muted()),
    ]));
    lines.push(blank());

    if app.findings.is_empty() {
        lines.push(muted("No findings yet."));
        lines.push(muted(
            "Next: scan, scan <target>, or context build before scanning.",
        ));
        return lines;
    }

    let widths = finding_summary_widths(area.width.saturating_sub(2));
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(
            table_text(
                &[
                    "alias",
                    "severity",
                    "verdict",
                    "conf",
                    "proof/static",
                    "cwe",
                    "source",
                ],
                &widths,
            ),
            theme::subtle(),
        ),
    ]));
    let aliases = sorted_finding_aliases(&app.findings);
    let cursor = app.findings_cursor.min(aliases.len().saturating_sub(1));
    let mut body = Vec::new();
    for (index, (alias, finding)) in aliases.into_iter().enumerate() {
        let selected = app
            .selected_finding
            .as_ref()
            .is_some_and(|selected| selected.fingerprint.as_str() == finding.fingerprint.as_str());
        let cursor_row = app.findings_cursor == index;
        let marker = if cursor_row {
            ">"
        } else if selected {
            "*"
        } else {
            " "
        };
        body.push(Line::from(vec![
            Span::styled(marker, theme::subtle()),
            Span::raw(" "),
            Span::styled(
                pad(&alias, widths.first().copied().unwrap_or(8)),
                theme::accent(),
            ),
            Span::raw("  "),
            Span::styled(
                pad(
                    finding.severity.as_str(),
                    widths.get(1).copied().unwrap_or(8),
                ),
                theme::severity(finding.severity),
            ),
            Span::raw("  "),
            Span::raw(pad(
                &finding_verdict_label(&finding),
                widths.get(2).copied().unwrap_or(9),
            )),
            Span::raw("  "),
            Span::raw(pad(
                &finding_confidence_label(&finding),
                widths.get(3).copied().unwrap_or(5),
            )),
            Span::raw("  "),
            Span::raw(pad(
                &finding_proof_state_label(&finding),
                widths.get(4).copied().unwrap_or(12),
            )),
            Span::raw("  "),
            Span::raw(pad(
                &finding_cwe_label(&finding),
                widths.get(5).copied().unwrap_or(8),
            )),
            Span::raw("  "),
            Span::raw(fit(
                &finding_source_label(&finding),
                widths.get(6).copied().unwrap_or(12),
            )),
        ]));
        body.push(indent(
            muted(&fit(
                &format!("loc {} | {}", finding_location(&finding), finding.title),
                area.width.saturating_sub(2) as usize,
            )),
            2,
        ));
        body.push(indent(
            muted(&fit(
                &format!(
                    "evidence: {} | next: open {}",
                    finding_evidence_preview(&finding),
                    alias
                ),
                area.width.saturating_sub(2) as usize,
            )),
            2,
        ));
    }

    let body_height = area.height.saturating_sub(lines.len() as u16) as usize;
    if body_height == 0 {
        return lines;
    }
    let row_height = 3;
    let visible_rows = (body_height / row_height).max(1);
    let start_row = viewport_start_for_cursor(app.findings.len(), visible_rows, cursor);
    lines.extend(
        body.into_iter()
            .skip(start_row * row_height)
            .take(body_height),
    );
    lines
}

fn finding_detail_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let Some(finding) = &app.selected_finding else {
        return findings_lines(app, area);
    };

    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(Line::from(vec![
        Span::styled(finding.severity.as_str(), theme::severity(finding.severity)),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(finding.title.clone(), theme::heading()),
    ]));
    lines.push(blank());
    if let Some(alias) = stable_finding_alias(&app.findings, &finding.fingerprint) {
        lines.push(detail("alias", &alias));
    }
    lines.push(detail(
        "location",
        &format!("{}:{}", finding.file_path, finding.start_line),
    ));
    lines.push(detail("rule", &finding.rule_id));
    lines.push(detail("tool", &finding.tool));
    lines.push(detail("fingerprint", &finding.fingerprint));
    lines.push(blank());
    lines.push(divider("EVIDENCE", area.width));
    for line in finding.message.lines().take(8) {
        lines.push(indent(
            Line::raw(fit(line, area.width.saturating_sub(2) as usize)),
            2,
        ));
    }

    if let Some(triage) = &finding.triage {
        lines.push(blank());
        lines.push(divider("TRIAGE", area.width));
        lines.push(detail("verdict", triage.verdict.as_str()));
        lines.push(detail("confidence", &format!("{:.2}", triage.confidence)));
        lines.push(detail("rationale", &triage.rationale));
    }

    lines
}

fn tune_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let module = app.focused_module.as_deref().unwrap_or("semgrep");
    lines.push(blank());
    lines.push(divider("TUNE", area.width));
    lines.push(detail("module", module));
    lines.push(detail("severity floor", "medium"));
    lines.push(detail("triage confidence", "0.70"));
    lines.push(detail("scan concurrency", "adaptive"));
    lines.push(detail(
        "house rules",
        &format!(".kuzushi/house-rules/{module}.md"),
    ));
    lines.push(blank());
    match app.read_house_rules() {
        Some(text) if !text.trim().is_empty() => {
            lines.push(divider("HOUSE RULES", area.width));
            for raw in text
                .lines()
                .take((area.height as usize).saturating_sub(10).max(4))
            {
                lines.push(Line::raw(fit(raw, area.width as usize)));
            }
            lines.push(blank());
        }
        _ => {
            lines.push(muted(
                "(no house rules set; type `set \"...\"` to add some)",
            ));
        }
    }
    lines.push(muted(
        "Verbs (no slash needed): show · set \"...\" · reset · prompt edit <verb> · back",
    ));
    lines
}

fn threat_lines(app: &ShellApp, area: Rect, view: ThreatView) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(threat_nav(view));
    lines.push(blank());

    match view {
        ThreatView::Dfd => {
            lines.push(section_header_line("DFD · acme-checkout", area.width));
            lines.extend(dfd_canonical_lines());
            if let Some(doc) = current_threat_model_doc(app) {
                if let Some(nodes) = dfd_nodes_from_doc(&doc) {
                    lines.push(blank());
                    lines.push(section_header_line(
                        &format!("NODES FROM threat-model.json · {}", nodes.len()),
                        area.width,
                    ));
                    for (id, node_type, zone) in nodes.into_iter().take(8) {
                        lines.push(Line::from(vec![
                            Span::raw("   "),
                            Span::styled(pad(&id, 24), theme::accent()),
                            Span::styled(pad(&node_type, 16), theme::muted()),
                            Span::styled(zone, theme::subtle()),
                        ]));
                    }
                }
            }
        }
        ThreatView::Stride => {
            let doc = current_threat_model_doc(app);
            let rollup = doc
                .as_ref()
                .and_then(stride_rollup_from_doc)
                .unwrap_or_else(stride_rollup_rows);
            let total_issues: usize = rollup.iter().map(|r| r.3).sum();
            lines.push(section_header_line(
                &format!("STRIDE ROLLUP · {total_issues} issues"),
                area.width,
            ));
            for (letter, sev, category, count, description) in &rollup {
                lines.push(stride_row(
                    letter,
                    *sev,
                    category,
                    *count,
                    description,
                    area.width,
                ));
            }
        }
        ThreatView::Stories => {
            let doc = current_threat_model_doc(app);
            let stories = doc
                .as_ref()
                .and_then(stories_from_doc)
                .unwrap_or_else(canonical_stories_fixture);
            lines.push(section_header_line(
                &format!("ATTACKER STORIES · {}", stories.len()),
                area.width,
            ));
            for (id, severity, title, attack, location) in stories.into_iter().take(8) {
                lines.push(Line::from(vec![
                    Span::raw("   "),
                    Span::styled("▸ ", theme::warn()),
                    Span::styled(pad(&id, 8), theme::accent()),
                    Span::styled(
                        pad(&severity.as_str().to_uppercase(), 9),
                        theme::severity(severity),
                    ),
                    Span::styled(title, theme::primary()),
                ]));
                if !attack.is_empty() {
                    lines.push(Line::from(vec![
                        Span::raw("              "),
                        Span::styled("attack ", theme::subtle()),
                        Span::styled(attack, theme::muted()),
                    ]));
                }
                if !location.is_empty() {
                    lines.push(Line::from(vec![
                        Span::raw("              "),
                        Span::styled("loc    ", theme::subtle()),
                        Span::styled(location, theme::muted()),
                    ]));
                }
            }
        }
        ThreatView::Scope => {
            let doc = current_threat_model_doc(app);
            let buckets = doc
                .as_ref()
                .and_then(scope_buckets_from_doc)
                .unwrap_or_else(canonical_scope_buckets);
            let total: usize = buckets.iter().map(|(_, _, items)| items.len()).sum();
            lines.push(section_header_line(
                &format!("SCOPE · {total} issues"),
                area.width,
            ));
            for (severity, label, items) in &buckets {
                if items.is_empty() {
                    continue;
                }
                lines.push(Line::from(vec![
                    Span::raw("   "),
                    Span::styled(
                        format!("{} · {}", label.to_uppercase(), items.len()),
                        theme::severity(*severity),
                    ),
                ]));
                for item in items.iter().take(4) {
                    lines.push(Line::from(vec![
                        Span::raw("      "),
                        Span::styled("• ", theme::subtle()),
                        Span::styled(item.clone(), theme::muted()),
                    ]));
                }
                if items.len() > 4 {
                    lines.push(Line::from(vec![
                        Span::raw("      "),
                        Span::styled(format!("… {} more", items.len() - 4), theme::subtle()),
                    ]));
                }
            }
            lines.push(blank());
            lines.push(Line::from(vec![
                Span::raw("   "),
                Span::styled("OUT OF SCOPE", theme::muted()),
            ]));
            lines.push(Line::from(vec![
                Span::raw("      "),
                Span::styled("• ", theme::subtle()),
                Span::styled("generated caches, vendored fixtures", theme::muted()),
            ]));
        }
        ThreatView::Summary => {
            let doc = current_threat_model_doc(app);
            let rollup = doc
                .as_ref()
                .and_then(stride_rollup_from_doc)
                .unwrap_or_else(stride_rollup_rows);
            let total_issues: usize = rollup.iter().map(|r| r.3).sum();
            lines.push(section_header_line(
                &format!("THREAT MODEL · {total_issues} issues"),
                area.width,
            ));
            for (letter, sev, category, count, description) in &rollup {
                lines.push(stride_row(
                    letter,
                    *sev,
                    category,
                    *count,
                    description,
                    area.width,
                ));
            }
            lines.push(blank());
            lines.push(transcript_line(
                "agent",
                "biggest delta from last model: admin.acme-checkout.com shares the jwt secret.",
                false,
            ));
            lines.push(transcript_line(
                "flow",
                "recommend split signing keys + audience claim",
                false,
            ));
            lines.push(transcript_line(
                "log",
                "artifact .kuzushi/threat-model.json (proposed v4 · +12 −3)",
                false,
            ));
        }
    }

    lines
}

fn threat_editor_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("THREAT MODEL EDIT", area.width));
    lines.push(detail("artifact", ".kuzushi/threat-model.json"));
    lines.push(detail("mode", "operator edits"));
    lines.push(detail("sections", "elements, boundaries, stories, scope"));
    lines
}

fn prompts_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let module = app.focused_module.as_deref().unwrap_or("semgrep");
    lines.push(blank());
    lines.push(divider("PROMPTS", area.width));
    lines.push(detail("module", module));
    lines.push(blank());
    lines.push(header(&["verb", "source", "override path"]));
    for verb in ["scan", "triage", "verify", "summary"] {
        lines.push(row(&[
            pad(verb, 12),
            "builtin".to_string(),
            fit(
                &format!(".kuzushi/prompts/{module}/{verb}.md"),
                value_width(area, 28),
            ),
        ]));
    }
    lines
}

fn actor_detail_lines(app: &ShellApp, area: Rect, index: usize) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider(&format!("ACTOR {index}"), area.width));
    lines.push(detail("tool", "semgrep:scan"));
    lines.push(detail(
        "status",
        app.scan
            .as_ref()
            .map(scan_status)
            .unwrap_or_else(|| "idle".to_string())
            .as_str(),
    ));
    lines.push(blank());
    lines.extend(transcript_lines(
        app,
        area.height.saturating_sub(6) as usize,
    ));
    lines
}

fn runs_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("RUNS", area.width));
    if let Some(scan) = &app.scan {
        lines.push(header(&["run", "status", "findings", "target"]));
        lines.push(row(&[
            scan.run_id
                .as_deref()
                .map(short)
                .unwrap_or_else(|| "pending".to_string()),
            scan_status(scan),
            scan.findings_count.to_string(),
            fit(&scan.target.display().to_string(), value_width(area, 34)),
        ]));
    } else {
        lines.push(muted(
            "No scan run is active in this shell session. Next: scan <target> or show runs.",
        ));
    }
    lines
}

fn replay_lines(app: &ShellApp, area: Rect, run_id: &str) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("REPLAY", area.width));
    lines.push(detail("run", run_id));
    lines.push(detail(
        "summary",
        &format!(".kuzushi/runs/{run_id}/summary.json"),
    ));
    lines.push(detail(
        "triage",
        &format!(".kuzushi/runs/{run_id}/triage.jsonl"),
    ));
    lines.extend(alias_reference_lines(app, area));
    lines
}

fn trace_lines(app: &ShellApp, area: Rect, run_id: &str) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("TRACE", area.width));
    lines.push(detail("run", run_id));
    lines.push(detail(
        "triage",
        &format!(".kuzushi/runs/{run_id}/triage.jsonl"),
    ));
    lines.push(detail(
        "verify",
        &format!(".kuzushi/runs/{run_id}/verify.jsonl"),
    ));
    lines.extend(alias_reference_lines(app, area));
    lines
}

fn alias_reference_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let aliases = sorted_finding_aliases(&app.findings);
    lines.push(blank());
    if aliases.is_empty() {
        lines.push(muted("aliases: load findings first with findings"));
        return lines;
    }
    lines.push(divider("ALIASES", area.width));
    for (alias, finding) in aliases.into_iter().take(3) {
        lines.push(detail(
            &alias,
            &format!("{} {}", short(&finding.fingerprint), finding.title),
        ));
    }
    lines
}

fn help_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("HELP", area.width));
    lines.push(muted(&fit(
        "Input: ? opens help; ?text, /ask <question>, and ask <question> enter agent mode.",
        area.width as usize,
    )));
    let examples = shell_help_examples();
    if !examples.is_empty() {
        lines.push(muted(&fit(
            &format!("Examples: {}", examples.join(" | ")),
            area.width as usize,
        )));
    }
    let widths = help_table_widths(area.width);
    for category in ShellCommandCategory::ORDER {
        lines.push(blank());
        lines.push(Line::styled(category.label(), theme::subtle()));
        if widths.len() == 2 {
            lines.push(table_header(&["command", "aliases / examples"], &widths));
        } else {
            lines.push(table_header(
                &["command", "aliases / examples", "description"],
                &widths,
            ));
        }
        for spec in shell_command_specs()
            .iter()
            .filter(|spec| spec.category == category)
        {
            let command = fit(spec.command, widths.first().copied().unwrap_or(18));
            let aliases = help_alias_text(spec, widths.get(1).copied().unwrap_or(18));
            if widths.len() == 2 {
                lines.push(table_row(&[&command, &aliases], &widths));
            } else {
                let description = fit(spec.description, widths.get(2).copied().unwrap_or(20));
                lines.push(table_row(&[&command, &aliases, &description], &widths));
            }
        }
    }
    lines
}

fn help_table_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    if total < 72 {
        let command = total.min(if total < 48 { 14 } else { 18 });
        let aliases = total.saturating_sub(command + 2);
        return vec![command, aliases];
    }

    let command = if total < 96 { 22 } else { 28 };
    let aliases = if total < 96 { 24 } else { 32 };
    let description = total.saturating_sub(command + aliases + 4);
    vec![command, aliases, description]
}

fn help_alias_text(spec: &ShellCommandSpec, max_chars: usize) -> String {
    let mut aliases = Vec::new();
    for alias in spec.aliases {
        if *alias == spec.command || aliases.contains(alias) {
            continue;
        }
        aliases.push(*alias);
    }
    if aliases.is_empty() {
        "-".to_string()
    } else {
        fit(&aliases.join(", "), max_chars)
    }
}

fn config_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("CONFIG", area.width));
    lines.push(detail(
        "backend",
        crate::app::runtime_backend_label(&app.config),
    ));
    lines.push(detail("provider", &app.provider_label()));
    lines.push(detail(
        "model",
        app.config.model.as_deref().unwrap_or("unconfigured"),
    ));
    lines.push(detail(
        "reasoning",
        app.session_thinking_level.as_deref().unwrap_or("default"),
    ));
    let auth_status = if std::env::var_os(&app.config.runtime.api_key_env).is_some() {
        "set; value hidden"
    } else {
        "missing"
    };
    lines.push(detail(
        "auth envs",
        &format!(
            "{} ({auth_status}); ANTHROPIC_API_KEY ({})",
            app.config.runtime.api_key_env,
            if std::env::var_os("ANTHROPIC_API_KEY").is_some() {
                "set; value hidden"
            } else {
                "missing"
            }
        ),
    ));
    lines.push(detail(
        "oauth",
        &format!(
            "openai-codex {}; anthropic {}",
            crate::app::oauth_provider_status("openai-codex"),
            crate::app::oauth_provider_status("anthropic")
        ),
    ));
    lines.push(detail(
        "base url",
        app.config
            .runtime
            .base_url
            .as_deref()
            .unwrap_or("provider default"),
    ));
    lines.push(detail(
        "bridge",
        crate::app::bridge_command_status(&app.config),
    ));
    lines.push(detail(
        "cost",
        &if let Some(last) = app.last_tool_cost_usd {
            format!(
                "session ${:.4}; last tool ${:.4}",
                app.session_cost_usd, last
            )
        } else {
            "unavailable until a tool reports costUsd".to_string()
        },
    ));
    if app.config.model.is_none() {
        lines.push(detail(
            "onboarding",
            "Up/Down selects a model; Enter activates it. OAuth availability is shown below.",
        ));
    }
    lines.push(blank());
    lines.push(divider("MODELS", area.width));
    lines.push(header(&["", "#", "model", "effort", "auth"]));
    for (index, choice) in crate::app::model_choices().iter().enumerate() {
        let marker = if index == app.selected_model_index {
            ">"
        } else {
            " "
        };
        lines.push(row(&[
            marker.to_string(),
            choice.index.to_string(),
            fit(choice.id, 28),
            choice.thinking_level.to_string(),
            fit(&model_auth_status(choice), value_width(area, 28)),
        ]));
    }
    lines.push(blank());
    lines.push(muted(&fit(
        "Up/Down select · Enter choose · model <n> [xhigh] · auth login openai-codex|anthropic",
        area.width as usize,
    )));
    lines
}

fn model_auth_status(choice: &crate::app::ModelChoice) -> String {
    match choice.provider {
        "openai" => {
            if std::env::var_os("OPENAI_API_KEY").is_some() {
                "OPENAI_API_KEY set".to_string()
            } else {
                "OPENAI_API_KEY missing".to_string()
            }
        }
        "openai-codex" => {
            let status = crate::app::oauth_provider_status("openai-codex");
            if status.starts_with("stored") {
                "OAuth ready".to_string()
            } else {
                "OAuth missing".to_string()
            }
        }
        "anthropic" => {
            let env_ready = std::env::var_os("ANTHROPIC_API_KEY").is_some();
            let oauth_ready = crate::app::oauth_provider_status("anthropic").starts_with("stored");
            match (env_ready, oauth_ready) {
                (true, true) => "ANTHROPIC_API_KEY/OAuth ready".to_string(),
                (true, false) => "ANTHROPIC_API_KEY set".to_string(),
                (false, true) => "OAuth ready".to_string(),
                (false, false) => "ANTHROPIC auth missing".to_string(),
            }
        }
        _ => choice.auth.to_string(),
    }
}

fn tools_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("TOOLS", area.width));
    lines.push(header(&["tool", "headless", "description"]));
    for tool in app.registry.tools() {
        lines.push(row(&[
            fit(&tool.name, 24),
            tool.headless.to_string(),
            fit(&tool.description, value_width(area, 40)),
        ]));
    }
    lines
}

fn options_lines(app: &ShellApp, area: Rect, view: &crate::app::OptionsView) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("OPTIONS", area.width));
    lines.push(detail("tool", &view.tool_name));
    lines.push(detail("view", options_filter_label(view.filter)));

    let Some(tool) = app.registry.resolve_tool(&view.tool_name) else {
        lines.push(blank());
        lines.push(muted(
            "Unknown tool. Run tools to inspect the native registry.",
        ));
        return lines;
    };

    let stored = app.option_store.effective_stored_values(&tool.name);
    let specs = tool
        .options
        .iter()
        .filter(|spec| option_visible(spec, view.filter, stored.get(&spec.name).is_some()))
        .collect::<Vec<_>>();

    if specs.is_empty() {
        lines.push(blank());
        let message = match view.filter {
            crate::app::OptionsFilter::Standard => {
                "No standard options. Run show advanced for hidden controls."
            }
            crate::app::OptionsFilter::Advanced => "No advanced options for this tool.",
            crate::app::OptionsFilter::Missing => "No missing required options for this tool.",
        };
        lines.push(muted(message));
        return lines;
    }

    lines.push(blank());
    lines.push(table_header(
        &["option", "value", "default", "req", "type", "description"],
        &option_table_widths(area.width),
    ));
    for spec in specs {
        let current = stored.get(&spec.name);
        let required = if spec.required && current.is_none() && spec.default.is_none() {
            "missing"
        } else if spec.required {
            "yes"
        } else {
            "no"
        };
        let description = option_description(spec);
        let widths = option_table_widths(area.width);
        lines.push(table_row(
            &[
                &spec.name,
                &current
                    .map(format_json_value)
                    .unwrap_or_else(|| "-".to_string()),
                &spec
                    .default
                    .as_ref()
                    .map(format_json_value)
                    .unwrap_or_else(|| "-".to_string()),
                required,
                option_type_label(spec.option_type),
                &fit(&description, widths.get(5).copied().unwrap_or(16)),
            ],
            &widths,
        ));
    }
    lines.push(blank());
    lines.push(muted(&fit(
        "set <key> <value> writes a session option; setg writes a global option for this shell session.",
        area.width as usize,
    )));
    lines
}

fn sast_tasks_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let rows = app.sast_task_rows();
    let enabled = rows.iter().filter(|row| row.selected).count();
    let blocked = rows.iter().filter(|row| row.source == "blocked").count();
    let mode = app
        .option_store
        .effective_stored_values("sast:scan")
        .get("taskMode")
        .and_then(serde_json::Value::as_str)
        .filter(|mode| *mode == "manual")
        .map(|_| "manual allowlist")
        .unwrap_or("auto + denylist");

    lines.push(blank());
    lines.push(divider("SAST TASKS", area.width));
    lines.push(detail("mode", mode));
    lines.push(detail(
        "selected",
        &format!("{enabled}/{} enabled, {blocked} blocked", rows.len()),
    ));
    lines.push(blank());
    lines.push(table_header(
        &["state", "id", "cost", "scan", "notes"],
        &sast_task_table_widths(area.width),
    ));
    let widths = sast_task_table_widths(area.width);
    for row in rows {
        lines.push(table_row(
            &[
                row.state,
                row.id,
                row.cost,
                row.scan_task,
                &fit(row.notes, widths.get(4).copied().unwrap_or(20)),
            ],
            &widths,
        ));
    }
    lines.push(blank());
    lines.push(muted(&fit(
        "/task block <id> · /task allow <id> · /task toggle [id] · /task mode auto|manual|toggle · /task reset",
        area.width as usize,
    )));
    lines
}

fn context_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let view = &app.context_view;

    lines.push(blank());
    lines.push(divider("CONTEXT", area.width));
    lines.push(detail(
        "snapshot",
        &view
            .snapshot_path
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| ".kuzushi/context-snapshot.json".to_string()),
    ));
    lines.push(detail(
        "state",
        if view.exists { "present" } else { "missing" },
    ));
    lines.push(detail("status", &fit(&view.status, value_width(area, 10))));

    if view.exists {
        lines.push(detail(
            "target",
            view.target.as_deref().unwrap_or("unknown"),
        ));
        lines.push(detail(
            "discovery",
            view.discovery.as_deref().unwrap_or("unknown"),
        ));
        lines.push(detail(
            "files",
            &format!(
                "indexed={} total={}",
                view.files_indexed
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "?".to_string()),
                view.total_files
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "?".to_string())
            ),
        ));
        lines.push(detail(
            "languages",
            &fit(&join_or_dash(&view.languages), value_width(area, 10)),
        ));
        lines.push(detail(
            "frameworks",
            &fit(&join_or_dash(&view.frameworks), value_width(area, 10)),
        ));
        lines.push(detail(
            "generated",
            &fit(&join_or_dash(&view.generated_slices), value_width(area, 10)),
        ));
        lines.push(detail(
            "stale",
            &fit(&join_or_dash(&view.stale_slices), value_width(area, 10)),
        ));
    } else {
        lines.push(blank());
        lines.push(muted(
            "No context snapshot exists yet. Run context build to write .kuzushi/context-snapshot.json.",
        ));
    }

    lines.push(blank());
    lines.push(muted(&fit(
        "context build · context status · context regen repo · context regen app-model",
        area.width as usize,
    )));
    lines
}

fn workspace_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let view = &app.workspace_view;

    lines.push(blank());
    lines.push(divider("WORKSPACE", area.width));
    lines.push(detail("status", &fit(&view.status, value_width(area, 10))));
    lines.push(detail(
        "target",
        &view
            .root
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| "none".to_string()),
    ));
    lines.push(detail(
        "state",
        &view
            .state_dir
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| ".kuzushi/v2".to_string()),
    ));
    lines.push(detail(
        "findings db",
        &view
            .findings_db
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| ".kuzushi/v2/findings.sqlite3".to_string()),
    ));
    lines.push(detail(
        "findings",
        &view
            .findings_count
            .map(|count| count.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
    ));
    lines.push(detail(
        "last export",
        &view
            .last_export
            .as_ref()
            .map(|path| compact_target_path(&path.display().to_string()))
            .unwrap_or_else(|| "none".to_string()),
    ));

    if view.root.is_none() {
        lines.push(blank());
        lines.push(muted(
            "No active workspace is selected. Run scan <target> or start kuzushi shell --target .",
        ));
    }

    lines.push(blank());
    lines.push(muted(&fit(
        "workspace status · workspace export findings findings.json · findings export findings.json",
        area.width as usize,
    )));
    lines
}

fn knowledge_base_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let module_id = app.kb_view.module_id.as_str();
    let attachments = app
        .kb_view
        .attachments
        .iter()
        .filter(|record| record.module_id == module_id)
        .collect::<Vec<_>>();
    let store = app
        .kb_view
        .store_path
        .as_ref()
        .map(|path| compact_target_path(&path.display().to_string()))
        .unwrap_or_else(|| ".kuzushi/v2/attachments.json".to_string());

    lines.push(blank());
    lines.push(divider("KB ATTACHMENTS", area.width));
    lines.push(detail("module", module_id));
    lines.push(detail("store", &store));
    lines.push(detail(
        "supported",
        &SUPPORTED_ATTACHMENT_MODULES.join(", "),
    ));
    lines.push(blank());

    lines.push(divider("KNOWN ARTIFACTS", area.width));
    if app.kb_view.artifacts.is_empty() {
        lines.push(muted("No known Rust artifacts for this module."));
    } else {
        lines.push(table_header(
            &["state", "path", "description"],
            &kb_artifact_widths(area.width),
        ));
        let widths = kb_artifact_widths(area.width);
        for artifact in &app.kb_view.artifacts {
            lines.push(table_row(
                &[
                    if artifact.exists {
                        "present"
                    } else {
                        "missing"
                    },
                    &fit(&artifact.path, widths.get(1).copied().unwrap_or(24)),
                    &fit(&artifact.description, widths.get(2).copied().unwrap_or(20)),
                ],
                &widths,
            ));
        }
    }

    lines.push(blank());
    lines.push(divider("ATTACHED", area.width));
    if attachments.is_empty() {
        lines.push(muted(
            "No attachments yet. Use attach <repo-relative-path> or attach https://example/...",
        ));
    } else {
        lines.push(table_header(
            &["id", "kind", "source", "status"],
            &kb_attachment_widths(area.width),
        ));
        let widths = kb_attachment_widths(area.width);
        for record in attachments {
            let kind = match &record.kind {
                AttachmentKind::Path => "path",
                AttachmentKind::Url => "url",
            };
            lines.push(table_row(
                &[
                    &record.id,
                    kind,
                    &fit(&record.source, widths.get(2).copied().unwrap_or(22)),
                    &fit(&record.status, widths.get(3).copied().unwrap_or(18)),
                ],
                &widths,
            ));
        }
    }
    lines.push(blank());
    lines.push(muted(&fit(
        "kb [module] · attach <path-or-url> · detach <id> · reparse <id>",
        area.width as usize,
    )));
    lines
}

fn agent_chat_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("AGENT", area.width));

    let Some(agent) = &app.agent_chat else {
        lines.push(muted("No active question. Use ask <question> or ?text."));
        return lines;
    };

    let status = if agent.abort_requested {
        "abort requested"
    } else if agent.running {
        "running"
    } else if agent.error.is_some() {
        "failed"
    } else {
        "answered"
    };
    lines.push(detail("mode", "agent chat"));
    lines.push(detail("status", status));
    lines.push(detail(
        "model",
        app.config.model.as_deref().unwrap_or("unconfigured"),
    ));
    lines.push(blank());
    lines.push(styled("question", theme::label()));
    lines.push(indent(
        muted(&fit(&agent.question, area.width.saturating_sub(2) as usize)),
        2,
    ));
    lines.push(blank());

    if let Some(error) = &agent.error {
        lines.push(styled("error", theme::danger()));
        lines.push(indent(
            muted(&fit(error, area.width.saturating_sub(2) as usize)),
            2,
        ));
    } else if let Some(answer) = &agent.answer {
        lines.push(styled("answer", theme::label()));
        for line in wrap_text(answer, area.width.saturating_sub(2) as usize)
            .into_iter()
            .take(8)
        {
            lines.push(indent(muted(&line), 2));
        }
    } else if agent.abort_requested {
        lines.push(muted(
            "Abort requested; waiting for pi-agent-core to return. Process kill is not confirmed.",
        ));
    } else {
        lines.push(muted("Waiting for pi-agent-core response..."));
    }

    lines.push(blank());
    lines.push(muted(&fit(
        "ask <question> · ?text · model provider:model-id · back",
        area.width as usize,
    )));
    lines
}

fn history_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("COMMAND HISTORY", area.width));

    let entries = app
        .command_history
        .iter()
        .rev()
        .take(50)
        .collect::<Vec<_>>();
    if entries.is_empty() {
        lines.push(muted("No command history yet. Next: help"));
    } else {
        let start = app.command_history.len().saturating_sub(entries.len()) + 1;
        let width = (start + entries.len()).to_string().len();
        for (offset, command) in entries.into_iter().rev().enumerate() {
            lines.push(row(&[
                format!("{:>width$}", start + offset, width = width),
                fit(command, area.width.saturating_sub(8) as usize),
            ]));
        }
    }

    lines.push(blank());
    lines.push(muted(&fit(
        "clear · run <tool> · show runs · back",
        area.width as usize,
    )));
    lines
}

fn story_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("SESSION STORY · live event timeline", area.width));
    if let Some(scan) = &app.scan {
        let label = if scan.running {
            if scan.abort_requested {
                "abort requested"
            } else if app.is_scan_paused() {
                "paused"
            } else {
                "running"
            }
        } else {
            "idle"
        };
        lines.push(row(&[
            pad("scan", 10),
            fit(
                &format!(
                    "{label} · stage={} · findings={}",
                    scan.stage, scan.findings_count
                ),
                area.width.saturating_sub(14) as usize,
            ),
        ]));
    }
    lines.push(blank());

    let max_events = (area.height as usize).saturating_sub(8).max(8);
    let events = app
        .log
        .iter()
        .filter(|line| line.prefix != ">")
        .rev()
        .take(max_events)
        .collect::<Vec<_>>();
    if events.is_empty() {
        lines.push(muted(
            "No session events yet. Next: run <tool>, ask <question>, or scan <target>",
        ));
    } else {
        for line in events.into_iter().rev() {
            let body_width = area.width.saturating_sub(14) as usize;
            lines.push(row(&[pad(&line.prefix, 10), fit(&line.body, body_width)]));
        }
    }

    lines.push(blank());
    lines.push(muted(&fit(
        "Ctrl+O toggle · /history commands · /show runs · /replay <runId> · /trace <runId>",
        area.width as usize,
    )));
    lines
}

fn kb_artifact_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let state = 7;
    let path = if total < 88 { 30 } else { 42 };
    let gaps = 4;
    let description = total.saturating_sub(state + path + gaps).max(16);
    vec![state, path, description]
}

fn kb_attachment_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let id = 14;
    let kind = 4;
    let source = if total < 88 { 24 } else { 36 };
    let gaps = 6;
    let status = total.saturating_sub(id + kind + source + gaps).max(16);
    vec![id, kind, source, status]
}

fn finding_summary_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let alias = 8;
    let severity = 8;
    let verdict = 9;
    let confidence = 5;
    let proof = 12;
    let cwe = 8;
    let gaps = 12;
    let source = total
        .saturating_sub(alias + severity + verdict + confidence + proof + cwe + gaps)
        .max(10);
    vec![alias, severity, verdict, confidence, proof, cwe, source]
}

fn finding_location(finding: &Finding) -> String {
    match finding.end_line {
        Some(end_line) if end_line > finding.start_line => {
            format!("{}:{}-{}", finding.file_path, finding.start_line, end_line)
        }
        _ => format!("{}:{}", finding.file_path, finding.start_line),
    }
}

fn finding_verdict_label(finding: &Finding) -> String {
    match finding
        .triage
        .as_ref()
        .map(|triage| triage.verdict.as_str())
    {
        Some("true_positive") => "tp",
        Some("false_positive") => "fp",
        Some("needs_review") => "review",
        Some("by_design") => "by-design",
        Some(other) => other,
        None => "untriaged",
    }
    .to_string()
}

fn finding_confidence_label(finding: &Finding) -> String {
    finding
        .triage
        .as_ref()
        .map(|triage| format!("{:.0}%", (triage.confidence.clamp(0.0, 1.0) * 100.0)))
        .unwrap_or_else(|| "-".to_string())
}

fn finding_proof_state_label(finding: &Finding) -> String {
    match finding
        .triage
        .as_ref()
        .map(|triage| triage.verdict.as_str())
    {
        Some("true_positive") => "triaged-tp",
        Some("false_positive") => "triaged-fp",
        Some("needs_review") => "needs-review",
        Some("by_design") => "by-design",
        Some(_) | None => "static-sig",
    }
    .to_string()
}

fn finding_cwe_label(finding: &Finding) -> String {
    extract_cwe(&finding.message)
        .or_else(|| extract_cwe(&finding.rule_id))
        .unwrap_or_else(|| "-".to_string())
}

fn extract_cwe(value: &str) -> Option<String> {
    let upper = value.to_ascii_uppercase();
    for (index, _) in upper.match_indices("CWE") {
        let mut rest = upper[index + 3..].chars();
        while matches!(rest.clone().next(), Some('-' | '_' | ' ' | ':')) {
            rest.next();
        }
        let digits = rest
            .take_while(|ch| ch.is_ascii_digit())
            .collect::<String>();
        if !digits.is_empty() {
            return Some(format!("CWE-{digits}"));
        }
    }
    None
}

fn finding_source_label(finding: &Finding) -> String {
    if finding.rule_id.is_empty() || finding.rule_id.starts_with(&finding.tool) {
        finding.tool.clone()
    } else {
        format!("{}:{}", finding.tool, finding.rule_id)
    }
}

fn finding_evidence_preview(finding: &Finding) -> String {
    let lines = finding
        .message
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();

    if let Some(evidence) = lines.iter().find_map(|line| {
        line.strip_prefix("Evidence:")
            .or_else(|| line.strip_prefix("evidence:"))
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }) {
        return evidence.to_string();
    }

    lines
        .iter()
        .copied()
        .find(|line| *line != finding.title)
        .unwrap_or_else(|| lines.first().copied().unwrap_or(&finding.title))
        .to_string()
}

fn render_throttle_banner(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(throttle) = &app.advisory.throttle else {
        return;
    };
    let text = fit(
        &format!("⚠ rate limit · {} · {}", throttle.source, throttle.message),
        area.width as usize,
    );
    frame.render_widget(Paragraph::new(Line::styled(text, theme::warn())), area);
}

fn render_plan_card(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(plan) = app.pending_plan.as_ref() else {
        return;
    };
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::styled(
        fit(
            &format!("◆ PLAN · goal: {}", plan.goal),
            area.width as usize,
        ),
        theme::accent(),
    ));
    lines.push(Line::styled(
        fit(&format!("  summary: {}", plan.summary), area.width as usize),
        theme::primary(),
    ));
    for change in &plan.changes {
        lines.push(Line::styled(
            fit(&format!("  + {}", change.label()), area.width as usize),
            theme::success(),
        ));
    }
    for note in &plan.unsupported {
        lines.push(Line::styled(
            fit(&format!("  ! unsupported: {note}"), area.width as usize),
            theme::warn(),
        ));
    }
    lines.push(Line::styled(
        fit("[y] apply   [n] discard   /yes   /no", area.width as usize),
        theme::label(),
    ));
    render_lines(frame, area, lines);
}

fn render_cost_cap_halt(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let Some(halt) = app.advisory.budget_halt.as_ref() else {
        return;
    };
    let header = fit(
        &format!(
            "■ COST CAP HALT · spent ${:.4} / cap ${:.4}",
            halt.spent_usd, halt.limit_usd
        ),
        area.width as usize,
    );
    let actions = fit(
        "[c] continue past cap   [a] abort scan",
        area.width as usize,
    );
    let mut lines = vec![Line::styled(header, theme::danger())];
    if area.height > 1 {
        lines.push(Line::styled(actions, theme::warn()));
    }
    render_lines(frame, area, lines);
}

fn render_status_footer(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }

    let left = if app.scan.as_ref().is_some_and(|scan| scan.running) {
        join_segments(&[
            routing_mode_segment(app),
            app.config
                .model
                .clone()
                .unwrap_or_else(|| "unconfigured".to_string()),
            app.scan
                .as_ref()
                .map(scan_status)
                .unwrap_or_else(|| "idle".to_string()),
        ])
    } else if app.agent_chat.as_ref().is_some_and(|agent| agent.running) {
        join_segments(&[
            routing_mode_segment(app),
            app.config
                .model
                .clone()
                .unwrap_or_else(|| "unconfigured".to_string()),
            if app
                .agent_chat
                .as_ref()
                .is_some_and(|agent| agent.abort_requested)
            {
                "agent: abort requested".to_string()
            } else {
                "agent: active".to_string()
            },
        ])
    } else if app.planner_running {
        join_segments(&[
            routing_mode_segment(app),
            app.config
                .model
                .clone()
                .unwrap_or_else(|| "unconfigured".to_string()),
            if app.plan_abort_requested {
                "plan: abort requested".to_string()
            } else {
                "plan: active".to_string()
            },
        ])
    } else if app.threat_worker_running {
        join_segments(&[
            routing_mode_segment(app),
            app.config
                .model
                .clone()
                .unwrap_or_else(|| "unconfigured".to_string()),
            if app.threat_abort_requested {
                "threats: abort requested".to_string()
            } else {
                "threats: active".to_string()
            },
        ])
    } else {
        join_segments(&[
            routing_mode_segment(app),
            app.target
                .as_ref()
                .map(|path| compact_target_path(&path.display().to_string()))
                .unwrap_or_else(|| "target:none".to_string()),
            if app.context_view.exists {
                "ctx: present".to_string()
            } else {
                "ctx: missing".to_string()
            },
            app.focused_module
                .clone()
                .unwrap_or_else(|| "catalog".to_string()),
        ])
    };

    let mut right_segments = vec![findings_summary(&app.findings)];
    if app.ctrl_c_armed() {
        right_segments.insert(0, "Ctrl+C again to exit".to_string());
    }
    let right = join_segments(&right_segments);
    let text = justify(left, right, area.width as usize);
    let style = if app.ctrl_c_armed() {
        theme::warn()
    } else {
        theme::primary()
    };
    frame.render_widget(Paragraph::new(Line::styled(text, style)), area);
}

fn render_keybind_footer(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let mut lines = Vec::new();
    lines.push(Line::styled(
        theme::RULE_CHAR.repeat(area.width as usize),
        theme::subtle(),
    ));

    if area.height > 1 {
        lines.push(Line::styled(
            keybindings_text(app, area.width as usize),
            theme::primary(),
        ));
    }

    render_lines(frame, area, lines);
}

fn render_transcript(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    render_lines(frame, area, transcript_lines(app, area.height as usize));
}

fn render_prompt(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }

    let prompt = match routing_mode(app) {
        RoutingMode::Run => "kuzushi/run> ".to_string(),
        RoutingMode::Agent => "kuzushi/agent> ".to_string(),
        RoutingMode::Plan => "kuzushi/plan> ".to_string(),
        RoutingMode::Module => app
            .focused_module
            .as_ref()
            .map(|module| format!("kuzushi/{module}> "))
            .unwrap_or_else(|| "kuzushi/module> ".to_string()),
        RoutingMode::Shell => "kuzushi> ".to_string(),
    };
    let segments = prompt_segments(&prompt, &app.input, area.width as usize, " ");
    let line = Line::from(vec![
        Span::styled(segments.prompt, theme::label()),
        Span::raw(segments.before_cursor),
        Span::styled(segments.cursor_text, theme::selection()),
        Span::raw(segments.after_cursor),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn context_strip(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let target = app
        .target
        .as_ref()
        .map(|path| compact_target_path(&path.display().to_string()))
        .unwrap_or_else(|| "none".to_string());
    let module = if matches!(app.shell_view, ShellView::AgentChat) {
        "agent".to_string()
    } else {
        app.focused_module
            .clone()
            .unwrap_or_else(|| "catalog".to_string())
    };
    let ctx = if app.context_view.exists {
        "✓ present"
    } else {
        "missing"
    };
    let model = app.config.model.as_deref().unwrap_or("unconfigured");
    let cost = format!("${:.4}", app.session_cost_usd);
    let rest = fit(
        &join_segments(&[
            routing_mode_segment(app),
            format!("target {target}"),
            findings_count_summary(&app.findings),
            format!("ctx {ctx}"),
            format!("module {module}"),
            format!("model {model}"),
            format!("cost {cost}"),
        ]),
        area.width.saturating_sub(9) as usize,
    );

    vec![Line::from(vec![
        Span::styled("KUZUSHI", theme::heading()),
        Span::raw("  "),
        Span::styled(rest, theme::primary()),
    ])]
}

fn transcript_lines(app: &ShellApp, visible: usize) -> Vec<Line<'static>> {
    if visible == 0 {
        return Vec::new();
    }
    let mut rows = Vec::new();
    for line in &app.log {
        let body_lines = if line.body.is_empty() {
            vec![""]
        } else {
            line.body.lines().collect::<Vec<_>>()
        };
        for (index, body) in body_lines.into_iter().enumerate() {
            rows.push(transcript_line(&line.prefix, body, index > 0));
        }
    }
    let start = rows.len().saturating_sub(visible);
    rows.into_iter().skip(start).collect()
}

fn transcript_line(prefix: &str, body: &str, continuation: bool) -> Line<'static> {
    let (glyph, style, show_label) = transcript_glyph(prefix, continuation);
    let mut spans = vec![Span::styled(format!(" {glyph} "), style)];
    if show_label {
        spans.push(Span::styled(prefix.to_string(), theme::subtle()));
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled(
        body.to_string(),
        transcript_body_style(prefix),
    ));
    Line::from(spans)
}

fn transcript_glyph(prefix: &str, continuation: bool) -> (&'static str, Style, bool) {
    if continuation {
        return ("…", theme::muted(), false);
    }
    match prefix {
        ">" => ("●", theme::accent(), false),
        "tool" | "scan" | "run" | "resume" | "pause" => ("⏵", theme::accent(), true),
        "result" | "answer" | "agent" | "plan" | "threats" => ("◆", theme::accent(), true),
        "finding" | "open" | "title" | "triage" | "aliases" => ("▸", theme::warn(), true),
        "error" => ("✗", theme::danger(), true),
        "system" | "startup" | "first-run" | "help" | "view" | "module" | "prompt" | "tune"
        | "target" | "workspace" | "context" | "history" | "quickstart" | "auth" | "model"
        | "provider" | "backend" | "cost" | "load" | "runs" | "replay" | "trace" => {
            ("·", theme::muted(), true)
        }
        _ => ("·", theme::subtle(), true),
    }
}

fn transcript_body_style(prefix: &str) -> Style {
    match prefix {
        "error" => theme::danger(),
        "finding" | "open" => theme::warn(),
        "result" | "answer" | "agent" => theme::primary(),
        _ => Style::default(),
    }
}

fn keybindings_text(app: &ShellApp, width: usize) -> String {
    let bindings = keybindings(app);
    let mut shown = Vec::new();
    for (key, label) in bindings {
        let next = format!("[{key}] {label}");
        let candidate = if shown.is_empty() {
            next.clone()
        } else {
            format!("{}  ·  {next}", shown.join("  ·  "))
        };
        if candidate.chars().count() > width.saturating_sub(8) && !shown.is_empty() {
            shown.push("+more".to_string());
            break;
        }
        shown.push(next);
    }
    fit(&shown.join("  ·  "), width)
}

fn keybindings(app: &ShellApp) -> Vec<(&'static str, &'static str)> {
    if app.scan.as_ref().is_some_and(|scan| scan.running) {
        let mut bindings = vec![(
            "Ctrl+C",
            if app.scan.as_ref().is_some_and(|scan| scan.abort_requested) {
                "arm exit"
            } else {
                "request abort"
            },
        )];
        push_view_keybindings(&mut bindings, app);
        bindings.extend([("findings", "list"), ("back", "home")]);
        return bindings;
    }
    if app.agent_chat.as_ref().is_some_and(|agent| agent.running)
        || app.planner_running
        || app.threat_worker_running
    {
        let abort_requested = app
            .agent_chat
            .as_ref()
            .is_some_and(|agent| agent.abort_requested)
            || app.plan_abort_requested
            || app.threat_abort_requested;
        return vec![
            (
                "Ctrl+C",
                if abort_requested {
                    "arm exit"
                } else {
                    "request abort"
                },
            ),
            ("back", "home"),
            ("history", "events"),
            ("model", "runtime"),
        ];
    }

    let mut bindings = match app.shell_view {
        ShellView::Catalog if !app.catalog_expanded => vec![
            ("modules", "browse"),
            ("use <id>", "focus module"),
            ("scan", "scan target"),
            ("Ctrl+C", "exit"),
        ],
        ShellView::Catalog => vec![
            ("PgUp/PgDn", "scroll"),
            ("use <id>", "focus module"),
            ("findings", "findings"),
            ("help", "help"),
        ],
        ShellView::Findings => {
            let mut bindings = Vec::new();
            push_view_keybindings(&mut bindings, app);
            bindings.extend([("scan", "rescan"), ("back", "home"), ("Ctrl+C", "exit")]);
            bindings
        }
        ShellView::Finding => vec![
            ("back", "findings"),
            ("findings", "list"),
            ("scan", "rescan"),
            ("Ctrl+C", "exit"),
        ],
        ShellView::Threat(_) => {
            let mut bindings = Vec::new();
            push_view_keybindings(&mut bindings, app);
            bindings.extend([
                ("threats edit", "edit"),
                ("back", "home"),
                ("Ctrl+C", "exit"),
            ]);
            bindings
        }
        ShellView::ModuleRun => {
            let mut bindings = Vec::new();
            push_view_keybindings(&mut bindings, app);
            bindings.extend([("findings", "list"), ("back", "home"), ("Ctrl+C", "exit")]);
            bindings
        }
        ShellView::PromptsEditor => vec![
            ("prompt edit", "edit"),
            ("prompt show", "show"),
            ("back", "module"),
            ("Ctrl+C", "exit"),
        ],
        ShellView::Options(_) => vec![
            ("set key value", "set"),
            ("show advanced", "advanced"),
            ("show missing", "missing"),
            ("back", "module"),
        ],
        ShellView::Context => vec![
            ("context build", "build"),
            ("context status", "status"),
            ("context regen repo", "regen"),
            ("back", "module"),
        ],
        ShellView::Workspace => vec![
            ("workspace status", "status"),
            ("workspace export", "findings"),
            ("scan <target>", "select target"),
            ("back", "module"),
        ],
        ShellView::KnowledgeBase => vec![
            ("PgUp/PgDn", "scroll"),
            ("attach <path>", "attach"),
            ("detach <id>", "detach"),
            ("reparse <id>", "reparse"),
        ],
        ShellView::AgentChat => vec![
            ("ask <q>", "new question"),
            ("?text", "ask"),
            ("model", "runtime"),
            ("back", "home"),
        ],
        ShellView::History => vec![
            ("PgUp/PgDn", "scroll"),
            ("clear", "clear log"),
            ("show runs", "runs"),
            ("story", "story"),
        ],
        ShellView::Story => vec![
            ("history", "commands"),
            ("show runs", "runs"),
            ("replay <id>", "replay"),
            ("back", "home"),
        ],
        ShellView::Help => vec![
            ("PgUp/PgDn", "scroll"),
            ("back", "home"),
            ("Ctrl+C", "exit"),
        ],
        ShellView::Tools => vec![
            ("PgUp/PgDn", "scroll"),
            ("use <id>", "focus module"),
            ("options <tool>", "options"),
            ("back", "home"),
        ],
        _ => vec![
            ("Enter", "run command"),
            ("back", "home"),
            ("help", "help"),
            ("Ctrl+C", "exit"),
        ],
    };
    bindings.insert(0, ("Tab", "complete"));
    bindings
}

fn push_view_keybindings(bindings: &mut Vec<(&'static str, &'static str)>, app: &ShellApp) {
    for binding in app.view_keybindings() {
        if !bindings
            .iter()
            .any(|(hint, label)| *hint == binding.hint && *label == binding.label)
        {
            bindings.push((binding.hint, binding.label));
        }
    }
}

fn render_lines(frame: &mut Frame<'_>, area: Rect, lines: Vec<Line<'static>>) {
    if area.height == 0 {
        return;
    }
    frame.render_widget(Paragraph::new(lines), area);
}

fn detail(key: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{key} "), theme::label()),
        Span::raw(value.to_string()),
    ])
}

fn join_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(", ")
    }
}

fn divider(title: &str, width: u16) -> Line<'static> {
    let safe_width = width.max(8) as usize;
    let title = format!(" {title} ");
    let remaining = safe_width.saturating_sub(title.chars().count());
    let left = remaining / 2;
    let right = remaining.saturating_sub(left);
    Line::from(vec![
        Span::styled(theme::RULE_CHAR.repeat(left), theme::subtle()),
        Span::styled(title, theme::muted()),
        Span::styled(theme::RULE_CHAR.repeat(right), theme::subtle()),
    ])
}

fn module_table_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let id = if total < 72 { 14 } else { 22 };
    let gaps = 2;
    let description = total.saturating_sub(id + gaps).max(16);
    vec![id, description]
}

fn table_header(values: &[&str], widths: &[usize]) -> Line<'static> {
    Line::styled(table_text(values, widths), theme::subtle())
}

fn table_row(values: &[&str], widths: &[usize]) -> Line<'static> {
    let mut spans = Vec::new();
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            spans.push(Span::raw("  "));
        }
        let style = if index == 0 {
            theme::accent()
        } else {
            Style::default()
        };
        spans.push(Span::styled(
            pad(value, widths.get(index).copied().unwrap_or(12)),
            style,
        ));
    }
    Line::from(spans)
}

fn table_text(values: &[&str], widths: &[usize]) -> String {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| pad(value, widths.get(index).copied().unwrap_or(12)))
        .collect::<Vec<_>>()
        .join("  ")
}

fn header(values: &[&str]) -> Line<'static> {
    Line::from(
        values
            .iter()
            .map(|value| Span::styled(format!("{}  ", pad(value, 14)), theme::subtle()))
            .collect::<Vec<_>>(),
    )
}

fn row(values: &[String]) -> Line<'static> {
    Line::from(
        values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let style = if index == 0 {
                    theme::accent()
                } else {
                    Style::default()
                };
                Span::styled(format!("{}  ", value), style)
            })
            .collect::<Vec<_>>(),
    )
}

fn pipeline_row(symbol: &str, label: &str, detail: &str) -> Line<'static> {
    let style = match symbol {
        "✓" => theme::success(),
        "→" | "⏵" => theme::accent(),
        _ => theme::subtle(),
    };
    Line::from(vec![
        Span::styled(format!("{symbol} "), style),
        Span::styled(pad(label, 24), theme::label()),
        Span::styled(detail.to_string(), theme::muted()),
    ])
}

fn threat_nav(active: ThreatView) -> Line<'static> {
    let items = [
        (ThreatView::Dfd, "1 DFD"),
        (ThreatView::Stride, "2 STRIDE"),
        (ThreatView::Stories, "3 STORIES"),
        (ThreatView::Scope, "4 SCOPE"),
        (ThreatView::Summary, "5 SUMMARY"),
    ];
    let mut spans = Vec::new();
    for (index, (view, label)) in items.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled("  ", theme::subtle()));
        }
        let style = if *view == active {
            theme::selection()
        } else {
            theme::muted()
        };
        spans.push(Span::styled(*label, style));
    }
    Line::from(spans)
}

fn blank() -> Line<'static> {
    Line::raw("")
}

fn muted(value: &str) -> Line<'static> {
    styled(value, theme::muted())
}

fn styled(value: &str, style: Style) -> Line<'static> {
    Line::styled(value.to_string(), style)
}

fn indent(line: Line<'static>, spaces: usize) -> Line<'static> {
    let mut spans = vec![Span::raw(" ".repeat(spaces))];
    spans.extend(line.spans);
    Line::from(spans)
}

fn next_action_line(text: &str, width: usize) -> Line<'static> {
    let available = width.saturating_sub(8);
    Line::from(vec![
        Span::styled("▸ NEXT ", theme::warn()),
        Span::styled(fit(text, available), theme::primary()),
    ])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProgressKind {
    Done,
    Active,
    Failing,
}

impl ProgressKind {
    fn fill_style(self) -> Style {
        match self {
            ProgressKind::Done => theme::success(),
            ProgressKind::Active => theme::warn(),
            ProgressKind::Failing => theme::danger(),
        }
    }

    fn status_style(self) -> Style {
        self.fill_style()
    }
}

/// Render a progress bar matching `design/mockups/sast.jsx::bar()`:
///
/// ```text
///    semgrep              [████████████████████░░░░]  612/612   done · 18 raw hits
/// ```
fn progress_bar_line(
    label: &str,
    done: usize,
    total: usize,
    status: &str,
    kind: ProgressKind,
) -> Line<'static> {
    let bar_width: usize = 24;
    let filled = if total == 0 {
        0
    } else {
        let raw = (bar_width as f64 * done as f64 / total as f64).round() as usize;
        raw.min(bar_width)
    };
    let empty = bar_width - filled;
    let count = format!("{done}/{total}");
    let count = format!("{:>7}", count);

    Line::from(vec![
        Span::raw("   "),
        Span::styled(pad(label, 20), theme::primary()),
        Span::styled(" [", theme::subtle()),
        Span::styled("█".repeat(filled), kind.fill_style()),
        Span::styled("░".repeat(empty), theme::subtle()),
        Span::styled("] ", theme::subtle()),
        Span::styled(count, theme::muted()),
        Span::raw("  "),
        Span::styled(status.to_string(), kind.status_style()),
    ])
}

/// Section header matching `design/mockups/_shared.jsx::sectionHeader()`:
/// uppercase bold heading on the left, subtle dash filler on the right.
fn section_header_line(label: &str, width: u16) -> Line<'static> {
    let text = label.to_uppercase();
    let total = width as usize;
    let used = text.chars().count() + 2;
    let dashes = total.saturating_sub(used).max(2);
    Line::from(vec![
        Span::styled(format!("{text}  "), theme::heading()),
        Span::styled("─".repeat(dashes), theme::subtle()),
    ])
}

/// STRIDE rollup row matching `design/mockups/threat-model.jsx`:
///
/// ```text
///    [ S ] Spoofing         2 issues  · jwt without aud-claim, mailgun cname dangling
/// ```
fn stride_row(
    letter: &str,
    severity: Severity,
    category: &str,
    count: usize,
    description: &str,
    width: u16,
) -> Line<'static> {
    let total = width as usize;
    let used = 3 + 3 + 1 + 16 + 4 + 10;
    let desc_w = total.saturating_sub(used).max(8);
    let issues_label = if count == 1 { "issue" } else { "issues" };
    let mut spans = vec![
        Span::raw("   "),
        Span::styled(format!(" {letter} "), theme::severity(severity)),
        Span::raw(" "),
        Span::styled(pad(category, 16), theme::muted()),
        Span::styled(format!("{count} "), theme::primary()),
        Span::styled(format!("{issues_label}"), theme::muted()),
    ];
    if !description.is_empty() {
        spans.push(Span::styled("  · ", theme::muted()));
        spans.push(Span::styled(fit(description, desc_w), theme::muted()));
    }
    Line::from(spans)
}

/// Returns the canonical 6-row STRIDE rollup matching the design fixture.
/// Used as a fallback when no `.kuzushi/threat-model.json` is present.
fn stride_rollup_rows() -> Vec<(&'static str, Severity, &'static str, usize, String)> {
    vec![
        (
            "S",
            Severity::High,
            "Spoofing",
            2,
            "jwt without aud-claim, mailgun cname dangling".to_string(),
        ),
        (
            "T",
            Severity::Medium,
            "Tampering",
            1,
            "worker pool reads unsigned amqp messages".to_string(),
        ),
        ("R", Severity::Low, "Repudiation", 0, String::new()),
        (
            "I",
            Severity::Critical,
            "Info-disclosure",
            3,
            "plaintext PII at db→s3 boundary, debug logs".to_string(),
        ),
        (
            "D",
            Severity::Medium,
            "DoS",
            1,
            "no rate-limit on /checkout/confirm".to_string(),
        ),
        (
            "E",
            Severity::High,
            "Elev-of-priv",
            1,
            "admin subdomain shares jwt secret with api".to_string(),
        ),
    ]
}

/// Canonical 10-row ASCII DFD matching `design/mockups/threat-model.jsx`.
/// 5 boxed nodes + 2 annotated edges (jwt, plaintext PII).
fn dfd_canonical_lines() -> Vec<Line<'static>> {
    let sub = theme::subtle();
    let acc = theme::accent();
    let mut_ = theme::muted();
    let warn = theme::warn();
    vec![
        Line::from(vec![
            Span::raw("     "),
            Span::styled(
                "┌────────────┐         ┌─────────────┐         ┌──────────────┐",
                sub,
            ),
        ]),
        Line::from(vec![
            Span::raw("     "),
            Span::styled("│ ", sub),
            Span::styled("  user    ", acc),
            Span::styled("│  https  │ ", sub),
            Span::styled(" api edge  ", acc),
            Span::styled("│   sql   │ ", sub),
            Span::styled("  postgres   ", acc),
            Span::styled("│", sub),
        ]),
        Line::from(vec![
            Span::raw("     "),
            Span::styled("│ ", sub),
            Span::styled("  browser ", mut_),
            Span::styled("│ ──────► │ ", sub),
            Span::styled("  nginx    ", mut_),
            Span::styled("│ ──────► │ ", sub),
            Span::styled("  primary db ", mut_),
            Span::styled("│", sub),
        ]),
        Line::from(vec![
            Span::raw("     "),
            Span::styled(
                "└────────────┘         └──────┬──────┘         └──────┬───────┘",
                sub,
            ),
        ]),
        Line::from(vec![
            Span::raw("                                       "),
            Span::styled("│ ", sub),
            Span::styled("jwt", mut_),
            Span::raw("                    "),
            Span::styled("│ ", sub),
            Span::styled("plaintext PII", warn),
        ]),
        Line::from(vec![
            Span::raw("                                       "),
            Span::styled("▼", sub),
            Span::raw("                       "),
            Span::styled("▼", sub),
        ]),
        Line::from(vec![
            Span::raw("                              "),
            Span::styled("┌──────────────┐         ┌──────────────┐", sub),
        ]),
        Line::from(vec![
            Span::raw("                              "),
            Span::styled("│ ", sub),
            Span::styled(" worker pool  ", acc),
            Span::styled("│  amqp   │ ", sub),
            Span::styled(" s3 (us-east) ", acc),
            Span::styled("│", sub),
        ]),
        Line::from(vec![
            Span::raw("                              "),
            Span::styled("│ ", sub),
            Span::styled(" rabbitmq cli ", mut_),
            Span::styled("│ ──────► │ ", sub),
            Span::styled(" invoices/    ", mut_),
            Span::styled("│", sub),
        ]),
        Line::from(vec![
            Span::raw("                              "),
            Span::styled("└──────────────┘         └──────────────┘", sub),
        ]),
    ]
}

/// Extract `(id, node_type, trust_zone)` triples from `dfd.nodes` if present.
fn dfd_nodes_from_doc(doc: &serde_json::Value) -> Option<Vec<(String, String, String)>> {
    let nodes = doc.get("dfd")?.get("nodes")?.as_array()?;
    if nodes.is_empty() {
        return None;
    }
    let rows = nodes
        .iter()
        .filter_map(|n| {
            let id = n.get("id").and_then(|v| v.as_str())?.to_string();
            let node_type = n
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("node")
                .to_string();
            let zone = n
                .get("trustZone")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Some((id, node_type, zone))
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        None
    } else {
        Some(rows)
    }
}

/// Try to load the persisted threat model for the active workspace target.
/// Returns `None` if the file doesn't exist or is empty/null.
fn current_threat_model_doc(app: &ShellApp) -> Option<serde_json::Value> {
    let cwd = app
        .target
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let doc = kuzushi_core::load_persistent_threat_model(&cwd)?;
    if doc.is_null() {
        return None;
    }
    Some(doc)
}

/// Compute the STRIDE rollup from a persisted threat model document.
/// Returns `None` if the document has no `threats` array or it's empty.
fn stride_rollup_from_doc(
    doc: &serde_json::Value,
) -> Option<Vec<(&'static str, Severity, &'static str, usize, String)>> {
    let threats = doc.get("threats")?.as_array()?;
    if threats.is_empty() {
        return None;
    }
    let cats: [(&'static str, &'static str, &'static str); 6] = [
        ("S", "spoofing", "Spoofing"),
        ("T", "tampering", "Tampering"),
        ("R", "repudiation", "Repudiation"),
        ("I", "information-disclosure", "Info-disclosure"),
        ("D", "denial-of-service", "DoS"),
        ("E", "elevation-of-privilege", "Elev-of-priv"),
    ];
    let mut rows = Vec::with_capacity(6);
    for (letter, key, label) in cats {
        let matching: Vec<&serde_json::Value> = threats
            .iter()
            .filter(|t| {
                t.get("category")
                    .and_then(|c| c.as_str())
                    .map(|c| c.to_lowercase().replace('_', "-"))
                    .as_deref()
                    == Some(key)
            })
            .collect();
        let count = matching.len();
        let severity = matching
            .iter()
            .map(|t| {
                t.get("impact")
                    .and_then(|s| s.as_str())
                    .map(impact_to_severity)
                    .unwrap_or(Severity::Medium)
            })
            .max_by_key(|s| severity_rank(*s))
            .unwrap_or(Severity::Low);
        let description = matching
            .iter()
            .filter_map(|t| {
                t.get("title")
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string())
            })
            .take(2)
            .collect::<Vec<_>>()
            .join(", ");
        rows.push((letter, severity, label, count, description));
    }
    Some(rows)
}

/// `(id, severity, title, attack_vector, location)` — one attacker story.
type StoryRow = (String, Severity, String, String, String);

/// Extract attacker stories from the persisted threat model. Each `threats[]`
/// entry becomes one story, sorted by impact severity (highest first).
fn stories_from_doc(doc: &serde_json::Value) -> Option<Vec<StoryRow>> {
    let threats = doc.get("threats")?.as_array()?;
    if threats.is_empty() {
        return None;
    }
    let mut rows: Vec<StoryRow> = threats
        .iter()
        .filter_map(|t| {
            let id = t.get("id").and_then(|v| v.as_str())?.to_string();
            let severity = t
                .get("impact")
                .and_then(|v| v.as_str())
                .map(impact_to_severity)
                .unwrap_or(Severity::Medium);
            let title = t
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("untitled")
                .to_string();
            let attack = t
                .get("attackVector")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let location = t
                .get("affectedFiles")
                .and_then(|v| v.as_array())
                .and_then(|files| files.first())
                .map(|f| {
                    let path = f.get("filePath").and_then(|v| v.as_str()).unwrap_or("");
                    let line = f.get("startLine").and_then(|v| v.as_u64()).unwrap_or(0);
                    if path.is_empty() {
                        String::new()
                    } else if line == 0 {
                        path.to_string()
                    } else {
                        format!("{path}:{line}")
                    }
                })
                .unwrap_or_default();
            Some((id, severity, title, attack, location))
        })
        .collect();
    rows.sort_by_key(|(_, sev, _, _, _)| std::cmp::Reverse(severity_rank(*sev)));
    Some(rows)
}

/// Fixture matching the canonical 4 attacker stories used when no real
/// threat model is loaded.
fn canonical_stories_fixture() -> Vec<StoryRow> {
    vec![
        (
            "T-001".to_string(),
            Severity::Critical,
            "sql injection via order_id concatenation".to_string(),
            "POST /orders/<id>".to_string(),
            "apps/api/orders.rs:142".to_string(),
        ),
        (
            "T-002".to_string(),
            Severity::Critical,
            "prompt injection sink reads user body".to_string(),
            "user message → llm context".to_string(),
            "apps/web/agents/concierge.ts:88".to_string(),
        ),
        (
            "T-003".to_string(),
            Severity::High,
            "jwt verify accepts alg=none".to_string(),
            "forged Authorization header".to_string(),
            "apps/api/auth/jwt.rs:54".to_string(),
        ),
        (
            "T-004".to_string(),
            Severity::High,
            "shell exec from cron payload".to_string(),
            "scheduled job pulls untrusted task".to_string(),
            "jobs/worker.py:213".to_string(),
        ),
    ]
}

/// `(severity, label, items)` — one criticality bucket of threat titles.
type ScopeBucket = (Severity, &'static str, Vec<String>);

/// Bucket threats from the persisted model by impact severity.
fn scope_buckets_from_doc(doc: &serde_json::Value) -> Option<Vec<ScopeBucket>> {
    let threats = doc.get("threats")?.as_array()?;
    if threats.is_empty() {
        return None;
    }
    let mut buckets: Vec<ScopeBucket> = vec![
        (Severity::Critical, "critical", Vec::new()),
        (Severity::High, "high", Vec::new()),
        (Severity::Medium, "medium", Vec::new()),
        (Severity::Low, "low", Vec::new()),
    ];
    for t in threats {
        let severity = t
            .get("impact")
            .and_then(|v| v.as_str())
            .map(impact_to_severity)
            .unwrap_or(Severity::Medium);
        let title = t
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("untitled")
            .to_string();
        if let Some((_, _, items)) = buckets.iter_mut().find(|(sev, _, _)| *sev == severity) {
            items.push(title);
        }
    }
    Some(buckets)
}

/// Fixture used when no real threat model is loaded — matches the canonical
/// design content.
fn canonical_scope_buckets() -> Vec<ScopeBucket> {
    vec![
        (
            Severity::Critical,
            "critical",
            vec![
                "sql injection via order_id concatenation".to_string(),
                "prompt injection sink reads user body".to_string(),
            ],
        ),
        (
            Severity::High,
            "high",
            vec![
                "jwt verify accepts alg=none".to_string(),
                "shell exec from cron payload".to_string(),
                "path traversal in /assets/<file>".to_string(),
            ],
        ),
        (
            Severity::Medium,
            "medium",
            vec![
                "open redirect on /login?next=".to_string(),
                "csrf token not bound to session".to_string(),
                "unbounded regex on /search".to_string(),
            ],
        ),
        (
            Severity::Low,
            "low",
            vec![
                "cors allows null origin".to_string(),
                "cookie set without SameSite".to_string(),
                "console.log of req.body in handler".to_string(),
            ],
        ),
    ]
}

fn impact_to_severity(value: &str) -> Severity {
    match value.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => Severity::Medium,
    }
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
        Severity::Unknown => 0,
    }
}

/// One-line finding row matching `design/mockups/sast.jsx::finding()`:
///
/// ```text
///  F-0001  CRITICAL  sql injection via order_id concatenation       apps/api/orders.rs:142
/// ```
fn compact_finding_row(
    alias: &str,
    severity: Severity,
    name: &str,
    location: &str,
    width: u16,
) -> Line<'static> {
    let alias_w = 8;
    let sev_w = 9;
    let used = 1 + alias_w + 2 + sev_w;
    let total = (width as usize).saturating_sub(used);
    let location_w = location.chars().count().min(total.saturating_sub(2)).max(8);
    let name_w = total.saturating_sub(location_w + 2).max(12);
    Line::from(vec![
        Span::raw(" "),
        Span::styled(pad(alias, alias_w), theme::accent()),
        Span::raw("  "),
        Span::styled(
            pad(&severity.as_str().to_uppercase(), sev_w),
            theme::severity(severity),
        ),
        Span::styled(pad(&fit(name, name_w), name_w), theme::primary()),
        Span::styled("  ", Style::default()),
        Span::styled(fit(location, location_w), theme::muted()),
    ])
}

fn catalog_module_row(
    id: &str,
    description: &str,
    focused: bool,
    widths: &[usize],
) -> Line<'static> {
    let id_width = widths.first().copied().unwrap_or(16);
    let description_width = widths.get(1).copied().unwrap_or(24);
    if focused {
        return Line::from(vec![
            Span::styled("▌ ", theme::accent()),
            Span::styled(
                format!(
                    "{}  {}",
                    pad(id, id_width),
                    pad(description, description_width)
                ),
                theme::selection(),
            ),
        ]);
    }
    Line::from(vec![
        Span::raw("  "),
        Span::styled(pad(id, id_width), theme::primary()),
        Span::raw("  "),
        Span::styled(pad(description, description_width), theme::muted()),
    ])
}

fn tool_console_row(name: &str, description: &str, headless: bool, width: u16) -> Line<'static> {
    let status = if headless { "headless" } else { "interactive" };
    let name_width = if width < 80 { 22 } else { 30 };
    let used = 4 + name_width + status.len() + 6;
    Line::from(vec![
        Span::styled(" ⏵ ", theme::subtle()),
        Span::styled(pad(name, name_width), theme::accent()),
        Span::styled(format!(" {status} "), theme::muted()),
        Span::styled(
            fit(description, (width as usize).saturating_sub(used).max(12)),
            theme::primary(),
        ),
    ])
}

fn module_playbook_lines(module_id: &str, width: u16) -> Vec<Line<'static>> {
    let mut lines = vec![divider("NEXT", width)];
    let (run, inspect) = match module_id {
        "context" => (
            "run build to write .kuzushi/context-snapshot.json",
            "context status · context regen repo",
        ),
        "recon" => (
            "run nmap, subdomain, or http-fingerprint with a target",
            "workspace · findings · use threat-model",
        ),
        "threat-model" => (
            "run build to refresh STRIDE / DFD artifacts",
            "threats summary · threats edit · threats regen",
        ),
        "sast" => (
            "run . or scan to launch the umbrella scanner",
            "tasks · findings · use triage",
        ),
        "carlini-threat-hunt" => (
            "run . after threat-model:build to start adversarial actor hunts",
            "show trace · findings · use verify",
        ),
        "agentic-sast" => (
            "run scan to start dataflow and variant hunting agents",
            "findings · show trace · use verify",
        ),
        _ => (
            "run . to dispatch the primary tool for this module",
            "options . · prompts · tune · back",
        ),
    };
    lines.push(transcript_line("tool", &fit(run, width as usize), false));
    lines.push(transcript_line(
        "help",
        &fit(inspect, width as usize),
        false,
    ));
    lines
}

fn catalog_module_category(id: &str, kind: ModuleKind) -> &'static str {
    match id {
        "semgrep"
        | "sast"
        | "codeql"
        | "agentic-sast"
        | "carlini-threat-hunt"
        | "secret-scan"
        | "iac-scan"
        | "dep-hygiene"
        | "taint-iris"
        | "taint-iris-next"
        | "systems-hunt"
        | "chrome-rce"
        | "prompt-armor"
        | "vuln-scout"
        | "tob" => "OFFENSE",
        "context" | "context-lite" | "recon" | "threat-model" | "randori" | "x-ray" | "ndiff"
        | "workspace" => "INTEL",
        "triage" | "verify" | "patch" | "findings" => "DEFENSE",
        _ => module_category(kind).0,
    }
}

fn module_category(kind: ModuleKind) -> (&'static str, &'static str) {
    match kind {
        ModuleKind::Offense | ModuleKind::Scan => {
            ("OFFENSE", "hunt vulnerabilities and prove exploitability")
        }
        ModuleKind::Intel | ModuleKind::Context | ModuleKind::Workspace => {
            ("INTEL", "map target context and workspace state")
        }
        ModuleKind::Governance | ModuleKind::Config | ModuleKind::Catalog => (
            "GOVERNANCE",
            "configuration, inventory, and operator controls",
        ),
        ModuleKind::Defense | ModuleKind::Findings | ModuleKind::Triage => {
            ("DEFENSE", "prioritize, triage, and remediate findings")
        }
        ModuleKind::Internal => ("GOVERNANCE", "internal orchestration"),
    }
}

fn module_category_blurb(category: &str) -> (&'static str, &'static str) {
    match category {
        "OFFENSE" => (
            "OFFENSE",
            "find vulnerabilities by scanning code, dependencies, and runtime surface",
        ),
        "INTEL" => (
            "INTEL",
            "build context, recon, and threat model the operator reads first",
        ),
        "GOVERNANCE" => ("GOVERNANCE", "configuration, allowlists, and audit trails"),
        "DEFENSE" => ("DEFENSE", "triage, verify, and patch emitted findings"),
        _ => ("OTHER", "loaded module surfaces"),
    }
}

fn scan_status(scan: &ScanPanelState) -> String {
    if scan.running && scan.abort_requested {
        "abort requested: waiting for subprocess".to_string()
    } else if scan.running {
        format!("running: {}", scan.stage)
    } else {
        scan.stage.clone()
    }
}

fn run_state_glyph(scan: Option<&ScanPanelState>) -> &'static str {
    match scan {
        Some(scan) if scan.running && scan.abort_requested => "✗",
        Some(scan) if scan.running => "⠿",
        Some(scan) if scan.error.is_some() => "✗",
        Some(_) => "✓",
        None => "●",
    }
}

fn run_state_style(scan: Option<&ScanPanelState>) -> Style {
    match scan {
        Some(scan) if scan.running && scan.abort_requested => theme::warn(),
        Some(scan) if scan.running => theme::warn(),
        Some(scan) if scan.error.is_some() => theme::danger(),
        Some(_) => theme::success(),
        None => theme::accent(),
    }
}

fn findings_summary(findings: &[Finding]) -> String {
    let counts = SeverityCounts::from_findings(findings);
    let mut parts = vec![format!("{} findings", findings.len())];
    if counts.critical > 0 {
        parts.push(format!("{} critical", counts.critical));
    }
    if counts.high > 0 {
        parts.push(format!("{} high", counts.high));
    }
    if counts.medium > 0 {
        parts.push(format!("{} medium", counts.medium));
    }
    parts.join(" / ")
}

fn findings_count_summary(findings: &[Finding]) -> String {
    let counts = SeverityCounts::from_findings(findings);
    if counts.critical > 0 {
        return format!("{} findings ({} critical)", findings.len(), counts.critical);
    }
    if counts.high > 0 {
        return format!("{} findings ({} high)", findings.len(), counts.high);
    }
    if counts.medium > 0 {
        return format!("{} findings ({} medium)", findings.len(), counts.medium);
    }
    format!("{} findings", findings.len())
}

fn join_segments(values: &[String]) -> String {
    values
        .iter()
        .filter(|value| !value.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join(theme::STATUS_SEPARATOR)
}

fn justify(left: String, right: String, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let left = fit(&left, width);
    if right.is_empty() {
        return left;
    }
    let right = fit(&right, width);
    let left_len = left.chars().count();
    let right_len = right.chars().count();
    if left_len + right_len + 1 >= width {
        return fit(&format!("{left} {}", right), width);
    }
    format!(
        "{left}{}{}",
        " ".repeat(width - left_len - right_len),
        right
    )
}

fn compact_target_path(value: &str) -> String {
    let trimmed = value.trim_end_matches('/');
    let name = trimmed
        .rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or(trimmed);
    if name.is_empty() {
        "target:/".to_string()
    } else {
        format!("./{name}")
    }
}

fn short(value: &str) -> String {
    value.chars().take(8).collect()
}

fn short_sentence(value: &str, max_chars: usize) -> String {
    let first = value.split('.').next().unwrap_or(value).trim();
    fit(first, max_chars)
}

fn fit(value: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    if max_chars <= 3 {
        return value.chars().take(max_chars).collect();
    }
    let mut truncated = value
        .chars()
        .take(max_chars.saturating_sub(3))
        .collect::<String>();
    truncated.push_str("...");
    truncated
}

fn wrap_text(value: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![String::new()];
    }

    let mut lines = Vec::new();
    for raw_line in value.lines() {
        let mut current = String::new();
        for word in raw_line.split_whitespace() {
            let mut pending = word.to_string();
            while !pending.is_empty() {
                let pending_len = pending.chars().count();
                let current_len = current.chars().count();
                if current_len == 0 {
                    if pending_len <= width {
                        current = pending;
                        break;
                    }
                    let (head, tail) = split_at_char_count(&pending, width);
                    lines.push(head);
                    pending = tail;
                } else if current_len + 1 + pending_len <= width {
                    current.push(' ');
                    current.push_str(&pending);
                    break;
                } else {
                    lines.push(current);
                    current = String::new();
                }
            }
        }
        if !current.is_empty() {
            lines.push(current);
        } else if raw_line.is_empty() {
            lines.push(String::new());
        }
    }

    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

fn split_at_char_count(value: &str, count: usize) -> (String, String) {
    if count == 0 {
        return (String::new(), value.to_string());
    }
    let split_index = value
        .char_indices()
        .nth(count)
        .map(|(index, _)| index)
        .unwrap_or(value.len());
    (
        value[..split_index].to_string(),
        value[split_index..].to_string(),
    )
}

fn pad(value: &str, width: usize) -> String {
    let value = fit(value, width);
    let padding = width.saturating_sub(value.chars().count());
    format!("{value}{}", " ".repeat(padding))
}

fn value_width(area: Rect, used: usize) -> usize {
    (area.width as usize).saturating_sub(used).max(12)
}

fn options_filter_label(filter: crate::app::OptionsFilter) -> &'static str {
    match filter {
        crate::app::OptionsFilter::Standard => "standard",
        crate::app::OptionsFilter::Advanced => "advanced",
        crate::app::OptionsFilter::Missing => "missing required",
    }
}

fn option_visible(
    spec: &OptionSpec,
    filter: crate::app::OptionsFilter,
    has_stored_value: bool,
) -> bool {
    match filter {
        crate::app::OptionsFilter::Standard => !spec.advanced && !spec.evasion,
        crate::app::OptionsFilter::Advanced => spec.advanced || spec.evasion,
        crate::app::OptionsFilter::Missing => {
            spec.required && !has_stored_value && spec.default.is_none()
        }
    }
}

fn option_type_label(option_type: OptionType) -> &'static str {
    match option_type {
        OptionType::String => "string",
        OptionType::Bool => "bool",
        OptionType::Int => "int",
        OptionType::Float => "float",
        OptionType::Path => "path",
        OptionType::Enum => "enum",
        OptionType::StringList => "list",
    }
}

fn option_description(spec: &OptionSpec) -> String {
    if spec.choices.is_empty() {
        spec.description.clone()
    } else {
        format!("{} Choices: {}.", spec.description, spec.choices.join("|"))
    }
}

fn format_json_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Null => "null".to_string(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "<json>".to_string()),
    }
}

fn option_table_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let option = if total < 80 { 14 } else { 16 };
    let value = if total < 80 { 10 } else { 12 };
    let default = if total < 80 { 8 } else { 10 };
    let required = if total < 80 { 5 } else { 7 };
    let kind = 6;
    let gaps = 10;
    let description = total
        .saturating_sub(option + value + default + required + kind + gaps)
        .max(12);
    vec![option, value, default, required, kind, description]
}

fn sast_task_table_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let state = 5;
    let id = if total < 88 { 20 } else { 24 };
    let cost = 5;
    let scan = if total < 88 { 14 } else { 18 };
    let gaps = 8;
    let notes = total
        .saturating_sub(state + id + cost + scan + gaps)
        .max(16);
    vec![state, id, cost, scan, notes]
}

#[derive(Debug)]
struct PromptSegments {
    prompt: String,
    before_cursor: String,
    cursor_text: String,
    after_cursor: String,
}

fn prompt_segments(
    prompt: &str,
    input: &str,
    columns: usize,
    cursor_glyph: &str,
) -> PromptSegments {
    let width = columns.max(1);
    let min_editor_width = 2.min(width);
    let fitted_prompt = fit_prompt(prompt, width.saturating_sub(min_editor_width));
    let editor_width = width.saturating_sub(fitted_prompt.chars().count()).max(1);

    let input_chars = input.chars().collect::<Vec<_>>();
    let cursor = input_chars.len();
    let mut visual_chars = input_chars.clone();
    let cursor_text = if cursor < visual_chars.len() {
        visual_chars[cursor].to_string()
    } else {
        visual_chars.push(cursor_glyph.chars().next().unwrap_or(' '));
        cursor_glyph.to_string()
    };

    let visual_len = visual_chars.len();
    let start = prompt_window_start(visual_len, cursor, editor_width);
    let end = (start + editor_width).min(visual_len);
    let visible = &visual_chars[start..end];
    let visible_cursor = cursor
        .saturating_sub(start)
        .min(visible.len().saturating_sub(1));

    PromptSegments {
        prompt: fitted_prompt,
        before_cursor: visible[..visible_cursor].iter().collect(),
        cursor_text,
        after_cursor: visible[visible_cursor.saturating_add(1)..].iter().collect(),
    }
}

fn fit_prompt(prompt: &str, max_columns: usize) -> String {
    if max_columns == 0 {
        return String::new();
    }
    if prompt.chars().count() <= max_columns {
        return prompt.to_string();
    }
    if max_columns <= 4 {
        return prompt.chars().take(max_columns).collect();
    }

    let suffix = if prompt.ends_with("> ") { "> " } else { "" };
    let suffix_width = suffix.chars().count();
    let body_columns = max_columns.saturating_sub(suffix_width);
    if body_columns <= 3 {
        return prompt.chars().take(max_columns).collect();
    }
    format!(
        "{}...{}",
        prompt
            .chars()
            .take(body_columns.saturating_sub(3))
            .collect::<String>(),
        suffix
    )
}

fn prompt_window_start(line_len: usize, cursor_index: usize, width: usize) -> usize {
    if line_len <= width {
        return 0;
    }
    let max_start = line_len.saturating_sub(width);
    let cursor_margin = width.saturating_sub(1) / 2;
    max_start.min(cursor_index.saturating_sub(cursor_margin))
}

#[derive(Debug, Default)]
struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

impl SeverityCounts {
    fn from_findings(findings: &[Finding]) -> Self {
        let mut counts = Self::default();
        for finding in findings {
            match finding.severity {
                Severity::Critical => counts.critical += 1,
                Severity::High => counts.high += 1,
                Severity::Medium => counts.medium += 1,
                Severity::Low => counts.low += 1,
                Severity::Info => counts.info += 1,
                Severity::Unknown => {}
            }
        }
        counts
    }
}

#[cfg(test)]
mod tests {
    use kuzushi_core::{
        Finding, OptionScope, OptionTarget, ScanCancellation, Severity, TriageOutcome,
        TriageVerdict, V2Config,
    };
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use ratatui::Terminal;

    use super::*;

    #[test]
    fn renders_ink_style_shell_without_box_dashboard() {
        let backend = TestBackend::new(96, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let app = ShellApp::new(V2Config::default(), None);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("kuzushi shell"));
        assert!(rendered.contains("kuzushi>"));
        assert!(rendered.contains("[Tab] complete"));
        assert!(rendered.contains("[modules]"));
        assert!(!rendered.contains("command log"));
        assert!(!rendered.contains("┌"));
        assert!(!rendered.contains("v2"));
    }

    #[test]
    fn catalog_first_run_state_names_real_first_finding_commands() {
        let backend = TestBackend::new(80, 16);
        let mut terminal = Terminal::new(backend).unwrap();
        let app = ShellApp::new(V2Config::default(), None);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("First finding"));
        assert!(rendered.contains("scan ."));
        assert!(rendered.contains("findings"));
        assert!(rendered.contains("quickstart"));
        assert!(!rendered.contains("./repo"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn renders_selected_finding_detail() {
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        let finding = Finding::new_semgrep(
            "demo.rule",
            "src/app.ts",
            8,
            Some(8),
            Severity::High,
            "dangerous sink",
        );
        app.findings = vec![finding.clone()];
        app.selected_finding = Some(finding);
        app.shell_view = ShellView::Finding;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("dangerous sink"));
        assert!(rendered.contains("alias"));
        assert!(rendered.contains("F-0001"));
        assert!(rendered.contains("fingerprint"));
    }

    #[test]
    fn renders_dense_findings_rows_at_80_columns() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut confirmed = Finding::new_semgrep(
            "typescript.express.sql-injection",
            "src/controllers/admin_search.ts",
            117,
            Some(119),
            Severity::High,
            "SQL injection in admin search\nEvidence: req.query.q flows into db.query without a guard\nCWE: CWE-89",
        );
        confirmed.triage = Some(TriageOutcome {
            verdict: TriageVerdict::TruePositive,
            confidence: 0.91,
            rationale: "source and sink are linked in the same handler".to_string(),
        });
        let untriaged = Finding::new_tool(
            "codeql",
            "js/path-injection",
            "src/files.ts",
            22,
            None,
            Severity::Medium,
            "Path traversal candidate\nEvidence: filename reaches fs.readFile",
        );
        app.findings = vec![confirmed, untriaged];
        app.shell_view = ShellView::Findings;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let buffer = terminal.backend().buffer();
        let rendered = format!("{:?}", buffer);

        for expected in [
            "alias",
            "severity",
            "verdict",
            "conf",
            "proof/static",
            "cwe",
            "source",
            "F-0001",
            "high",
            "tp",
            "91%",
            "triaged-tp",
            "CWE-89",
            "semgrep",
            "loc src/controllers/admin_search.ts:117-119",
            "SQL injection in admin search",
            "req.query.q flows into db.query",
            "next: open F-0001",
            "F-0002",
            "untriaged",
            "static-sig",
            "codeql",
        ] {
            assert!(rendered.contains(expected), "missing {expected}");
        }
        for y in 0..24 {
            let row = buffer_row_text(buffer, 80, y);
            assert!(
                row.chars().count() <= 80,
                "row exceeded 80 columns: {row:?}"
            );
        }
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn renders_actionable_empty_states_at_80_columns() {
        for (view, expected) in [
            (ShellView::Findings, "Next: scan"),
            (ShellView::Runs, "Next: scan <target>"),
            (ShellView::Workspace, "Next: scan <target>"),
        ] {
            let backend = TestBackend::new(80, 18);
            let mut terminal = Terminal::new(backend).unwrap();
            let mut app = ShellApp::new(V2Config::default(), None);
            let is_dfd = matches!(view, ShellView::Threat(ThreatView::Dfd));
            app.shell_view = view;

            terminal.draw(|frame| render_app(frame, &app)).unwrap();
            let rendered = format!("{:?}", terminal.backend().buffer());

            assert!(rendered.contains(expected), "missing {expected}");
            // Box-drawing is reserved for the DFD diagram; every other view
            // must remain free of nested boxes (no Ink-style boxed dashboard).
            if !is_dfd {
                assert!(!rendered.contains("┌"), "{expected} drew a box");
            }
        }
    }

    #[test]
    fn renders_long_prompt_on_single_row() {
        let backend = TestBackend::new(40, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.input = "scan ./a/very/long/path/that/should/not/wrap".to_string();

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("kuzushi>"));
        assert!(!rendered.contains("prompt"));
    }

    #[test]
    fn keeps_command_log_directly_above_bottom_prompt_at_80_columns() {
        let backend = TestBackend::new(80, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.log(
            "error",
            "scanner failed while reading src/really/long/path/that/must/not_overlap.rs",
        );
        app.log(
            "result",
            "next action: inspect configuration and rerun scan with a narrower target",
        );
        app.input = "run sast:scan {\"severity\":[\"high\"],\"triage\":true}".to_string();

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let buffer = terminal.backend().buffer();
        let prompt_row = buffer_row_text(buffer, 80, 11);
        let log_row = buffer_row_text(buffer, 80, 10);

        assert!(prompt_row.trim_start().starts_with("kuzushi>"));
        assert!(prompt_row.contains("triage"));
        assert!(!prompt_row.contains("result"));
        assert!(log_row.contains("result"));
        assert!(!log_row.contains("kuzushi>"));
        assert!(!format!("{:?}", buffer).contains("┌"));
    }

    #[test]
    fn renders_exit_commands_before_closing() {
        for command in ["/exit", "exit", "/exitj"] {
            let backend = TestBackend::new(80, 12);
            let mut terminal = Terminal::new(backend).unwrap();
            let mut app = ShellApp::new(V2Config::default(), None);

            app.submit_line(command);
            assert!(app.should_quit, "{command} should request shell shutdown");

            terminal.draw(|frame| render_app(frame, &app)).unwrap();
            let buffer = terminal.backend().buffer();
            let command_row = buffer_row_text(buffer, 80, 9);
            let exit_row = buffer_row_text(buffer, 80, 10);
            let prompt_row = buffer_row_text(buffer, 80, 11);

            assert!(
                command_row.contains(command),
                "{command} should remain visible in the transcript"
            );
            assert!(exit_row.contains("exit requested; closing shell"));
            assert!(prompt_row.trim_start().starts_with("kuzushi>"));
        }
    }

    #[test]
    fn replay_and_trace_surfaces_reuse_current_finding_aliases() {
        for view in [
            ShellView::Replay("run-1".to_string()),
            ShellView::Trace("run-1".to_string()),
        ] {
            let backend = TestBackend::new(80, 18);
            let mut terminal = Terminal::new(backend).unwrap();
            let mut app = ShellApp::new(V2Config::default(), None);
            let mut finding =
                Finding::new_semgrep("demo.rule", "src/app.ts", 8, None, Severity::High, "sink");
            finding.fingerprint = "aaaa1111".to_string();
            app.findings = vec![finding];
            app.shell_view = view;

            terminal.draw(|frame| render_app(frame, &app)).unwrap();
            let rendered = format!("{:?}", terminal.backend().buffer());

            assert!(rendered.contains("ALIASES"));
            assert!(rendered.contains("F-0001"));
            assert!(rendered.contains("aaaa1111"));
        }
    }

    #[test]
    fn renders_threat_view_navigation() {
        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Threat(ThreatView::Stride);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("STRIDE"));
        assert!(rendered.contains("Spoofing"));
    }

    #[test]
    fn renders_pending_threat_patch_card() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_pending_threat_patch(crate::app::ThreatPatch {
            goal: "regen".to_string(),
            summary: "add admin trust zone".to_string(),
            patch: serde_json::json!({"trustZones":{"admin":"isolated"}}),
            unsupported: vec!["manual review required".to_string()],
        });

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("THREAT PATCH"));
        assert!(rendered.contains("add admin trust zone"));
        assert!(rendered.contains("1 top-level key"));
        assert!(rendered.contains("/threats apply"));
        assert!(rendered.contains("/threats reject"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn renders_expanded_catalog_readably_on_narrow_terminal() {
        let backend = TestBackend::new(58, 32);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.handle_command(crate::commands::ShellCommand::Modules);
        app.findings = (0..82)
            .map(|index| {
                Finding::new_semgrep(
                    format!("demo.rule.{index}"),
                    "src/app.ts",
                    index + 1,
                    None,
                    Severity::Medium,
                    "demo finding",
                )
            })
            .collect();

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("82 findings"));
        assert!(rendered.contains("semgrep"));
        assert!(rendered.contains("description"));
        assert!(!rendered.contains("module context-lite"));
        assert!(!rendered.contains("command log"));
    }

    #[test]
    fn expanded_catalog_uses_design_sections_without_dag_column() {
        let backend = TestBackend::new(120, 36);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.handle_command(crate::commands::ShellCommand::Modules);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("KUZUSHI · CATALOG"));
        assert!(rendered.contains("▸ NEXT"));
        assert!(rendered.contains("OFFENSE"));
        assert!(rendered.contains("sast"));
        assert!(!rendered.contains("dag"));
        assert!(!rendered.contains("DAG"));
    }

    #[test]
    fn module_run_body_ends_with_streaming_cursor_when_scan_active() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.scan = Some(crate::app::ScanPanelState {
            run_id: Some("run-abc".to_string()),
            target: std::path::PathBuf::from("./demo"),
            stage: "scanning".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: false,
            error: None,
        });
        app.shell_view = ShellView::ModuleRun;
        let area = Rect::new(0, 0, 120, 30);
        let lines = module_run_lines(&app, area);
        let last = lines.last().expect("expected non-empty body");
        let last_text: String = last.spans.iter().map(|s| s.content.as_ref()).collect();
        // The cursor line is " " + a single styled-block " ", so two visible cells.
        assert_eq!(
            last_text, "  ",
            "expected streaming cursor line at end while scan running, got {last_text:?}"
        );
        // Sanity: confirm a styled span with primary bg exists on that line.
        let has_inverse = last
            .spans
            .iter()
            .any(|sp| sp.style.bg.is_some() && sp.content.as_ref() == " ");
        assert!(has_inverse, "streaming cursor should be a styled background cell");
    }

    #[test]
    fn module_run_body_omits_streaming_cursor_when_idle() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::ModuleRun;
        let area = Rect::new(0, 0, 120, 30);
        let lines = module_run_lines(&app, area);
        // No scan → no streaming cursor expected.
        for line in &lines {
            let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
            let has_cursor = line
                .spans
                .iter()
                .any(|sp| sp.style.bg.is_some() && sp.content.as_ref() == " ");
            assert!(
                !has_cursor || text.trim() != "",
                "unexpected streaming cursor while idle: {text:?}"
            );
        }
    }

    #[test]
    fn stories_from_doc_sorts_threats_by_impact_severity() {
        let doc = serde_json::json!({
            "threats": [
                {"id": "T-001", "title": "low risk",  "impact": "low",      "category": "spoofing",  "attackVector": "vec1"},
                {"id": "T-002", "title": "critical bug", "impact": "critical","category": "tampering","attackVector": "vec2",
                 "affectedFiles": [{"filePath": "src/api.rs", "startLine": 42}]},
                {"id": "T-003", "title": "high issue", "impact": "high",     "category": "elevation_of_privilege"}
            ]
        });
        let stories = stories_from_doc(&doc).expect("non-empty stories");
        assert_eq!(stories.len(), 3);
        assert_eq!(stories[0].0, "T-002");
        assert_eq!(stories[0].1, Severity::Critical);
        assert_eq!(stories[0].4, "src/api.rs:42");
        assert_eq!(stories[1].0, "T-003");
        assert_eq!(stories[1].1, Severity::High);
        assert_eq!(stories[2].0, "T-001");
    }

    #[test]
    fn scope_buckets_from_doc_groups_by_impact() {
        let doc = serde_json::json!({
            "threats": [
                {"title": "a", "impact": "critical"},
                {"title": "b", "impact": "high"},
                {"title": "c", "impact": "high"},
                {"title": "d", "impact": "medium"}
            ]
        });
        let buckets = scope_buckets_from_doc(&doc).expect("non-empty");
        assert_eq!(buckets[0].0, Severity::Critical);
        assert_eq!(buckets[0].2.len(), 1);
        assert_eq!(buckets[1].0, Severity::High);
        assert_eq!(buckets[1].2.len(), 2);
        assert_eq!(buckets[2].0, Severity::Medium);
        assert_eq!(buckets[2].2.len(), 1);
        assert_eq!(buckets[3].0, Severity::Low);
        assert!(buckets[3].2.is_empty());
    }

    #[test]
    fn threats_stories_view_renders_attacker_story_cards() {
        let backend = TestBackend::new(120, 36);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Threat(ThreatView::Stories);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("ATTACKER STORIES"));
        assert!(rendered.contains("T-001"));
        assert!(rendered.contains("CRITICAL"));
        assert!(rendered.contains("attack"));
        assert!(rendered.contains("loc"));
        // Old placeholder gone
        assert!(!rendered.contains("malicious input reaches a sink"));
    }

    #[test]
    fn threats_scope_view_renders_criticality_buckets() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Threat(ThreatView::Scope);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains("SCOPE · 11 ISSUES"),
            "expected SCOPE · 11 ISSUES in: {rendered}"
        );
        assert!(rendered.contains("CRITICAL · 2"));
        assert!(rendered.contains("HIGH · 3"));
        assert!(rendered.contains("OUT OF SCOPE"));
        // Old placeholders gone
        assert!(!rendered.contains("auth, request parsing"));
    }

    #[test]
    fn dfd_canonical_lines_render_design_diagram() {
        let lines = dfd_canonical_lines();
        assert_eq!(lines.len(), 10, "expected 10 rows in canonical DFD");
        let texts: Vec<String> = lines
            .iter()
            .map(|line| line.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect();
        assert!(texts[1].contains("user"));
        assert!(texts[1].contains("api edge"));
        assert!(texts[1].contains("postgres"));
        assert!(texts[4].contains("jwt"));
        assert!(texts[4].contains("plaintext PII"));
        assert!(texts[7].contains("worker pool"));
        assert!(texts[7].contains("s3 (us-east)"));
        // top + bottom borders are pure box-drawing
        assert!(texts[0].contains("┌────"));
        assert!(texts[3].contains("└────"));
    }

    #[test]
    fn dfd_nodes_from_doc_returns_id_type_zone_triples() {
        let doc = serde_json::json!({
            "dfd": {
                "nodes": [
                    {"id": "actor-user", "type": "external-entity", "name": "User",
                     "description": "End user", "trustZone": "external"},
                    {"id": "web", "type": "process", "name": "Web app",
                     "description": "Server", "trustZone": "internal"}
                ]
            }
        });
        let nodes = dfd_nodes_from_doc(&doc).expect("expected non-empty nodes");
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].0, "actor-user");
        assert_eq!(nodes[0].1, "external-entity");
        assert_eq!(nodes[0].2, "external");
        assert_eq!(nodes[1].0, "web");
        assert_eq!(nodes[1].2, "internal");
    }

    #[test]
    fn dfd_nodes_from_doc_returns_none_when_missing() {
        assert!(dfd_nodes_from_doc(&serde_json::json!({})).is_none());
        assert!(dfd_nodes_from_doc(&serde_json::json!({"dfd": {}})).is_none());
        assert!(dfd_nodes_from_doc(&serde_json::json!({"dfd": {"nodes": []}})).is_none());
    }

    #[test]
    fn threats_dfd_view_renders_canonical_diagram_header() {
        let backend = TestBackend::new(120, 28);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Threat(ThreatView::Dfd);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains("DFD · ACME-CHECKOUT"),
            "expected DFD section header in: {rendered}"
        );
        assert!(rendered.contains("user"));
        assert!(rendered.contains("api edge"));
        assert!(rendered.contains("postgres"));
        assert!(rendered.contains("worker pool"));
        // Old placeholder content must be gone.
        assert!(!rendered.contains("browser, API clients, package registries"));
        assert!(!rendered.contains("source tree, handlers, jobs, CLIs"));
    }

    #[test]
    fn stride_rollup_from_doc_parses_real_threats() {
        let doc = serde_json::json!({
            "threats": [
                {"id": "T-001", "category": "spoofing",          "title": "spoofed login",    "impact": "high"},
                {"id": "T-002", "category": "spoofing",          "title": "stolen token",     "impact": "medium"},
                {"id": "T-003", "category": "tampering",         "title": "config tamper",    "impact": "critical"},
                {"id": "T-004", "category": "information-disclosure", "title": "log leak",    "impact": "low"},
            ]
        });
        let rollup = stride_rollup_from_doc(&doc).expect("expected rollup from non-empty threats");
        assert_eq!(rollup.len(), 6);

        let total: usize = rollup.iter().map(|r| r.3).sum();
        assert_eq!(total, 4);

        // Spoofing: 2 threats, max impact = high
        let spoof = &rollup[0];
        assert_eq!(spoof.0, "S");
        assert_eq!(spoof.2, "Spoofing");
        assert_eq!(spoof.3, 2);
        assert_eq!(spoof.1, Severity::High);
        assert!(spoof.4.contains("spoofed login"));
        assert!(spoof.4.contains("stolen token"));

        // Tampering: 1 threat, impact = critical
        let tamper = &rollup[1];
        assert_eq!(tamper.3, 1);
        assert_eq!(tamper.1, Severity::Critical);
        assert_eq!(tamper.4, "config tamper");

        // Repudiation: 0 threats, default Low severity, empty description
        let repud = &rollup[2];
        assert_eq!(repud.3, 0);
        assert_eq!(repud.1, Severity::Low);
        assert!(repud.4.is_empty());

        // Info-disclosure: 1 threat, impact = low
        let info = &rollup[3];
        assert_eq!(info.3, 1);
        assert_eq!(info.1, Severity::Low);
        assert_eq!(info.4, "log leak");
    }

    #[test]
    fn stride_rollup_from_doc_returns_none_on_empty_or_missing_threats() {
        assert!(stride_rollup_from_doc(&serde_json::json!({})).is_none());
        assert!(stride_rollup_from_doc(&serde_json::json!({"threats": []})).is_none());
        assert!(stride_rollup_from_doc(&serde_json::json!({"threats": null})).is_none());
    }

    #[test]
    fn stride_rollup_from_doc_normalizes_underscored_categories() {
        let doc = serde_json::json!({
            "threats": [
                {"category": "denial_of_service",        "title": "ddos",  "impact": "medium"},
                {"category": "elevation_of_privilege",   "title": "sudo bypass", "impact": "critical"},
            ]
        });
        let rollup = stride_rollup_from_doc(&doc).expect("rollup should accept underscored");
        let dos = &rollup[4];
        assert_eq!(dos.0, "D");
        assert_eq!(dos.3, 1);
        let elev = &rollup[5];
        assert_eq!(elev.0, "E");
        assert_eq!(elev.3, 1);
        assert_eq!(elev.1, Severity::Critical);
    }

    #[test]
    fn threats_summary_view_combines_stride_rollup_and_observations() {
        let backend = TestBackend::new(120, 32);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Threat(ThreatView::Summary);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains("THREAT MODEL · 8 ISSUES"),
            "expected design summary header in: {rendered}"
        );
        assert!(rendered.contains("Spoofing"));
        assert!(rendered.contains("admin.acme-checkout.com"));
        assert!(rendered.contains("threat-model.json"));
    }

    #[test]
    fn threats_stride_view_renders_design_rollup() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Threat(ThreatView::Stride);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains("STRIDE ROLLUP"),
            "expected STRIDE ROLLUP header in: {rendered}"
        );
        assert!(rendered.contains("Spoofing"));
        assert!(rendered.contains("Tampering"));
        assert!(rendered.contains("Repudiation"));
        assert!(rendered.contains("Info-disclosure"));
        assert!(rendered.contains("DoS"));
        assert!(rendered.contains("Elev-of-priv"));
        // Old hardcoded content must be gone.
        assert!(!rendered.contains("entrypoints"));
        assert!(!rendered.contains("scanners"));
    }

    #[test]
    fn focused_recon_module_renders_recent_activity_section() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.log.clear();
        app.log("recon:nmap", "discovered 5 hosts and 18 services for acme-checkout.com");
        app.log("recon:subdomain", "discovered 7 subdomains");
        app.log("recon", "persisted 3 findings");
        app.handle_command(crate::commands::ShellCommand::Use("recon".to_string()));

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains("RECENT RECON ACTIVITY"),
            "expected design section header for recon: {rendered}"
        );
        assert!(rendered.contains("discovered 5 hosts"));
        assert!(rendered.contains("discovered 7 subdomains"));
    }

    #[test]
    fn focused_carlini_module_renders_recent_threat_hunt_activity() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.log.clear();
        app.log("carlini-threat-hunt", "actor 1/4 dispatched");
        app.log("carlini-threat-hunt", "actor 2/4 found path-traversal sink");
        app.handle_command(crate::commands::ShellCommand::Use(
            "carlini-threat-hunt".to_string(),
        ));

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains("RECENT THREAT-HUNT ACTIVITY"),
            "expected design section header for carlini: {rendered}"
        );
        assert!(rendered.contains("actor 1/4 dispatched"));
    }

    #[test]
    fn module_run_transcript_uses_growing_console_glyphs() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.log.clear();
        app.log(">", "/scan");
        app.log("scan", "starting ./demo");
        app.log("finding", "abc123 high dangerous sink");
        app.log("error", "scanner failed");
        app.scan = Some(crate::app::ScanPanelState {
            run_id: Some("run-123456".to_string()),
            target: std::path::PathBuf::from("./demo"),
            stage: "agentic-sast tracing".to_string(),
            findings_count: 1,
            running: true,
            abort_requested: false,
            error: None,
        });
        app.shell_view = ShellView::ModuleRun;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("SCAN PROGRESS"));
        assert!(rendered.contains("⠿"));
        assert!(rendered.contains("● /scan"));
        assert!(rendered.contains("⏵ scan starting ./demo"));
        assert!(rendered.contains("▸ finding abc123 high dangerous sink"));
        assert!(rendered.contains("✗ error scanner failed"));
    }

    #[test]
    fn direct_tool_run_header_does_not_show_pending_scan_run() {
        let backend = TestBackend::new(96, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.focused_module = Some("context".to_string());
        app.shell_view = ShellView::ModuleRun;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("tool run"));
        assert!(!rendered.contains("run pending"));
    }

    #[test]
    fn renders_options_table_readably_at_80_columns() {
        let backend = TestBackend::new(80, 22);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.option_store.set_value(
            OptionScope::Session,
            OptionTarget::Tool("sast:scan".to_string()),
            "triage",
            serde_json::json!(true),
        );
        app.shell_view = ShellView::Options(crate::app::OptionsView {
            tool_name: "sast:scan".to_string(),
            filter: crate::app::OptionsFilter::Standard,
        });

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("OPTIONS"));
        assert!(rendered.contains("sast:scan"));
        assert!(rendered.contains("tasks"));
        assert!(rendered.contains("disabledTasks"));
        assert!(rendered.contains("triage"));
        assert!(rendered.contains("true"));
        assert!(rendered.contains("set <key> <value>"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn renders_sast_task_picker_readably_at_80_columns() {
        let backend = TestBackend::new(80, 22);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::SastTasks;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("SAST TASKS"));
        assert!(rendered.contains("semgrep"));
        assert!(rendered.contains("codeql"));
        assert!(rendered.contains("auto + denylist"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn renders_kb_attachments_readably_at_80_columns() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.kb_view.module_id = "x-ray".to_string();
        app.kb_view.artifacts = vec![kuzushi_core::KnownArtifact {
            module_id: "x-ray".to_string(),
            path: "x-ray/x-ray.md".to_string(),
            description: "x-ray report".to_string(),
            exists: true,
        }];
        app.kb_view.attachments = vec![kuzushi_core::AttachmentRecord {
            id: "A-123456789abc".to_string(),
            module_id: "x-ray".to_string(),
            kind: kuzushi_core::AttachmentKind::Url,
            source: "https://example.test/design".to_string(),
            title: "example.test".to_string(),
            metadata_only: true,
            content_hash: None,
            byte_count: None,
            status: "metadata-only; URL was not fetched".to_string(),
            updated_at_unix: 1,
        }];
        app.shell_view = ShellView::KnowledgeBase;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("KB ATTACHMENTS"));
        assert!(rendered.contains("x-ray/x-ray.md"));
        assert!(rendered.contains("A-123456789abc"));
        assert!(rendered.contains("metadata-only"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn renders_context_status_readably_at_80_columns() {
        let backend = TestBackend::new(80, 22);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.context_view = crate::app::ContextSnapshotView {
            snapshot_path: Some(std::path::PathBuf::from(".kuzushi/context-snapshot.json")),
            exists: true,
            status: "snapshot present; 2 indexed file(s). Next: context regen repo".to_string(),
            target: Some("/tmp/demo".to_string()),
            discovery: Some("auto".to_string()),
            files_indexed: Some(2),
            total_files: Some(2),
            languages: vec!["Rust".to_string()],
            frameworks: vec!["Cargo".to_string()],
            generated_slices: vec!["repo".to_string(), "app-model".to_string()],
            stale_slices: Vec::new(),
        };
        app.shell_view = ShellView::Context;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("CONTEXT"));
        assert!(rendered.contains("context-snapshot.json"));
        assert!(rendered.contains("Rust"));
        assert!(rendered.contains("context regen repo"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn renders_workspace_status_readably_at_80_columns() {
        let backend = TestBackend::new(80, 22);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.workspace_view = crate::app::WorkspaceView {
            root: Some(std::path::PathBuf::from("/tmp/kuzushi-demo")),
            state_dir: Some(std::path::PathBuf::from("/tmp/kuzushi-demo/.kuzushi/v2")),
            findings_db: Some(std::path::PathBuf::from(
                "/tmp/kuzushi-demo/.kuzushi/v2/findings.sqlite3",
            )),
            findings_count: Some(2),
            last_export: Some(std::path::PathBuf::from("/tmp/findings.json")),
            status: "workspace ready; 2 finding(s). Next: workspace export findings findings.json"
                .to_string(),
        };
        app.shell_view = ShellView::Workspace;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("WORKSPACE"));
        assert!(rendered.contains("findings.sqlite3"));
        assert!(rendered.contains("findings.json"));
        assert!(rendered.contains("workspace export"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn plain_options_table_has_no_ansi_or_box_drawing() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.option_store.set_value(
            OptionScope::Session,
            OptionTarget::Tool("sast:scan".to_string()),
            "triage",
            serde_json::json!(true),
        );
        app.shell_view = ShellView::Options(crate::app::OptionsView {
            tool_name: "sast:scan".to_string(),
            filter: crate::app::OptionsFilter::Standard,
        });

        let rendered = render_plain_app(&app, 80);

        assert!(rendered.contains("OPTIONS"));
        assert!(rendered.contains("sast:scan"));
        assert!(rendered.contains("triage"));
        assert!(rendered.contains("true"));
        assert!(rendered.contains("Next: set <key> <value>"));
        assert_strict_plain_80(&rendered);
    }

    #[test]
    fn plain_kb_list_has_no_ansi_or_box_drawing() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.kb_view.module_id = "x-ray".to_string();
        app.kb_view.artifacts = vec![kuzushi_core::KnownArtifact {
            module_id: "x-ray".to_string(),
            path: "x-ray/x-ray.md".to_string(),
            description: "x-ray report".to_string(),
            exists: true,
        }];
        app.kb_view.attachments = vec![kuzushi_core::AttachmentRecord {
            id: "A-123456789abc".to_string(),
            module_id: "x-ray".to_string(),
            kind: kuzushi_core::AttachmentKind::Url,
            source: "https://example.test/design".to_string(),
            title: "example.test".to_string(),
            metadata_only: true,
            content_hash: None,
            byte_count: None,
            status: "metadata-only; URL was not fetched".to_string(),
            updated_at_unix: 1,
        }];
        app.shell_view = ShellView::KnowledgeBase;

        let rendered = render_plain_app(&app, 80);

        assert!(rendered.contains("KB ATTACHMENTS"));
        assert!(rendered.contains("x-ray/x-ray.md"));
        assert!(rendered.contains("A-123456789abc"));
        assert!(rendered.contains("metadata-only"));
        assert!(rendered.contains("Next: kb [module]"));
        assert_strict_plain_80(&rendered);
    }

    #[test]
    fn plain_context_status_has_no_ansi_or_box_drawing() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.context_view = crate::app::ContextSnapshotView {
            snapshot_path: Some(std::path::PathBuf::from(".kuzushi/context-snapshot.json")),
            exists: true,
            status: "snapshot present; 2 indexed file(s). Next: context regen repo".to_string(),
            target: Some("/tmp/demo".to_string()),
            discovery: Some("auto".to_string()),
            files_indexed: Some(2),
            total_files: Some(2),
            languages: vec!["Rust".to_string()],
            frameworks: vec!["Cargo".to_string()],
            generated_slices: vec!["repo".to_string(), "app-model".to_string()],
            stale_slices: Vec::new(),
        };
        app.shell_view = ShellView::Context;

        let rendered = render_plain_app(&app, 80);

        assert!(rendered.contains("CONTEXT"));
        assert!(rendered.contains("context-snapshot.json"));
        assert!(rendered.contains("Rust"));
        assert!(rendered.contains("context regen repo"));
        assert_strict_plain_80(&rendered);
    }

    #[test]
    fn plain_context_guidance_wraps_without_truncating_next_steps() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Context;

        let rendered = render_plain_app(&app, 56);

        assert!(rendered.contains("No context snapshot exists yet."));
        assert!(rendered.contains(".kuzushi/context-snapshot.json"));
        assert!(rendered.contains("context build"));
        assert!(rendered.contains("context regen repo"));
        assert!(!rendered.contains("context-s..."));
        assert_strict_plain_width(&rendered, 56);
    }

    #[test]
    fn plain_workspace_guidance_wraps_without_truncating_export_command() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.workspace_view = crate::app::WorkspaceView {
            root: Some(std::path::PathBuf::from("/tmp/kuzushi-demo")),
            state_dir: Some(std::path::PathBuf::from("/tmp/kuzushi-demo/.kuzushi/v2")),
            findings_db: Some(std::path::PathBuf::from(
                "/tmp/kuzushi-demo/.kuzushi/v2/findings.sqlite3",
            )),
            findings_count: Some(2),
            last_export: None,
            status: "workspace ready; 2 finding(s). Next: workspace export findings findings.json"
                .to_string(),
        };
        app.shell_view = ShellView::Workspace;

        let rendered = render_plain_app(&app, 52);

        assert!(rendered.contains("workspace ready; 2 finding(s)."));
        assert!(rendered.contains("workspace export findings findings.json"));
        assert!(!rendered.contains("workspace export findings..."));
        assert_strict_plain_width(&rendered, 52);
    }

    #[test]
    fn plain_help_guidance_wraps_without_truncating_command_shapes() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Help;

        let rendered = render_plain_app(&app, 64);

        assert!(rendered.contains("HELP"));
        assert!(rendered.contains("ask <question>"));
        assert!(rendered.contains("enter agent mode"));
        assert!(rendered.contains("workspace export findings <path>"));
        assert!(rendered.contains("/workspace export findings <path>"));
        assert!(!rendered.contains("workspace export findings <..."));
        assert_strict_plain_width(&rendered, 64);
    }

    #[test]
    fn renders_config_onboarding_without_silent_model_selection() {
        let backend = TestBackend::new(100, 28);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.config.model = None;
        app.session_thinking_level = None;
        app.selected_model_index = 2;
        app.shell_view = ShellView::Config;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("provider"));
        assert!(rendered.contains("unconfigured"));
        assert!(rendered.contains("reasoning"));
        assert!(rendered.contains("default"));
        assert!(rendered.contains("onboarding"));
        assert!(rendered.contains("Up/Down"));
        assert!(rendered.contains(">"));
        assert!(rendered.contains("openai-codex:gpt-5.5"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn renders_help_grouped_by_operator_workflow() {
        let backend = TestBackend::new(110, 130);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Help;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        for heading in [
            "NAVIGATION",
            "RUN / SCAN",
            "OPTIONS / TASKS",
            "CONTEXT / KB",
            "FINDINGS / EVIDENCE",
            "AUTH / CONFIG / MODEL",
            "SESSION",
        ] {
            assert!(rendered.contains(heading), "missing help group {heading}");
        }
        assert!(rendered.contains("options [tool]"));
        assert!(rendered.contains("task toggle"));
        assert!(rendered.contains("kb [module]"));
        assert!(rendered.contains("auth login"));
        assert!(rendered.contains("? opens help"));
        assert!(rendered.contains("?text"));
        assert!(rendered.contains("/ask <question>"));
        assert!(rendered.contains("ask <question>"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn renders_help_aliases_and_examples_from_command_specs() {
        let backend = TestBackend::new(120, 130);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Help;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        for example in shell_help_examples() {
            assert!(
                rendered.contains(example),
                "missing featured help example {example}"
            );
        }

        for (category, alias) in [
            (ShellCommandCategory::Navigation, "/h"),
            (ShellCommandCategory::RunScan, "run ."),
            (ShellCommandCategory::OptionsTasks, "task deny <id>"),
            (ShellCommandCategory::ContextKb, "attachments"),
            (ShellCommandCategory::FindingsEvidence, "open F-0001"),
            (ShellCommandCategory::AuthConfigModel, "model 1"),
            (ShellCommandCategory::Session, "q"),
        ] {
            assert!(
                shell_command_specs()
                    .iter()
                    .any(|spec| spec.category == category && spec.aliases.contains(&alias)),
                "sample alias {alias:?} is not registered for {category:?}"
            );
            assert!(
                rendered.contains(alias),
                "missing help alias sample {alias:?} for {category:?}"
            );
        }

        assert!(rendered.contains("aliases / examples"));
        assert!(!rendered.contains("TypeScript"));
        assert!(!rendered.contains("Ink"));
    }

    #[test]
    fn plain_help_aliases_and_examples_are_width_safe() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Help;

        let rendered = render_plain_app(&app, 80);

        assert!(rendered.contains("HELP"));
        assert!(rendered.contains("aliases / examples"));
        for example in shell_help_examples() {
            assert!(
                rendered.contains(example),
                "missing plain help example {example}"
            );
        }
        for alias in [
            "/h",
            "run .",
            "task deny <id>",
            "attachments",
            "open F-0001",
            "model 1",
            "q",
        ] {
            assert!(rendered.contains(alias), "missing plain help alias {alias}");
        }
        assert!(!rendered.contains("TypeScript"));
        assert!(!rendered.contains("Ink"));
        assert_strict_plain_80(&rendered);
    }

    #[test]
    fn viewport_help_remains_navigable_at_24_rows() {
        let backend = TestBackend::new(110, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Help;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let first_page = format!("{:?}", terminal.backend().buffer());
        assert!(first_page.contains("HELP"));
        assert!(first_page.contains("NAVIGATION"));

        app.help_scroll = usize::MAX;
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let last_page = format!("{:?}", terminal.backend().buffer());
        assert!(last_page.contains("SESSION"));
        assert!(last_page.contains("[PgUp/PgDn] scroll"), "{last_page}");
        assert!(!last_page.contains("┌"));
    }

    #[test]
    fn viewport_tools_remain_navigable_at_24_rows() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let last_tool = app.registry.tools().last().unwrap().name.clone();
        app.shell_view = ShellView::Tools;
        app.tools_scroll = usize::MAX;

        let backend = TestBackend::new(110, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains(&last_tool),
            "missing last tool {last_tool}"
        );
        assert!(rendered.contains("[PgUp/PgDn] scroll"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn viewport_expanded_modules_remain_navigable_at_24_rows() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let last_defense_module = app
            .registry
            .modules()
            .filter(|module| module_category(module.metadata().kind).0 == "DEFENSE")
            .last()
            .unwrap()
            .metadata()
            .id
            .clone();
        app.shell_view = ShellView::Catalog;
        app.catalog_expanded = true;
        app.modules_scroll = usize::MAX;

        let backend = TestBackend::new(110, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains(&last_defense_module),
            "missing last module {last_defense_module}"
        );
        assert!(rendered.contains("[PgUp/PgDn] scroll"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn viewport_findings_keeps_cursor_visible_at_24_rows() {
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Findings;
        app.findings_cursor = 29;
        app.findings = (0..30)
            .map(|index| {
                let mut finding = Finding::new_semgrep(
                    format!("demo.rule.{index:04}"),
                    "src/app.rs",
                    index + 1,
                    None,
                    Severity::High,
                    format!("title-{index:02}\nEvidence: proof-{index:02}"),
                );
                finding.fingerprint = format!("fp-{index:04}");
                finding
            })
            .collect();

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("F-0030"));
        assert!(rendered.contains("title-29"));
        assert!(!rendered.contains("F-0001"));
        assert!(rendered.contains("[j/k/g/G] move"));
        assert!(rendered.contains("[PgUp/PgDn] page"));
        assert!(rendered.contains("[Enter] open"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn keybind_footer_advertises_findings_navigation_keys_at_80_columns() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Findings;
        app.findings = vec![Finding::new_semgrep(
            "demo.rule",
            "src/app.rs",
            1,
            None,
            Severity::High,
            "title\nEvidence: proof",
        )];

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("[j/k/g/G] move"));
        assert!(rendered.contains("[PgUp/PgDn] page"));
        assert!(rendered.contains("[Enter] open"));
        assert!(!rendered.contains("[open <id>]"));
    }

    #[test]
    fn keybind_footer_advertises_module_run_actor_and_pause_resume_keys() {
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        let cancel = ScanCancellation::default();
        app.set_scan_cancel_for_test(cancel.clone());
        app.scan = Some(crate::app::ScanPanelState {
            run_id: Some("run-1".to_string()),
            target: std::path::PathBuf::from("."),
            stage: "running".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: false,
            error: None,
        });
        app.shell_view = ShellView::ModuleRun;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let running = format!("{:?}", terminal.backend().buffer());
        assert!(running.contains("[1..4] actor"));
        assert!(running.contains("[p] pause"));
        assert!(!running.contains("[actor 1]"));

        cancel.pause();
        if let Some(scan) = &mut app.scan {
            scan.stage = "paused".to_string();
        }
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let paused = format!("{:?}", terminal.backend().buffer());
        assert!(paused.contains("[1..4] actor"));
        assert!(paused.contains("[r] resume"));
        assert!(!paused.contains("[p] pause"));
    }

    #[test]
    fn renders_agent_chat_mode_while_question_is_active() {
        let backend = TestBackend::new(80, 22);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(
            V2Config {
                model: Some("openai:gpt-4.1".to_string()),
                ..V2Config::default()
            },
            None,
        );
        app.agent_chat = Some(crate::app::AgentChatView {
            question: "What should I run first?".to_string(),
            answer: None,
            running: true,
            abort_requested: false,
            error: None,
        });
        app.shell_view = ShellView::AgentChat;

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("AGENT"));
        assert!(rendered.contains("running"));
        assert!(rendered.contains("mode:agent"));
        assert!(rendered.contains("agent: active"));
        assert!(rendered.contains("kuzushi/agent>"));
        assert!(!rendered.contains("┌"));
    }

    #[test]
    fn renders_honest_abort_requested_states() {
        let backend = TestBackend::new(96, 22);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(
            V2Config {
                model: Some("openai:gpt-4.1".to_string()),
                ..V2Config::default()
            },
            None,
        );
        app.shell_view = ShellView::AgentChat;
        app.agent_chat = Some(crate::app::AgentChatView {
            question: "What changed?".to_string(),
            answer: None,
            running: true,
            abort_requested: true,
            error: None,
        });

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let agent_rendered = format!("{:?}", terminal.backend().buffer());
        assert!(agent_rendered.contains("abort requested"));
        assert!(agent_rendered.contains("Process kill is not confirmed"));
        assert!(!agent_rendered.contains("killed"));

        let backend = TestBackend::new(96, 22);
        let mut terminal = Terminal::new(backend).unwrap();
        app.shell_view = ShellView::ModuleRun;
        app.agent_chat = None;
        app.scan = Some(crate::app::ScanPanelState {
            run_id: Some("run-1".to_string()),
            target: std::path::PathBuf::from("."),
            stage: "abort requested".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: true,
            error: None,
        });

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let scan_rendered = format!("{:?}", terminal.backend().buffer());
        assert!(scan_rendered.contains("abort requested"));
        assert!(scan_rendered.contains("waiting for subprocess"));
        assert!(!scan_rendered.contains("killed"));
    }

    #[test]
    fn renders_shell_module_plan_and_run_routing_modes() {
        let cases = [
            {
                let app = ShellApp::new(V2Config::default(), None);
                (app, "mode:shell", "kuzushi>")
            },
            {
                let mut app = ShellApp::new(V2Config::default(), None);
                app.focused_module = Some("sast".to_string());
                app.shell_view = ShellView::Module;
                (app, "mode:module", "kuzushi/sast>")
            },
            {
                let mut app = ShellApp::new(V2Config::default(), None);
                app.set_pending_plan(crate::app::PlanProposal {
                    goal: "tighten SAST options".to_string(),
                    summary: "set scanner controls".to_string(),
                    changes: Vec::new(),
                    unsupported: Vec::new(),
                });
                (app, "mode:plan", "kuzushi/plan>")
            },
            {
                let mut app = ShellApp::new(V2Config::default(), None);
                app.scan = Some(crate::app::ScanPanelState {
                    run_id: Some("run-1".to_string()),
                    target: std::path::PathBuf::from("."),
                    stage: "running semgrep".to_string(),
                    findings_count: 0,
                    running: true,
                    abort_requested: false,
                    error: None,
                });
                app.shell_view = ShellView::ModuleRun;
                (app, "mode:run", "kuzushi/run>")
            },
        ];

        for (app, mode, prompt) in cases {
            let backend = TestBackend::new(96, 24);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|frame| render_app(frame, &app)).unwrap();
            let rendered = format!("{:?}", terminal.backend().buffer());

            assert!(rendered.contains(mode), "missing {mode} in {rendered}");
            assert!(rendered.contains(prompt), "missing {prompt} in {rendered}");
            assert!(!rendered.contains("┌"));
        }
    }

    #[test]
    fn renders_all_ink_parity_shell_surfaces() {
        let cases = vec![
            (ShellView::Catalog, "target:none"),
            (ShellView::Module, "semgrep"),
            (ShellView::ModuleRun, "TRANSCRIPT"),
            (ShellView::Findings, "filters"),
            (ShellView::Tune, "TUNE"),
            (ShellView::Threat(ThreatView::Dfd), "DFD"),
            (ShellView::Threat(ThreatView::Stories), "STORIES"),
            (ShellView::ThreatEditor, "THREAT MODEL EDIT"),
            (ShellView::PromptsEditor, "PROMPTS"),
            (ShellView::ActorDetail(1), "ACTOR 1"),
            (ShellView::Runs, "RUNS"),
            (ShellView::Replay("run-1".to_string()), "REPLAY"),
            (ShellView::Trace("run-1".to_string()), "TRACE"),
            (ShellView::Help, "HELP"),
            (ShellView::Config, "CONFIG"),
            (ShellView::Tools, "TOOLS"),
            (
                ShellView::Options(crate::app::OptionsView {
                    tool_name: "sast:scan".to_string(),
                    filter: crate::app::OptionsFilter::Standard,
                }),
                "OPTIONS",
            ),
            (ShellView::SastTasks, "SAST TASKS"),
            (ShellView::Context, "CONTEXT"),
            (ShellView::Workspace, "WORKSPACE"),
            (ShellView::KnowledgeBase, "KB ATTACHMENTS"),
            (ShellView::AgentChat, "AGENT"),
            (ShellView::History, "COMMAND HISTORY"),
            (ShellView::Story, "SESSION STORY"),
        ];

        for (view, expected) in cases {
            let backend = TestBackend::new(110, 26);
            let mut terminal = Terminal::new(backend).unwrap();
            let mut app = ShellApp::new(V2Config::default(), None);
            app.focused_module = Some("semgrep".to_string());
            let is_dfd = matches!(view, ShellView::Threat(ThreatView::Dfd));
            app.shell_view = view;

            terminal.draw(|frame| render_app(frame, &app)).unwrap();
            let rendered = format!("{:?}", terminal.backend().buffer());

            assert!(rendered.contains(expected), "missing {expected}");
            // DFD diagram intentionally uses box-drawing; suppress the
            // no-Ink-dashboard guard for that one view.
            if !is_dfd {
                assert!(!rendered.contains("┌"), "{expected} drew a box");
            }
        }
    }

    fn buffer_row_text(buffer: &Buffer, width: u16, y: u16) -> String {
        let mut text = String::new();
        for x in 0..width {
            text.push_str(buffer[(x, y)].symbol());
        }
        text
    }

    fn assert_strict_plain_80(rendered: &str) {
        assert_strict_plain_width(rendered, 80);
    }

    fn assert_strict_plain_width(rendered: &str, width: usize) {
        assert!(
            !rendered.contains('\u{1b}'),
            "plain output contained ANSI escape: {rendered:?}"
        );
        assert!(
            !rendered
                .chars()
                .any(|ch| ('\u{2500}'..='\u{257f}').contains(&ch)),
            "plain output contained box drawing: {rendered:?}"
        );
        for line in rendered.lines() {
            assert!(
                line.chars().count() <= width,
                "plain line exceeded {width} columns: {line:?}"
            );
        }
    }

    fn line_text(line: &Line<'_>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn progress_bar_line_matches_design_glyphs_and_count() {
        let line = progress_bar_line("semgrep", 612, 612, "done · 18 raw hits", ProgressKind::Done);
        let text = line_text(&line);
        assert!(text.contains("semgrep"));
        assert!(text.contains("[████████████████████████]"));
        assert!(text.contains("612/612"));
        assert!(text.contains("done · 18 raw hits"));
    }

    #[test]
    fn progress_bar_line_partial_fills_proportionally() {
        let line = progress_bar_line("agentic-sast", 87, 120, "tracing…", ProgressKind::Active);
        let text = line_text(&line);
        // 87/120 = 0.725; round(0.725 * 24) = 17 filled, 7 empty
        let filled = text.matches('█').count();
        let empty = text.matches('░').count();
        assert_eq!(filled, 17, "expected 17 filled bars: {text:?}");
        assert_eq!(empty, 7, "expected 7 empty bars: {text:?}");
        assert!(text.contains("87/120"));
    }

    #[test]
    fn progress_bar_line_zero_total_renders_empty() {
        let line = progress_bar_line("idle", 0, 0, "queued", ProgressKind::Failing);
        let text = line_text(&line);
        assert_eq!(text.matches('█').count(), 0);
        assert_eq!(text.matches('░').count(), 24);
    }

    #[test]
    fn section_header_uppercases_and_pads_dashes() {
        let line = section_header_line("findings · 11 triaged", 60);
        let text = line_text(&line);
        assert!(text.starts_with("FINDINGS · 11 TRIAGED"));
        assert!(text.ends_with("─"));
        assert_eq!(text.chars().count(), 60);
    }

    #[test]
    fn compact_finding_row_renders_alias_severity_and_location() {
        let line = compact_finding_row(
            "F-0001",
            Severity::Critical,
            "sql injection via order_id concatenation",
            "apps/api/orders.rs:142",
            120,
        );
        let text = line_text(&line);
        assert!(text.contains("F-0001"));
        assert!(text.contains("CRITICAL"));
        assert!(text.contains("sql injection via order_id"));
        assert!(text.contains("apps/api/orders.rs:142"));
    }
}
