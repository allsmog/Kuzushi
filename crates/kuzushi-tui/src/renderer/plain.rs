use kuzushi_core::{AttachmentKind, SUPPORTED_ATTACHMENT_MODULES};
use ratatui::layout::Rect;
use ratatui::prelude::Line;

use crate::app::{LogLine, ShellApp, ShellView};
use crate::commands::{
    shell_command_specs, shell_help_examples, ShellCommandCategory, ShellCommandSpec,
};

use super::{
    compact_target_path, findings_count_summary, fit, format_json_value, help_category_blurb,
    join_or_dash, kb_artifact_widths, kb_attachment_widths, model_auth_status, option_description,
    option_table_widths, option_type_label, option_visible, options_filter_label,
    routing_mode_segment, sast_task_table_widths, shell_view_lines, table_text, wrap_text,
};

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
                .map(line_to_unstyled_text)
                .collect()
        }
    };

    lines = finalize_width_safe_plain_lines(lines, width);
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
        plain_section_divider("COMMAND RESULT", width),
        format!("command: {command}"),
        "logs:".to_string(),
    ];
    let log_start = log_start.min(app.log.len());
    for line in &app.log[log_start..] {
        lines.extend(plain_log_lines(line));
    }
    lines.push(String::new());
    lines.push(plain_section_divider("VIEW", width));
    lines.extend(render_plain_lines(app, width));

    let lines = finalize_width_safe_plain_lines(lines, width);
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
    lines.push(plain_section_divider("OPTIONS", width));
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
    lines.push(plain_section_divider("SAST TASKS", width));
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
    lines.push(plain_section_divider("HELP", width));
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
        // Mirror the `category_divider` from the Ratatui renderer in plain
        // text: section name followed by the design-mockup blurb on one line.
        lines.push(format!(
            "{} — {}",
            category.label(),
            help_category_blurb(category)
        ));
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
    lines.push(plain_section_divider("CONTEXT", width));
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
    lines.push(plain_section_divider("WORKSPACE", width));
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
    lines.push(plain_section_divider("KB ATTACHMENTS", width));
    lines.push(format!("module: {module_id}"));
    lines.push(format!("store: {store}"));
    lines.push(format!(
        "supported: {}",
        SUPPORTED_ATTACHMENT_MODULES.join(", ")
    ));

    lines.push(String::new());
    lines.push(plain_section_divider("KNOWN ARTIFACTS", width));
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
    lines.push(plain_section_divider("ATTACHED", width));
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
    lines.push(plain_section_divider("CONFIG", width));
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
    lines.push(plain_section_divider("MODELS", width));
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

fn plain_section_divider(title: &str, width: usize) -> String {
    // Mirror the styled `divider` from renderer.rs in plain text:
    //   ` ── TITLE ──────────────────...───`
    // Per `design/mockups/_shared.jsx::sectionHeader`. Use ASCII hyphen
    // for the rule so non-Unicode terminals/log scrapers don't choke on
    // the box-drawing char.
    let safe_width = width.max(8);
    let lead = "-- ";
    let label = format!("{title} ");
    let used = 1 + lead.chars().count() + label.chars().count();
    let fill = safe_width.saturating_sub(used).max(1);
    format!(" {}{}{}", lead, label, "-".repeat(fill))
}

fn line_to_unstyled_text(line: Line<'static>) -> String {
    line.spans
        .into_iter()
        .map(|span| span.content.into_owned())
        .collect::<String>()
}

fn finalize_width_safe_plain_lines(lines: Vec<String>, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    for line in lines {
        let line = sanitize_for_plain_output(&line);
        if line.chars().count() <= width {
            out.push(line);
        } else if should_truncate_plain_line(&line) {
            out.push(sanitize_for_plain_output(&fit(&line, width)));
        } else {
            out.extend(
                wrap_text(&line, width)
                    .into_iter()
                    .map(|line| sanitize_for_plain_output(&line)),
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

fn sanitize_for_plain_output(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            '\u{2500}'..='\u{257f}' => '-',
            '\u{00b7}' => '|',
            _ => ch,
        })
        .collect()
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
