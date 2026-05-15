use super::*;
use crate::ui_view_models::catalog_model;

pub(crate) fn plain_config_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    push_plain_config_summary(&mut lines, app, width);
    push_plain_model_table(&mut lines, width);
    lines.push(String::new());
    lines
        .push("Next: model <n> [xhigh], auth login openai, auth login anthropic, cost".to_string());
    lines
}

fn push_plain_config_summary(lines: &mut Vec<String>, app: &ShellApp, width: usize) {
    lines.push(String::new());
    lines.push(plain_section_divider("CONFIG", width));
    lines.push(format!(
        "runtime: {}",
        crate::app::runtime_backend_label(&app.config)
    ));
    lines.push(format!("provider: {}", app.provider_label()));
    lines.push(format!(
        "model: {}",
        app.config
            .model
            .as_deref()
            .map(crate::app::display_model_selector)
            .unwrap_or_else(|| "unconfigured".to_string())
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
}

fn push_plain_model_table(lines: &mut Vec<String>, width: usize) {
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
                &fit(
                    &crate::app::model_choice_display_selector(choice),
                    widths.get(1).copied().unwrap_or(28),
                ),
                choice.thinking_level,
                &fit(
                    &model_auth_status(choice),
                    widths.get(3).copied().unwrap_or(18),
                ),
            ],
            &widths,
        ));
    }
}

pub(crate) fn plain_context_strip(app: &ShellApp, width: usize) -> Vec<String> {
    let catalog = catalog_model(app);
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
    let view = view_status_segment(app);
    vec![fit(
        &format!(
            "{} | {target} | {view} | {} | {} mods",
            routing_mode_segment(app),
            findings_count_summary(&app.findings),
            catalog.module_count
        ),
        width,
    )]
}

pub(crate) fn plain_model_widths(width: usize) -> Vec<usize> {
    let number = 3;
    let effort = 6;
    let model = if width < 88 { 28 } else { 34 };
    let gaps = 6;
    let auth = width.saturating_sub(number + model + effort + gaps).max(14);
    vec![number, model, effort, auth]
}

pub(crate) fn plain_section_divider(title: &str, width: usize) -> String {
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

pub(crate) fn line_to_unstyled_text(line: Line<'static>) -> String {
    line.spans
        .into_iter()
        .map(|span| span.content.into_owned())
        .collect::<String>()
}
