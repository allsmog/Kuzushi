use super::*;
use crate::app::{auth_ready_for_provider, visible_model_choices, ModelChoice};

pub(crate) fn model_picker_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = model_picker_intro(app, area.width);
    let choices = visible_model_choices(app.config().model.as_deref());
    let widths = picker_column_widths(&choices);
    for (idx, choice) in choices.iter().enumerate() {
        lines.push(model_picker_row(app, idx, choice, widths, area.width));
    }
    lines.push(offline_demo_action_line(area.width));
    lines.push(blank());
    lines.push(model_picker_controls(area.width as usize));
    lines
}

fn model_picker_intro(app: &ShellApp, width: u16) -> Vec<Line<'static>> {
    let mut lines = vec![divider("CHOOSE A MODEL", width)];
    lines.extend(confirmed_target_line(app, width as usize));
    lines.push(blank());
    lines.extend(
        wrap_text(
            "Kuzushi does not silently pick a model for you. Select one to continue.",
            width as usize,
        )
        .into_iter()
        .map(|line| muted(&line)),
    );
    lines.push(blank());
    lines
}

fn model_picker_controls(width: usize) -> Line<'static> {
    responsive_keybind_hint_line(
        width,
        &[
            ("↑/↓/j/k", "move"),
            ("d/demo", "offline fixture"),
            (":", "type a command"),
            ("Enter", "confirm"),
            ("Esc/q", "defer (you'll need to /model later)"),
        ],
        &[
            ("↑/↓", "move"),
            ("Enter", "select"),
            ("d", "demo"),
            ("Esc", "defer"),
        ],
    )
}

/// Widest visible label and provider/effort cells, so the columns line up
/// instead of jittering with each row's text length.
fn picker_column_widths(choices: &[&ModelChoice]) -> (usize, usize) {
    let label = choices
        .iter()
        .map(|choice| display_width(choice.label))
        .max()
        .unwrap_or(0);
    let provider = choices
        .iter()
        .map(|choice| display_width(&provider_effort_cell(choice)))
        .max()
        .unwrap_or(0);
    (label, provider)
}

fn provider_effort_cell(choice: &ModelChoice) -> String {
    format!(
        "{}/{}",
        crate::app::display_model_provider(choice.provider),
        choice.thinking_level
    )
}

fn model_picker_row(
    app: &ShellApp,
    idx: usize,
    choice: &ModelChoice,
    (label_width, provider_width): (usize, usize),
    width: u16,
) -> Line<'static> {
    let auth_hint = auth_hint_for(choice);
    let provider_effort = provider_effort_cell(choice);
    let full = format!(
        "{label:<label_width$}   {provider_effort:<provider_width$}   {auth_hint}",
        label = choice.label,
    );
    let body = responsive_model_row(choice, &full, label_width, width as usize);
    selection_band(
        &body,
        idx == app.router.model_picker().cursor(),
        width as usize,
    )
}

fn responsive_model_row(
    choice: &ModelChoice,
    full: &str,
    label_width: usize,
    width: usize,
) -> String {
    let budget = width.saturating_sub(4);
    if display_width(full) <= budget {
        return full.to_string();
    }
    let status = compact_auth_hint(choice);
    let status_width = display_width(status);
    let label_width = label_width.min(budget.saturating_sub(status_width + 2));
    format!("{}  {status}", pad(choice.label, label_width))
}

fn compact_auth_hint(choice: &ModelChoice) -> &'static str {
    match (choice.provider, auth_ready_for_provider(choice.provider)) {
        (_, true) => "ready",
        ("openai-codex", false) => "OAuth login needed",
        (_, false) => "credentials needed",
    }
}

fn offline_demo_action_line(width: u16) -> Line<'static> {
    let body = if width >= 80 {
        "  demo  Try offline fixture   local/no auth   deterministic scan"
    } else {
        "  demo  offline fixture · deterministic · no auth"
    };
    Line::styled(fit(body, width as usize), theme::muted())
}

fn auth_hint_for(choice: &ModelChoice) -> String {
    let ready = auth_ready_for_provider(choice.provider);
    match (choice.provider, ready) {
        ("anthropic", true) => "auth ready".to_string(),
        ("anthropic", false) => "auth required".to_string(),
        ("openai", true) => "API key ready".to_string(),
        ("openai", false) => "needs OPENAI_API_KEY or OAuth".to_string(),
        ("openai-codex", true) => "OAuth stored".to_string(),
        ("openai-codex", false) => "needs OpenAI OAuth login".to_string(),
        (other, _) => format!("provider {other}"),
    }
}
