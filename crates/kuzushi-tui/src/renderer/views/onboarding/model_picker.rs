use super::*;
use crate::app::{auth_ready_for_provider, visible_model_choices, ModelChoice};

pub(crate) fn model_picker_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(divider("CHOOSE A MODEL", area.width));
    lines.push(blank());
    lines.push(muted(
        "Kuzushi does not silently pick a model for you. Select one to continue.",
    ));
    lines.push(blank());
    let choices = visible_model_choices(app.config.model.as_deref());
    let widths = picker_column_widths(&choices);
    for (idx, choice) in choices.iter().enumerate() {
        lines.push(model_picker_row(app, idx, choice, widths, area.width));
    }
    lines.push(blank());
    lines.push(keybind_hint_line(&[
        ("↑/↓", "move"),
        ("Enter", "confirm"),
        ("Esc", "defer (you'll need to /model later)"),
    ]));
    lines
}

/// Widest visible label and provider/effort cells, so the columns line up
/// instead of jittering with each row's text length.
fn picker_column_widths(choices: &[&ModelChoice]) -> (usize, usize) {
    let label = choices
        .iter()
        .map(|choice| choice.label.chars().count())
        .max()
        .unwrap_or(0);
    let provider = choices
        .iter()
        .map(|choice| provider_effort_cell(choice).chars().count())
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
    let marker = if idx == app.model_picker_cursor {
        ">"
    } else {
        " "
    };
    let auth_hint = auth_hint_for(choice);
    let provider_effort = provider_effort_cell(choice);
    let body = format!(
        "  {marker} {label:<label_width$}   {provider_effort:<provider_width$}   {auth_hint}",
        label = choice.label,
    );
    let style = if idx == app.model_picker_cursor {
        theme::success().add_modifier(Modifier::BOLD)
    } else {
        theme::primary()
    };
    Line::styled(fit(&body, width as usize), style)
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
