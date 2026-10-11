use super::*;
use crate::app::{visible_model_choices, ModelChoice};

pub(crate) fn model_picker_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = model_picker_intro(app, area);
    let choices = visible_model_choices(app.config());
    let widths = picker_column_widths(&choices);
    let footer = model_picker_footer(app, area);
    let candidate_budget = (area.height as usize)
        .saturating_sub(lines.len() + footer.len())
        .max(1);
    let show_window_label = choices.len() > candidate_budget;
    let row_budget = candidate_budget
        .saturating_sub(usize::from(show_window_label))
        .max(1);
    let range = visible_model_range(
        choices.len(),
        crate::app::model_picker_cursor(app),
        row_budget,
    );
    if show_window_label {
        lines.push(model_window_label(
            range.start,
            range.end,
            choices.len(),
            area.width,
        ));
    }
    for idx in range {
        let choice = choices[idx];
        lines.push(model_picker_row(app, choice, widths, area.width));
    }
    lines.extend(footer);
    lines
}

fn model_picker_footer(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if area.height > 12 {
        lines.push(offline_demo_action_line(area.width));
    }
    if app.picker_prompt_focused() {
        lines.push(model_picker_controls(app, area.width as usize));
        return lines;
    }
    if let Some(detail) = selected_model_detail(app) {
        lines.push(muted(&fit(&detail, area.width as usize)));
    }
    lines.push(model_picker_controls(app, area.width as usize));
    lines
}

fn selected_model_detail(app: &ShellApp) -> Option<String> {
    let selected = app.router.model_picker().selected_id()?;
    let choice =
        crate::app::model_choices().get(crate::app::model_choice_index_by_id(selected)?)?;
    let credential = match choice.provider {
        "openai-codex" => "ChatGPT",
        "openai" => "API key",
        _ => "Claude",
    };
    Some(format!(
        "Enter: {credential} · effort {}",
        choice.thinking_level
    ))
}

fn visible_model_range(total: usize, cursor: usize, row_budget: usize) -> std::ops::Range<usize> {
    let visible = row_budget.min(total).max(1);
    let centered = cursor.saturating_sub(visible / 2);
    let start = centered.min(total.saturating_sub(visible));
    start..(start + visible).min(total)
}

fn model_window_label(start: usize, end: usize, total: usize, width: u16) -> Line<'static> {
    muted(&fit(
        &format!(" models {}-{} of {total} · ↑/↓ scroll", start + 1, end),
        width as usize,
    ))
}

fn model_picker_intro(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = vec![divider("CHOOSE A MODEL", area.width)];
    if area.height > 12 {
        lines.extend(confirmed_target_line(app, area.width as usize));
        lines.push(blank());
    }
    lines.extend(current_model_lines(app, area));
    if area.height > 16 {
        lines.extend(
            wrap_text(
                "Suggestions below. Credentials do not guarantee model access.",
                area.width as usize,
            )
            .into_iter()
            .map(|line| muted(&line)),
        );
        lines.push(blank());
    }
    lines
}

fn current_model_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let current = app.config().model.as_deref();
    let label = current
        .map(crate::app::display_model_selector)
        .unwrap_or_else(|| "not set".into());
    let mut lines = model_notice_lines(&format!("Current: {label}"), area);
    if let Some(note) = current.and_then(crate::app::model_catalog_note) {
        lines.extend(model_notice_lines(note, area));
    }
    lines
}

fn model_notice_lines(text: &str, area: Rect) -> Vec<Line<'static>> {
    if area.height <= 12 {
        return vec![muted(&fit(text, area.width as usize))];
    }
    wrap_text(text, area.width as usize)
        .into_iter()
        .map(|line| muted(&line))
        .collect()
}

fn model_picker_controls(app: &ShellApp, width: usize) -> Line<'static> {
    if app.picker_prompt_focused() {
        return responsive_keybind_hint_line(
            width,
            &[("Enter", "run command"), ("Esc", "return to picker")],
            &[("Enter", "command"), ("Esc", "picker")],
        );
    }
    responsive_keybind_hint_line(
        width,
        &[
            ("↑/↓", "move"),
            ("demo", "offline fixture"),
            ("type", "a command"),
            ("Enter", "confirm"),
            ("Esc", "keep current"),
        ],
        &[("↑/↓", "move"), ("Enter", "select"), ("Esc", "keep")],
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
    choice: &ModelChoice,
    (label_width, provider_width): (usize, usize),
    width: u16,
) -> Line<'static> {
    let auth_hint = auth_hint_for(app, choice);
    let provider_effort = provider_effort_cell(choice);
    let full = format!(
        "{label:<label_width$}   {provider_effort:<provider_width$}   {auth_hint}",
        label = choice.label,
    );
    let body = responsive_model_row(app, choice, &full, label_width, width as usize);
    selection_band(
        &body,
        Some(choice.id) == app.router.model_picker().selected_id(),
        width as usize,
    )
}

fn responsive_model_row(
    app: &ShellApp,
    choice: &ModelChoice,
    full: &str,
    label_width: usize,
    width: usize,
) -> String {
    let budget = width.saturating_sub(4);
    if display_width(full) <= budget {
        return full.to_string();
    }
    let status = compact_auth_hint(app, choice);
    let status_width = display_width(status);
    let label_width = label_width.min(budget.saturating_sub(status_width + 2));
    let label = choice
        .label
        .strip_prefix("OpenAI OAuth ")
        .unwrap_or(choice.label);
    format!("{}  {status}", pad(label, label_width))
}

fn compact_auth_hint(app: &ShellApp, choice: &ModelChoice) -> &'static str {
    match (
        choice.provider,
        app.provider_auth_ready_for(choice.provider),
    ) {
        (_, true) => "auth ready",
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

fn auth_hint_for(app: &ShellApp, choice: &ModelChoice) -> String {
    crate::ui_view_models::model_auth_status(app, choice)
}
