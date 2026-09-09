use super::*;

pub(super) fn budget_editor_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let width = area.width as usize;
    let mut lines = vec![divider("SESSION BUDGET", area.width)];
    lines.extend(budget_policy_lines(app, width));
    lines.push(muted(&fit("Budget USD · empty + Enter unsets", width)));
    let errors = budget_error_lines(app, width);
    let field_height = (area.height as usize)
        .saturating_sub(lines.len() + errors.len() + 1)
        .clamp(1, 3);
    lines.extend(crate::renderer::shared::field_editor_lines(
        app.router.setup().budget_field(),
        width,
        field_height,
    ));
    lines.extend(errors);
    lines.push(responsive_keybind_hint_line(
        width,
        &[
            ("←/→", "cursor"),
            ("Ctrl+U", "clear to start"),
            ("Enter", "save"),
            ("Esc", "cancel"),
        ],
        &[("Enter", "save"), ("Esc", "cancel")],
    ));
    lines
}

fn budget_policy_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    let saved = budget_amount_label(app.session().session_budget_usd(), "not set");
    let ceiling = budget_amount_label(
        app.config().operator.spend_hard_ceiling_usd,
        "not configured",
    );
    [
        format!("Current session cap: {saved}"),
        format!("Hard ceiling: {ceiling}"),
    ]
    .into_iter()
    .flat_map(|text| wrap_text(&text, width))
    .map(|line| muted(&line))
    .collect()
}

fn budget_amount_label(value: Option<f64>, unset: &str) -> String {
    value
        .map(|value| format!("${value:?}"))
        .unwrap_or_else(|| unset.into())
}

fn budget_error_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    app.router
        .setup()
        .budget_error()
        .into_iter()
        .flat_map(|error| wrap_text(error, width))
        .map(|line| styled(&line, theme::danger()))
        .collect()
}

#[cfg(test)]
mod tests;
