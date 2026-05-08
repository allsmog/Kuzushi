use super::*;

pub(crate) fn tune_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
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
    lines.push(divider("ACTIONS", area.width));
    let cursor = app.tune_cursor_clamped();
    for (index, action) in crate::app::TuneAction::ORDER.iter().enumerate() {
        let selected = index == cursor;
        let marker = if selected { ">" } else { " " };
        let style = if selected {
            theme::accent().add_modifier(Modifier::BOLD)
        } else {
            theme::primary()
        };
        lines.push(Line::styled(
            fit(&format!("{marker} {}", action.label()), area.width as usize),
            style,
        ));
        lines.push(Line::styled(
            fit(&format!("    {}", action.hint()), area.width as usize),
            theme::muted(),
        ));
    }
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
                "(no house rules set; pick edit house rules and type a value)",
            ));
        }
    }
    lines.push(keybind_hint_line(&[
        ("Up/Down", "move"),
        ("Enter", "activate"),
        ("show/set/reset", "direct"),
        ("back", "home"),
    ]));
    lines
}

pub(crate) fn prompts_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let module = app.focused_module.as_deref().unwrap_or("semgrep");
    lines.push(blank());
    lines.push(divider("PROMPTS", area.width));
    lines.push(detail("module", module));
    lines.push(blank());
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(
            table_text(&["verb", "source", "override path"], &[12, 10, 28]),
            theme::subtle(),
        ),
    ]));
    let cursor = app.prompts_cursor_clamped();
    for (index, verb) in crate::app::ShellApp::PROMPT_VERB_NAMES.iter().enumerate() {
        let selected = index == cursor;
        let marker = if selected { ">" } else { " " };
        let style = if selected {
            theme::accent().add_modifier(Modifier::BOLD)
        } else {
            theme::primary()
        };
        let path = format!(".kuzushi/prompts/{module}/{verb}.md");
        lines.push(Line::styled(
            fit(
                &format!(
                    "{marker} {}",
                    table_text(&[verb, "builtin", &path], &[12, 10, value_width(area, 28)],)
                ),
                area.width as usize,
            ),
            style,
        ));
    }
    lines.push(blank());
    lines.push(keybind_hint_line(&[
        ("Up/Down", "row"),
        ("e", "edit"),
        ("s", "show"),
        ("d", "diff"),
        ("r", "reset"),
        ("S", "set"),
        ("Enter", "show"),
        ("back", "home"),
    ]));
    lines
}
