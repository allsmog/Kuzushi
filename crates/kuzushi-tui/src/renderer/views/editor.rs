use super::*;

pub(in crate::renderer) fn tune_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
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

pub(in crate::renderer) fn prompts_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
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

pub(in crate::renderer) fn actor_detail_lines(
    app: &ShellApp,
    area: Rect,
    index: usize,
) -> Vec<Line<'static>> {
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
    lines.push(detail("filter", app.actor_detail_filter.label()));
    lines.push(keybind_hint_line(&[
        ("f", "cycle filter"),
        ("0", "reset"),
        ("j/k/g/G", "scroll"),
        ("back", "home"),
    ]));
    lines.push(blank());

    let visible = area.height.saturating_sub(8).max(2) as usize;
    let filter = app.actor_detail_filter;
    let mut kept: Vec<&crate::app::LogLine> = app
        .log
        .iter()
        .filter(|line| filter.keeps(&line.prefix))
        .collect();
    let start = kept.len().saturating_sub(visible);
    kept.drain(..start);
    if kept.is_empty() {
        lines.push(muted("(no matching transcript entries under this filter)"));
    } else {
        for line in kept {
            lines.push(Line::from(vec![
                Span::styled(format!("{:>8} ", line.prefix), theme::subtle()),
                Span::raw(line.body.clone()),
            ]));
        }
    }
    lines
}
