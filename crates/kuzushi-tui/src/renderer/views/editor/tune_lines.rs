use super::*;
use crate::ui_view_models::{
    prompts_model, tune_model, PromptRow, PromptStackLayer, PromptStackModel, TuneActionRow,
    TuneHouseRules, TuneModel,
};

const TUNE_HINT_GUTTER: &str = "    ";
const PROMPT_TABLE_GUTTER: usize = 2;

pub(crate) fn tune_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let model = tune_model(app, house_rule_line_limit(area));
    lines.push(blank());
    append_tune_summary(&mut lines, &model, area.width);
    append_tune_actions(&mut lines, &model.actions, area.width);
    append_house_rules(&mut lines, &model.house_rules, area);
    lines.push(responsive_keybind_hint_line(
        area.width as usize,
        &[
            ("↑/↓/j/k", "move"),
            ("Enter", "activate"),
            ("show/set/reset", "direct"),
            ("back", "home"),
        ],
        &[("j/k", "move"), ("Enter", "open"), ("back", "home")],
    ));
    lines
}

fn append_tune_summary(lines: &mut Vec<Line<'static>>, model: &TuneModel, width: u16) {
    lines.push(divider("TUNE", width));
    lines.extend(detail_wrapped("module", &model.module, width));
    lines.extend(detail_wrapped(
        "severity floor",
        model.severity_floor,
        width,
    ));
    lines.extend(detail_wrapped(
        "triage confidence",
        model.triage_confidence,
        width,
    ));
    lines.extend(detail_wrapped(
        "scan concurrency",
        model.scan_concurrency,
        width,
    ));
    lines.extend(detail_wrapped(
        "house rules",
        &model.house_rules_path,
        width,
    ));
    lines.push(blank());
}

fn append_tune_actions(lines: &mut Vec<Line<'static>>, actions: &[TuneActionRow], width: u16) {
    lines.push(divider("ACTIONS", width));
    for action in actions {
        lines.push(tune_action_label_line(action, width));
        lines.push(tune_action_hint_line(action, width));
    }
}

fn tune_action_hint_line(action: &TuneActionRow, width: u16) -> Line<'static> {
    let gutter = fit(TUNE_HINT_GUTTER, width as usize);
    let hint_width = (width as usize).saturating_sub(display_width(&gutter));
    Line::from(vec![
        Span::raw(gutter),
        Span::styled(fit(action.hint, hint_width), theme::muted()),
    ])
}

fn tune_action_label_line(action: &TuneActionRow, width: u16) -> Line<'static> {
    let marker = if action.selected { ">" } else { " " };
    let style = if action.selected {
        theme::accent().add_modifier(Modifier::BOLD)
    } else {
        theme::primary()
    };
    Line::styled(
        fit(&format!("{marker} {}", action.label), width as usize),
        style,
    )
}

fn append_house_rules(lines: &mut Vec<Line<'static>>, house_rules: &TuneHouseRules, area: Rect) {
    lines.push(blank());
    match house_rules {
        TuneHouseRules::Present(rows) => {
            lines.push(divider("HOUSE RULES", area.width));
            for raw in rows {
                lines.push(Line::raw(fit(raw, area.width as usize)));
            }
            lines.push(blank());
        }
        TuneHouseRules::Unreadable(path) => {
            lines.push(muted(&fit(
                &format!("house rules file is unreadable: {path}"),
                area.width as usize,
            )));
        }
        TuneHouseRules::Empty => {
            lines.push(muted(&fit(
                "no house rules set — choose `edit house rules` above to add one",
                area.width as usize,
            )));
        }
    }
}

fn house_rule_line_limit(area: Rect) -> usize {
    (area.height as usize).saturating_sub(10).max(4)
}

#[cfg(test)]
mod tune_width_tests {
    use super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn tune_projection_includes_its_hint_gutter_in_narrow_budgets() {
        let app = ShellApp::new(V2Config::default(), None);
        for width in [40, 60, 80] {
            let lines = tune_lines(&app, Rect::new(0, 0, width, 30));
            let overlong = lines.iter().find(|line| {
                line.spans
                    .iter()
                    .map(|span| display_width(span.content.as_ref()))
                    .sum::<usize>()
                    > width as usize
            });

            assert!(overlong.is_none(), "tune exceeded {width}: {overlong:?}");
        }
    }

    #[test]
    fn prompt_tables_include_their_external_gutter_in_narrow_budgets() {
        let row = PromptRow {
            role: "security-reviewer".to_string(),
            verb: "日本語-hunt".to_string(),
            source: "override".to_string(),
            path: "/long/path/to/prompt.md".to_string(),
            selected: true,
        };
        for width in [40, 60, 80] {
            let area = Rect::new(0, 0, width, 20);
            let row_widths = prompt_table_widths(width);
            let stack_widths = prompt_stack_widths(area);
            let line = prompt_row_line(&row, area);
            let rendered_width = line
                .spans
                .iter()
                .map(|span| display_width(span.content.as_ref()))
                .sum::<usize>();

            assert_eq!(
                PROMPT_TABLE_GUTTER + table_width(&row_widths),
                width as usize
            );
            assert_eq!(
                PROMPT_TABLE_GUTTER + table_width(&stack_widths),
                width as usize
            );
            assert!(rendered_width <= width as usize);
        }
    }
}

pub(crate) fn prompts_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    if let Some(document) = app.router.prompts().document() {
        return prompt_document_lines(document, area);
    }
    let mut lines = context_strip(app, area);
    let model = prompts_model(app);
    lines.push(blank());
    append_prompts_header(&mut lines, &model.module, area.width);
    append_prompt_rows(&mut lines, &model.rows, area);
    if let Some(stack) = &model.stack {
        append_prompt_stack(&mut lines, stack, area);
    } else {
        lines.push(muted("no editable prompts are declared for this module"));
    }
    lines.push(blank());
    lines.push(keybind_hint_line(&[
        ("↑/↓/j/k", "row"),
        ("e", "edit"),
        ("s", "show"),
        ("d", "diff"),
        ("r", "reset"),
        ("S", "set"),
        ("cmd", "mutate/approve/reject"),
        ("Enter", "show"),
        ("back", "home"),
    ]));
    lines
}

fn prompt_document_lines(document: &PromptDocumentState, area: Rect) -> Vec<Line<'static>> {
    let width = area.width as usize;
    let mut lines = vec![divider("PROMPT REVIEW", area.width)];
    lines.push(prompt_document_header(document));
    lines.push(muted(&fit(&document.path.display().to_string(), width)));
    lines.push(muted(&fit(
        &format!("{} · {}", document.hash, document.context_note),
        width,
    )));
    lines.push(blank());
    let body_rows = (area.height as usize).saturating_sub(7).max(1);
    let top_row = visible_prompt_top_row(
        document.top_row,
        document.cursor_row,
        document.lines.len(),
        body_rows,
    );
    for (index, text) in document
        .lines
        .iter()
        .enumerate()
        .skip(top_row)
        .take(body_rows)
    {
        lines.push(prompt_document_line(document, index, text, width));
    }
    while lines.len() < (area.height as usize).saturating_sub(1) {
        lines.push(Line::raw("~"));
    }
    lines.push(prompt_document_status_line(document, width));
    lines
}

fn prompt_document_header(document: &PromptDocumentState) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!(" {} ", prompt_document_mode_label(document.mode)),
            theme::accent().add_modifier(Modifier::REVERSED),
        ),
        Span::styled(
            format!(
                " {} · {}/{} · {} ",
                document.role,
                document.prompt_index + 1,
                document.prompt_specs.len(),
                document.source
            ),
            theme::primary(),
        ),
        Span::styled(if document.dirty { "[+]" } else { "" }, theme::warn()),
    ])
}

fn prompt_document_line(
    document: &PromptDocumentState,
    index: usize,
    text: &str,
    width: usize,
) -> Line<'static> {
    let prefix = format!("{:>4} ", index + 1);
    let available = width.saturating_sub(prefix.len());
    if index != document.cursor_row {
        return Line::from(vec![
            Span::styled(prefix, theme::subtle()),
            Span::raw(fit(text, available)),
        ]);
    }
    let window_start = prompt_horizontal_window_start(document.cursor_col, available);
    let before = text
        .chars()
        .skip(window_start)
        .take(document.cursor_col.saturating_sub(window_start))
        .collect::<String>();
    let cursor = text.chars().nth(document.cursor_col).unwrap_or(' ');
    let after = text
        .chars()
        .skip(document.cursor_col + 1)
        .take(available.saturating_sub(before.chars().count() + 1))
        .collect::<String>();
    Line::from(vec![
        Span::styled(prefix, theme::accent()),
        Span::raw(before),
        Span::styled(
            cursor.to_string(),
            theme::accent().add_modifier(Modifier::REVERSED),
        ),
        Span::raw(after),
    ])
}

fn visible_prompt_top_row(
    requested_top: usize,
    cursor_row: usize,
    line_count: usize,
    body_rows: usize,
) -> usize {
    let top_row = requested_top.min(cursor_row);
    let top_row = if cursor_row >= top_row.saturating_add(body_rows) {
        cursor_row + 1 - body_rows
    } else {
        top_row
    };
    top_row.min(line_count.saturating_sub(body_rows))
}

fn prompt_horizontal_window_start(cursor_col: usize, available: usize) -> usize {
    cursor_col.saturating_sub(available.saturating_sub(1))
}

#[cfg(test)]
mod prompt_document_viewport_tests {
    use super::*;

    #[test]
    fn compact_viewport_keeps_cursor_row_visible() {
        assert_eq!(visible_prompt_top_row(0, 15, 30, 8), 8);
        assert_eq!(visible_prompt_top_row(8, 3, 30, 8), 3);
        assert_eq!(visible_prompt_top_row(25, 29, 30, 8), 22);
    }

    #[test]
    fn horizontal_window_keeps_cursor_cell_visible() {
        assert_eq!(prompt_horizontal_window_start(4, 12), 0);
        assert_eq!(prompt_horizontal_window_start(20, 12), 9);
    }
}

fn prompt_document_status_line(document: &PromptDocumentState, width: usize) -> Line<'static> {
    let text = match document.mode {
        PromptDocumentMode::Normal => format!(
            " i edit · :w save · :wq save+{} · :q return · j/k/h/l move · Ctrl+f/b page · gg/G ends · [/] role ",
            prompt_document_return_label(document)
        ),
        PromptDocumentMode::Insert => " -- INSERT -- · Esc normal ".to_string(),
        PromptDocumentMode::Command => format!(":{}", document.command),
        PromptDocumentMode::ConfirmDiscard => " Discard unsaved changes? y/n ".to_string(),
    };
    Line::styled(
        fit(&text, width),
        theme::accent().add_modifier(Modifier::REVERSED),
    )
}

fn prompt_document_return_label(document: &PromptDocumentState) -> &'static str {
    if document.origin == ShellView::PlanningPicker {
        "setup"
    } else {
        "return"
    }
}

fn prompt_document_mode_label(mode: PromptDocumentMode) -> &'static str {
    match mode {
        PromptDocumentMode::Normal => "NORMAL",
        PromptDocumentMode::Insert => "INSERT",
        PromptDocumentMode::Command => "COMMAND",
        PromptDocumentMode::ConfirmDiscard => "CONFIRM",
    }
}

fn append_prompts_header(lines: &mut Vec<Line<'static>>, module: &str, width: u16) {
    lines.push(divider("PROMPTS", width));
    lines.push(detail("module", module));
    lines.push(blank());
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(
            table_text(
                &["role", "verb", "override", "override path"],
                &prompt_table_widths(width),
            ),
            theme::subtle(),
        ),
    ]));
}

fn append_prompt_rows(lines: &mut Vec<Line<'static>>, rows: &[PromptRow], area: Rect) {
    for row in rows {
        lines.push(prompt_row_line(row, area));
    }
}

fn prompt_row_line(row: &PromptRow, area: Rect) -> Line<'static> {
    let marker = if row.selected { ">" } else { " " };
    let style = if row.selected {
        theme::accent().add_modifier(Modifier::BOLD)
    } else {
        theme::primary()
    };
    Line::styled(
        format!(
            "{marker} {}",
            table_text(
                &[&row.role, &row.verb, &row.source, &row.path],
                &prompt_table_widths(area.width),
            )
        ),
        style,
    )
}

fn prompt_table_widths(width: u16) -> [usize; 4] {
    fit_table_widths(
        (width as usize).saturating_sub(PROMPT_TABLE_GUTTER),
        [20, 14, 10, 24],
        [6, 4, 4, 6],
    )
}

fn append_prompt_stack(lines: &mut Vec<Line<'static>>, stack: &PromptStackModel, area: Rect) {
    lines.push(blank());
    lines.push(divider(
        &format!("PROMPT STACK · {}", stack.verb),
        area.width,
    ));
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(
            table_text(
                &["layer", "state", "hash", "path"],
                &prompt_stack_widths(area),
            ),
            theme::subtle(),
        ),
    ]));
    for layer in &stack.layers {
        lines.push(prompt_stack_layer_line(layer, area));
    }
}

fn prompt_stack_layer_line(layer: &PromptStackLayer, area: Rect) -> Line<'static> {
    Line::styled(
        fit(
            &format!(
                "  {}",
                table_text(
                    &[layer.layer, &layer.state, &layer.hash, &layer.path],
                    &prompt_stack_widths(area),
                )
            ),
            area.width as usize,
        ),
        theme::primary(),
    )
}

fn prompt_stack_widths(area: Rect) -> Vec<usize> {
    fit_table_widths(
        (area.width as usize).saturating_sub(PROMPT_TABLE_GUTTER),
        [18, 16, 22, 36],
        [5, 5, 6, 4],
    )
    .to_vec()
}
