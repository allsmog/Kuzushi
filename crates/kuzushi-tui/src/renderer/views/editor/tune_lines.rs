use super::*;
use crate::ui_view_models::{
    prompts_model, tune_model, PromptRow, TuneActionRow, TuneHouseRules, TuneModel,
};

pub(crate) fn tune_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let model = tune_model(app, house_rule_line_limit(area));
    lines.push(blank());
    append_tune_summary(&mut lines, &model, area.width);
    append_tune_actions(&mut lines, &model.actions, area.width);
    append_house_rules(&mut lines, &model.house_rules, area);
    lines.push(keybind_hint_line(&[
        ("↑/↓/j/k", "move"),
        ("Enter", "activate"),
        ("show/set/reset", "direct"),
        ("back", "home"),
    ]));
    lines
}

fn append_tune_summary(lines: &mut Vec<Line<'static>>, model: &TuneModel, width: u16) {
    lines.push(divider("TUNE", width));
    lines.push(detail("module", &model.module));
    lines.push(detail("severity floor", model.severity_floor));
    lines.push(detail("triage confidence", model.triage_confidence));
    lines.push(detail("scan concurrency", model.scan_concurrency));
    lines.push(detail("house rules", &model.house_rules_path));
    lines.push(blank());
}

fn append_tune_actions(lines: &mut Vec<Line<'static>>, actions: &[TuneActionRow], width: u16) {
    lines.push(divider("ACTIONS", width));
    for action in actions {
        lines.push(tune_action_label_line(action, width));
        lines.push(Line::styled(
            fit(&format!("    {}", action.hint), width as usize),
            theme::muted(),
        ));
    }
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
            lines.push(muted(&format!("house rules file is unreadable: {path}")));
        }
        TuneHouseRules::Empty => {
            lines.push(muted(
                "no house rules set — choose `edit house rules` above to add one",
            ));
        }
    }
}

fn house_rule_line_limit(area: Rect) -> usize {
    (area.height as usize).saturating_sub(10).max(4)
}

pub(crate) fn prompts_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let model = prompts_model(app);
    lines.push(blank());
    append_prompts_header(&mut lines, &model.module, area.width);
    append_prompt_rows(&mut lines, &model.rows, area);
    lines.push(blank());
    lines.push(keybind_hint_line(&[
        ("↑/↓/j/k", "row"),
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

fn append_prompts_header(lines: &mut Vec<Line<'static>>, module: &str, width: u16) {
    lines.push(divider("PROMPTS", width));
    lines.push(detail("module", module));
    lines.push(blank());
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(
            table_text(&["verb", "override", "override path"], &[12, 10, 28]),
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
        fit(
            &format!(
                "{marker} {}",
                table_text(
                    &[row.verb, row.source, &row.path],
                    &[12, 10, value_width(area, 28)],
                )
            ),
            area.width as usize,
        ),
        style,
    )
}
