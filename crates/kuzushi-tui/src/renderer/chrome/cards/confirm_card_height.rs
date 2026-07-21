use super::*;
use crate::ui_view_models::{confirm_card_model, ConfirmCardModel};

const CONFIRM_MIN_ROWS: usize = 3;
const CONFIRM_FULL_IDENTITY_ROWS: usize = 4;

pub(crate) fn confirm_card_height(app: &ShellApp, area: Rect) -> u16 {
    if area.height < 6 {
        return 0;
    }
    let Some(confirm) = confirm_card_model(app) else {
        return 0;
    };
    confirm_card_rows(
        &confirm,
        area.width as usize,
        area.height.saturating_sub(8) as usize,
    )
    .len() as u16
}

pub(crate) fn render_confirm_card(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    let Some(confirm) = confirm_card_model(app) else {
        return;
    };
    render_lines(
        frame,
        area,
        confirm_card_rows(&confirm, area.width as usize, area.height as usize),
    );
}

fn confirm_card_rows(
    confirm: &ConfirmCardModel,
    width: usize,
    max_rows: usize,
) -> Vec<Line<'static>> {
    if max_rows < CONFIRM_MIN_ROWS || width == 0 {
        return Vec::new();
    }
    let mut rows = vec![confirm_header_line(confirm, width)];
    rows.extend(confirm_identity_rows(confirm, width, max_rows));
    let core_rows = rows.len() + 1;
    let optional_budget = max_rows.saturating_sub(core_rows);
    rows.extend(
        confirm_optional_rows(confirm, width)
            .into_iter()
            .take(optional_budget),
    );
    rows.push(confirm_action_line(confirm, width));
    rows
}

fn confirm_identity_rows(
    confirm: &ConfirmCardModel,
    width: usize,
    max_rows: usize,
) -> Vec<Line<'static>> {
    if max_rows >= CONFIRM_FULL_IDENTITY_ROWS {
        return vec![
            confirm_field_line("tool", &confirm.tool, width, theme::primary()),
            confirm_field_line("target", &confirm.target, width, theme::primary()),
        ];
    }
    vec![confirm_compact_identity_line(confirm, width)]
}

fn confirm_compact_identity_line(confirm: &ConfirmCardModel, width: usize) -> Line<'static> {
    if width < 5 {
        return Line::from(Span::styled(
            fit(&format!("{} {}", confirm.tool, confirm.target), width),
            theme::primary(),
        ));
    }
    let (tool_label, target_label, separator) = if width >= 32 {
        ("tool ", "target ", " · ")
    } else {
        ("t:", "@:", " ")
    };
    let fixed = display_width(tool_label) + display_width(target_label) + display_width(separator);
    let value_width = width.saturating_sub(fixed);
    let tool_width = value_width / 2;
    let target_width = value_width.saturating_sub(tool_width);
    Line::from(vec![
        Span::styled(tool_label, theme::muted()),
        Span::styled(fit(&confirm.tool, tool_width), theme::primary()),
        Span::styled(separator, theme::subtle()),
        Span::styled(target_label, theme::muted()),
        Span::styled(fit(&confirm.target, target_width), theme::primary()),
    ])
}

fn confirm_optional_rows(confirm: &ConfirmCardModel, width: usize) -> Vec<Line<'static>> {
    [
        ("actor", confirm.actor.as_deref(), theme::primary()),
        ("rationale", confirm.rationale.as_deref(), theme::primary()),
        ("allowlist", confirm.allowlist.as_deref(), theme::muted()),
    ]
    .into_iter()
    .filter_map(|(label, value, style)| {
        value.map(|value| confirm_field_line(label, value, width, style))
    })
    .collect()
}

fn confirm_header_line(confirm: &ConfirmCardModel, width: usize) -> Line<'static> {
    let style = confirm_header_style(confirm);
    fitted_spans(
        format!(" {} ", confirm.header_glyph),
        style,
        confirm.header_label,
        style,
        width,
    )
}

fn confirm_header_style(confirm: &ConfirmCardModel) -> Style {
    if confirm.header_danger {
        theme::danger()
    } else {
        theme::warn()
    }
}

fn confirm_field_line(label: &str, value: &str, width: usize, value_style: Style) -> Line<'static> {
    let prefix = confirm_field_prefix(label, width);
    fitted_spans(prefix, theme::muted(), value, value_style, width)
}

fn confirm_field_prefix(label: &str, width: usize) -> String {
    let full = format!("  {label:<10}");
    if width >= display_width(&full) + 4 {
        full
    } else {
        format!("{label} ")
    }
}

fn fitted_spans(
    prefix: String,
    prefix_style: Style,
    value: &str,
    value_style: Style,
    width: usize,
) -> Line<'static> {
    let prefix = fit(&prefix, width);
    let value_width = width.saturating_sub(display_width(&prefix));
    Line::from(vec![
        Span::styled(prefix, prefix_style),
        Span::styled(fit(value, value_width), value_style),
    ])
}

fn confirm_action_line(confirm: &ConfirmCardModel, width: usize) -> Line<'static> {
    if !confirm.allows_decision {
        return confirm_field_line(
            "rule",
            "destructive verb · always refused (no override)",
            width,
            theme::danger(),
        );
    }
    let choices = decision_choices(confirm);
    if width >= full_decision_width(&choices) {
        return full_decision_line(choices);
    }
    let allow_key = if confirm.allows_remembered_yes {
        "y/Y"
    } else {
        "y"
    };
    let allow_label = if confirm.allows_remembered_yes {
        "allow/save"
    } else {
        "allow"
    };
    decision_line(allow_key, allow_label, "n/Esc/N", "deny/ban", width)
}

fn decision_choices(confirm: &ConfirmCardModel) -> Vec<(&'static str, &'static str, Style)> {
    let mut choices = vec![("y", "allow once", theme::success())];
    if confirm.allows_remembered_yes {
        choices.push(("Y", "allow + remember", theme::success()));
    }
    choices.extend([
        ("n/Esc", "deny once", theme::danger()),
        ("N", "deny + add to denylist", theme::danger()),
    ]);
    choices
}

fn full_decision_width(choices: &[(&str, &str, Style)]) -> usize {
    2 + choices
        .iter()
        .map(|(key, label, _)| display_width(key) + 1 + display_width(label))
        .sum::<usize>()
        + choices.len().saturating_sub(1) * 3
}

fn full_decision_line(choices: Vec<(&'static str, &'static str, Style)>) -> Line<'static> {
    let mut spans = vec![Span::raw("  ")];
    for (index, (key, label, style)) in choices.into_iter().enumerate() {
        if index > 0 {
            spans.push(Span::raw("   "));
        }
        spans.push(Span::styled(key, style));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(label, theme::muted()));
    }
    Line::from(spans)
}

fn decision_line(
    allow_key: &str,
    allow_label: &str,
    deny_key: &str,
    deny_label: &str,
    width: usize,
) -> Line<'static> {
    let indent = usize::from(width >= 24) * 2;
    let fixed = indent + display_width(allow_key) + display_width(deny_key) + 4;
    if width < fixed {
        return decision_key_line(allow_key, deny_key, width);
    }
    let label_budget = width.saturating_sub(fixed);
    let allow_budget = label_budget / 2;
    let deny_budget = label_budget.saturating_sub(allow_budget);
    Line::from(vec![
        Span::raw(" ".repeat(indent)),
        Span::styled(allow_key.to_string(), theme::success()),
        Span::raw(" "),
        Span::styled(
            choice_label(allow_label, "yes", allow_budget),
            theme::muted(),
        ),
        Span::raw("  "),
        Span::styled(deny_key.to_string(), theme::danger()),
        Span::raw(" "),
        Span::styled(choice_label(deny_label, "no", deny_budget), theme::muted()),
    ])
}

fn decision_key_line(allow_key: &str, deny_key: &str, width: usize) -> Line<'static> {
    let separator = usize::from(width >= 3);
    let key_width = width.saturating_sub(separator);
    let allow_width = key_width / 2;
    let deny_width = key_width.saturating_sub(allow_width);
    Line::from(vec![
        Span::styled(fit(allow_key, allow_width), theme::success()),
        Span::raw(" ".repeat(separator)),
        Span::styled(fit(deny_key, deny_width), theme::danger()),
    ])
}

fn choice_label(full: &str, compact: &str, width: usize) -> String {
    if display_width(full) <= width {
        full.to_string()
    } else {
        fit(compact, width)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constrained_projection_pins_identity_and_decision_rows() {
        let confirm = long_confirm();
        let rows = confirm_card_rows(&confirm, 22, CONFIRM_FULL_IDENTITY_ROWS);
        let text = row_texts(&rows);

        assert_eq!(rows.len(), CONFIRM_FULL_IDENTITY_ROWS);
        assert!(text[0].contains("network"), "{text:?}");
        assert!(text[1].contains("tool"), "{text:?}");
        assert!(text[1].contains("scanner"), "{text:?}");
        assert!(text[2].contains("target"), "{text:?}");
        assert!(text[2].contains("https"), "{text:?}");
        assert!(text[3].contains("y/Y"), "{text:?}");
        assert!(text[3].contains("n/Esc/N"), "{text:?}");
        assert!(
            !text.iter().any(|row| row.contains("rationale")),
            "{text:?}"
        );
        assert_rows_fit(&rows, 22);
    }

    #[test]
    fn three_row_projection_keeps_both_identities_and_actions() {
        let rows = confirm_card_rows(&long_confirm(), 22, CONFIRM_MIN_ROWS);
        let text = row_texts(&rows);

        assert_eq!(rows.len(), CONFIRM_MIN_ROWS);
        assert!(text[1].contains("sca"), "{text:?}");
        assert!(text[1].contains("http"), "{text:?}");
        assert!(text[2].contains("y/Y"), "{text:?}");
        assert!(text[2].contains("n/Esc/N"), "{text:?}");
        assert_rows_fit(&rows, 22);
    }

    #[test]
    fn minimum_projection_is_width_safe() {
        let confirm = long_confirm();
        for width in 1..=40 {
            assert_rows_fit(&confirm_card_rows(&confirm, width, CONFIRM_MIN_ROWS), width);
        }
    }

    #[test]
    fn decision_keys_keep_success_and_danger_semantics() {
        let row = confirm_action_line(&long_confirm(), 28);
        let allow = row.spans.iter().find(|span| span.content == "y/Y").unwrap();
        let deny = row
            .spans
            .iter()
            .find(|span| span.content == "n/Esc/N")
            .unwrap();

        assert_eq!(allow.style, theme::success());
        assert_eq!(deny.style, theme::danger());
    }

    fn long_confirm() -> ConfirmCardModel {
        ConfirmCardModel {
            header_glyph: "⚠",
            header_label: "network egress confirmation",
            header_danger: false,
            tool: "scanner:execute-with-options".to_string(),
            target: "https://example.test/a/very/long/path".to_string(),
            actor: Some("attacker".to_string()),
            rationale: Some("long rationale".to_string()),
            allowlist: Some("example.test".to_string()),
            allows_decision: true,
            allows_remembered_yes: true,
        }
    }

    fn row_texts(rows: &[Line<'static>]) -> Vec<String> {
        rows.iter().map(row_text).collect()
    }

    fn row_text(row: &Line<'static>) -> String {
        row.spans.iter().map(|span| span.content.as_ref()).collect()
    }

    fn assert_rows_fit(rows: &[Line<'static>], width: usize) {
        for row in rows {
            assert!(display_width(&row_text(row)) <= width, "{row:?}");
        }
    }
}
