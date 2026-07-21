use super::*;
use crate::ui_view_models::{
    plan_card_model, threat_patch_card_model, throttle_banner_model, ThreatPatchCardModel,
};

const THREAT_PATCH_CORE_ROWS: usize = 5;
const MIN_THROTTLE_MESSAGE_WIDTH: usize = 8;
const MIN_THROTTLE_SOURCE_WIDTH: usize = 4;

pub(crate) fn render_threat_patch_card(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    let Some(patch) = threat_patch_card_model(app) else {
        return;
    };
    render_lines(
        frame,
        area,
        threat_patch_rows(&patch, area.width as usize, area.height as usize),
    );
}

pub(crate) fn threat_patch_card_height(app: &ShellApp, area: Rect) -> u16 {
    if area.height < 6 {
        return 0;
    }
    let Some(patch) = threat_patch_card_model(app) else {
        return 0;
    };
    threat_patch_rows(
        &patch,
        area.width as usize,
        area.height.saturating_sub(4) as usize,
    )
    .len() as u16
}

fn threat_patch_rows(
    patch: &ThreatPatchCardModel,
    width: usize,
    max_rows: usize,
) -> Vec<Line<'static>> {
    if max_rows < THREAT_PATCH_CORE_ROWS || width == 0 {
        return Vec::new();
    }
    let mut rows = vec![
        Line::from(Span::styled(fit("◆ THREAT PATCH", width), theme::accent())),
        threat_field_line("goal", &patch.goal, width, theme::primary()),
        threat_field_line(
            "patch",
            &format!("{} top-level key(s)", patch.top_level_keys),
            width,
            theme::success(),
        ),
    ];
    let optional_budget = max_rows.saturating_sub(4);
    rows.extend(threat_optional_rows(patch, width, optional_budget));
    rows.push(threat_patch_action_line(width));
    rows
}

fn threat_optional_rows(
    patch: &ThreatPatchCardModel,
    width: usize,
    budget: usize,
) -> Vec<Line<'static>> {
    if budget == 0 {
        return Vec::new();
    }
    let summary = threat_field_line("summary", &patch.summary, width, theme::primary());
    if patch.unsupported.is_empty() {
        return vec![summary];
    }
    threat_warning_rows(patch, summary, width, budget)
}

fn threat_warning_rows(
    patch: &ThreatPatchCardModel,
    summary: Line<'static>,
    width: usize,
    budget: usize,
) -> Vec<Line<'static>> {
    if budget == 1 {
        return vec![threat_omitted_warnings_line(patch.unsupported.len(), width)];
    }
    let shown = patch.unsupported.len().min(budget.saturating_sub(2));
    let omitted = patch.unsupported.len().saturating_sub(shown);
    let mut rows = vec![summary];
    rows.extend(
        patch
            .unsupported
            .iter()
            .take(shown)
            .map(|note| threat_field_line("unsupported", note, width, theme::warn())),
    );
    if omitted > 0 {
        rows.push(threat_omitted_warnings_line(omitted, width));
    }
    rows
}

fn threat_omitted_warnings_line(omitted: usize, width: usize) -> Line<'static> {
    threat_field_line(
        "unsupported",
        &format!("+{omitted} more"),
        width,
        theme::warn(),
    )
}

fn threat_field_line(label: &str, value: &str, width: usize, value_style: Style) -> Line<'static> {
    let full_prefix = format!("  {label:<12}");
    let prefix = if width >= display_width(&full_prefix) + 8 {
        full_prefix
    } else {
        format!("{label} ")
    };
    let prefix = fit(&prefix, width);
    let value_width = width.saturating_sub(display_width(&prefix));
    Line::from(vec![
        Span::styled(prefix, theme::muted()),
        Span::styled(fit(value, value_width), value_style),
    ])
}

fn threat_patch_action_line(width: usize) -> Line<'static> {
    let (apply, reject, separator) = if width >= 32 {
        ("/threats apply", "/threats reject", "   ")
    } else {
        ("apply", "reject", " ")
    };
    let content_width = width.saturating_sub(display_width(separator));
    let apply_width = content_width / 2;
    let reject_width = content_width.saturating_sub(apply_width);
    Line::from(vec![
        Span::styled(fit(apply, apply_width), theme::success()),
        Span::raw(separator),
        Span::styled(fit(reject, reject_width), theme::danger()),
    ])
}

pub(crate) fn plan_card_height(app: &ShellApp, area: Rect) -> u16 {
    if area.height < 6 {
        return 0;
    }
    let Some(plan) = plan_card_model(app) else {
        return 0;
    };
    let body = (plan.changes.len() + plan.unsupported.len()) as u16;
    let height = 3 + body;
    height.min(area.height.saturating_sub(4))
}

pub(crate) fn render_throttle_banner(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    let Some(throttle) = throttle_banner_model(app) else {
        return;
    };
    frame.render_widget(
        Paragraph::new(throttle_banner_line(
            &throttle.source,
            &throttle.message,
            area.width as usize,
        )),
        area,
    );
}

fn throttle_banner_line(source: &str, message: &str, width: usize) -> Line<'static> {
    let prefix = throttle_prefix(width);
    let prefix = fit(prefix, width);
    let payload_width = width.saturating_sub(display_width(&prefix));
    if !throttle_can_show_source(source, message, payload_width) {
        return Line::from(vec![
            Span::styled(prefix, theme::warn()),
            Span::styled(fit(message, payload_width), theme::muted()),
        ]);
    }
    throttle_source_message_line(prefix, source, message, payload_width)
}

fn throttle_prefix(width: usize) -> &'static str {
    if width >= 24 {
        "  RATE LIMIT  "
    } else {
        " RATE "
    }
}

fn throttle_can_show_source(source: &str, message: &str, payload_width: usize) -> bool {
    display_width(source.trim()) > 0
        && display_width(message.trim()) > 0
        && payload_width
            >= MIN_THROTTLE_SOURCE_WIDTH + display_width(" · ") + MIN_THROTTLE_MESSAGE_WIDTH
}

fn throttle_source_message_line(
    prefix: String,
    source: &str,
    message: &str,
    payload_width: usize,
) -> Line<'static> {
    let separator = " · ";
    let source_budget =
        payload_width.saturating_sub(display_width(separator) + MIN_THROTTLE_MESSAGE_WIDTH);
    let source = fit(source, source_budget);
    let message_width = payload_width
        .saturating_sub(display_width(&source))
        .saturating_sub(display_width(separator));
    Line::from(vec![
        Span::styled(prefix, theme::warn()),
        Span::styled(source, theme::primary()),
        Span::styled(separator, theme::subtle()),
        Span::styled(fit(message, message_width), theme::muted()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constrained_threat_projection_pins_context_and_actions() {
        let patch = long_patch();
        let rows = threat_patch_rows(&patch, 18, THREAT_PATCH_CORE_ROWS);
        let text = row_texts(&rows);

        assert_eq!(rows.len(), THREAT_PATCH_CORE_ROWS);
        assert!(text[0].contains("THREAT PATCH"), "{text:?}");
        assert!(text[1].contains("goal"), "{text:?}");
        assert!(text[1].contains("regen"), "{text:?}");
        assert!(text[2].contains("patch"), "{text:?}");
        assert!(text[3].contains("unsupported"), "{text:?}");
        assert!(text[4].contains("apply"), "{text:?}");
        assert!(text[4].contains("reject"), "{text:?}");
        assert_rows_fit(&rows, 18);
    }

    #[test]
    fn constrained_threat_projection_discloses_omitted_warnings_before_apply() {
        let mut patch = long_patch();
        patch
            .unsupported
            .push("operator review is required".to_string());
        let rows = threat_patch_rows(&patch, 28, THREAT_PATCH_CORE_ROWS + 2);
        let text = row_texts(&rows);

        assert!(
            text.iter().any(|row| row.contains("unsupported")),
            "{text:?}"
        );
        assert!(text.iter().any(|row| row.contains("+1 more")), "{text:?}");
        assert!(
            text.last().is_some_and(|row| row.contains("apply")),
            "{text:?}"
        );
    }

    #[test]
    fn threat_height_and_projection_use_the_same_rows() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_pending_threat_patch(crate::app::ThreatPatch {
            goal: "regen".to_string(),
            summary: "add trust zone".to_string(),
            patch: serde_json::json!({"trustZones": {}}),
            unsupported: vec!["manual review".to_string()],
        });
        let area = Rect::new(0, 0, 18, 9);

        assert_eq!(threat_patch_card_height(&app, area), 5);
    }

    #[test]
    fn narrow_throttle_reserves_message_without_dangling_separator() {
        let row = throttle_banner_line(
            "extremely-long-upstream-source",
            "retry in thirty seconds",
            18,
        );
        let text = row_text(&row);

        assert!(text.contains("retry"), "{text:?}");
        assert!(!text.contains('·'), "{text:?}");
        assert!(display_width(&text) <= 18, "{text:?}");
    }

    #[test]
    fn minimum_threat_and_throttle_rows_are_width_safe() {
        let patch = long_patch();
        for width in 1..=40 {
            assert_rows_fit(
                &threat_patch_rows(&patch, width, THREAT_PATCH_CORE_ROWS),
                width,
            );
            let throttle = throttle_banner_line("long-source", "retry soon", width);
            assert!(display_width(&row_text(&throttle)) <= width, "{throttle:?}");
        }
    }

    fn long_patch() -> ThreatPatchCardModel {
        ThreatPatchCardModel {
            goal: "regenerate the complete threat model".to_string(),
            summary: "add a deliberately long trust boundary summary".to_string(),
            top_level_keys: 3,
            unsupported: vec!["manual review is required".to_string()],
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
