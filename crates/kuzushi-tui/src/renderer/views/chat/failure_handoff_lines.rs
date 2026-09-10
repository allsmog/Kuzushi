use super::*;
use crate::ui_view_models::{failure_handoff_model, FailureHandoffModel};

pub(crate) fn failure_handoff_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("FAILURE HANDOFF", area.width));
    let body_w = area.width.saturating_sub(3);

    if let Some(model) = failure_handoff_model(app) {
        append_failure_rows(&mut lines, &model, body_w);
    } else {
        append_failure_empty_state(&mut lines);
    }

    lines.push(blank());
    lines.push(command_list_line(
        &["ask <question>", "runs", "replay <run>", "back"],
        area.width as usize,
    ));
    lines
}

fn append_failure_empty_state(lines: &mut Vec<Line<'static>>) {
    lines.extend(empty_state_panel(
        "no failure handoff loaded",
        &[
            "partial and failed tool runs create bounded handoff context.",
            "the next agent question inherits that context once.",
        ],
        &[
            ("runs", "inspect recent run artifacts"),
            ("activity", "watch current module progress"),
            (
                "ask <question>",
                "next /ask inherits this failure context once",
            ),
        ],
    ));
}

fn append_failure_rows(lines: &mut Vec<Line<'static>>, model: &FailureHandoffModel, body_w: u16) {
    for row in &model.rows {
        append_failure_detail(lines, row.label, &row.value, body_w);
    }
}

fn append_failure_detail(lines: &mut Vec<Line<'static>>, key: &str, value: &str, body_w: u16) {
    lines.extend(detail_wrapped(key, value, body_w));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_handoff_pages_and_leaves_the_tail_in_a_narrow_terminal() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_shell_view(ShellView::FailureHandoff);
        app.set_input_mode(crate::InputMode::Navigate);
        app.set_viewport(crate::TerminalViewport::new(40, 12));
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        let maximum = crate::renderer::run_artifact_max_scroll(&app).unwrap();
        assert!(maximum > 0);
        assert!(app.reduce_key(key(KeyCode::PageDown)).handled);
        assert!(app.router.default_scroll().offset() > 0);
        assert!(app.reduce_key(key(KeyCode::Char('G'))).handled);
        assert!(app.reduce_key(key(KeyCode::Char('k'))).handled);
        assert_eq!(app.router.default_scroll().offset(), maximum - 1);
        assert!(app.reduce_key(key(KeyCode::Char('g'))).handled);
        assert_eq!(app.router.default_scroll().offset(), 0);
    }

    #[test]
    fn failure_detail_wrapping_keeps_every_word_in_all_supported_widths() {
        let value = "Review remaining work and approve a specific allowance revision before another model request. Preserve unresolved reservations; this failure does not establish zero cost.";
        for width in [40_u16, 60, 80, 96, 120, 160] {
            let mut lines = Vec::new();
            append_failure_detail(&mut lines, "recovery", value, width - 3);
            assert!(lines
                .iter()
                .all(|line| line.width() <= usize::from(width - 3)));
            let rendered = lines
                .iter()
                .map(|line| line.spans[1].content.as_ref())
                .collect::<Vec<_>>()
                .join(" ");
            assert_eq!(
                rendered.split_whitespace().collect::<Vec<_>>(),
                value.split_whitespace().collect::<Vec<_>>(),
                "width {width}"
            );
            assert_eq!(
                lines
                    .iter()
                    .filter(|line| line.spans[0].content.contains("recovery"))
                    .count(),
                1
            );
        }
    }
}
