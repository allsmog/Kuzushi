use super::*;

pub(super) fn scope_selection_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let state = app.router.setup().map_run_config();
    let Some(picker) = state.scope() else {
        return Vec::new();
    };
    let width = area.width as usize;
    let mut lines = vec![divider("SETUP · MAP SCOPE", area.width), blank()];
    lines.extend(scope_wrapped(
        "Type to filter · ↑/↓ choose · Enter selects · Esc cancels",
        width,
        theme::subtle(),
    ));
    lines.push(muted("Search:"));
    lines.extend(field_editor_lines(&picker.query, width, 2));
    if let Some(error) = state.error() {
        lines.extend(scope_wrapped(error, width, theme::warn()));
    }
    let choices = picker.filtered();
    lines.push(muted(&format!("{} matching scope choices", choices.len())));
    let visible = (area.height as usize).saturating_sub(lines.len()).max(1);
    let start = picker
        .cursor
        .saturating_sub(visible / 2)
        .min(choices.len().saturating_sub(visible));
    lines.extend(
        choices
            .into_iter()
            .enumerate()
            .skip(start)
            .take(visible)
            .map(|(index, choice)| selection_band(&choice.label, picker.cursor == index, width)),
    );
    lines
}

fn scope_wrapped(text: &str, width: usize, style: ratatui::style::Style) -> Vec<Line<'static>> {
    wrap_text(text, width)
        .into_iter()
        .map(|line| Line::styled(line, style))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::SetupEditor;
    use kuzushi_core::V2Config;

    #[test]
    fn scope_selector_windows_large_lists_and_shows_its_own_input_contract() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(crate::ShellView::Setup);
        app.router
            .setup_mut()
            .begin_editor(SetupEditor::ThreatModel);
        let choices = (0..50)
            .map(|n| (Some(format!("id:scope-{n}")), format!("packages/scope-{n}")))
            .collect();
        app.router
            .setup_mut()
            .map_run_config_mut()
            .begin_scope(choices, Some("id:scope-47"));
        for width in [60, 80, 120] {
            let lines = scope_selection_lines(&app, Rect::new(0, 0, width, 16));
            let text = lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(text.contains("packages/scope-47"));
            assert!(text.contains("Enter selects"));
            assert!(lines.len() <= 16);
            assert!(lines.iter().all(|line| line.width() <= width as usize));
        }
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let frame = format!("{:?}", terminal.backend().buffer());
        assert!(frame.contains("type to filter scopes"));
        assert!(!frame.contains("type a command"));
    }
}
