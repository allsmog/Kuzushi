use super::*;

pub(super) fn map_text_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let state = app.router.setup().map_run_config();
    let Some(list) = state.text() else {
        return Vec::new();
    };
    let width = area.width as usize;
    let title = format!("SETUP · {}", row_label(list.row).to_uppercase());
    let document = list.row == MapRunConfigRowId::DesignDocs;
    let mut lines = vec![divider(&title, area.width), blank()];
    if let Some(field) = &list.field {
        lines.extend(editing_lines(field, document, area));
    } else {
        lines.extend(entry_list_lines(&list.values, list.cursor, document, area));
    }
    if let Some(error) = state.error() {
        lines.extend(
            wrap_text(&format!("{error}. Your draft is kept."), width)
                .into_iter()
                .map(|line| styled(&line, theme::danger())),
        );
    }
    lines
}

fn editing_lines(
    field: &crate::app::FieldEditor,
    document: bool,
    area: Rect,
) -> Vec<Line<'static>> {
    let hint = if document {
        "Enter saves · Ctrl+O choose a file · Esc cancels this edit"
    } else {
        "Enter adds a line · Ctrl+S saves · Esc cancels this edit"
    };
    let mut lines = wrap_text(hint, area.width as usize)
        .into_iter()
        .map(|line| muted(&line))
        .collect::<Vec<_>>();
    lines.push(blank());
    let height = (area.height as usize)
        .saturating_sub(lines.len() + 5)
        .max(1);
    lines.extend(field_editor_lines(field, area.width as usize, height));
    lines.push(blank());
    lines
}

fn entry_list_lines(
    values: &[String],
    cursor: usize,
    document: bool,
    area: Rect,
) -> Vec<Line<'static>> {
    let width = area.width as usize;
    let hint = if document {
        "Enter edits · a adds a path · f chooses a file · Delete removes · Esc back"
    } else {
        "Enter edits · a adds context · Delete removes · Esc back"
    };
    let mut lines = wrap_text(hint, width)
        .into_iter()
        .map(|line| muted(&line))
        .collect::<Vec<_>>();
    lines.push(blank());
    let visible = (area.height as usize)
        .saturating_sub(lines.len() + 5)
        .max(1);
    let start = cursor
        .saturating_sub(visible / 2)
        .min((values.len() + 1).saturating_sub(visible));
    lines.extend(
        (start..(start + visible).min(values.len() + 1)).map(|index| {
            let label = values
                .get(index)
                .map(|value| format!(" {}. {}", index + 1, value.replace('\n', " ↵ ")))
                .unwrap_or_else(|| " + Add an entry".into());
            selection_band(&label, cursor == index, width)
        }),
    );
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{MapRunConfigRowId, SetupEditor};
    use kuzushi_core::V2Config;

    #[test]
    fn document_editor_shows_full_comma_path_and_local_save_controls() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(crate::app::ShellView::Setup);
        app.router
            .setup_mut()
            .begin_editor(SetupEditor::ThreatModel);
        let state = app.router.setup_mut().map_run_config_mut();
        state.begin_edit(MapRunConfigRowId::DesignDocs, Vec::new());
        state
            .text_mut()
            .unwrap()
            .field
            .as_mut()
            .unwrap()
            .insert("docs/Architecture, v2.md");
        for width in [60, 80, 120] {
            let lines = map_text_lines(&app, Rect::new(0, 0, width, 20));
            let text = lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(text.contains("docs/Architecture, v2.md"));
            assert!(text.contains("Enter saves"));
            assert!(!text.contains("comma or newline separates"));
            assert!(lines.iter().all(|line| line.width() <= width as usize));
        }
    }

    #[test]
    fn full_frame_field_owns_its_hint_and_plain_output_keeps_its_text() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(crate::app::ShellView::Setup);
        app.router
            .setup_mut()
            .begin_editor(SetupEditor::ThreatModel);
        let state = app.router.setup_mut().map_run_config_mut();
        state.begin_edit(MapRunConfigRowId::Context, Vec::new());
        state
            .text_mut()
            .unwrap()
            .field
            .as_mut()
            .unwrap()
            .insert("Architecture, v2\nsecond paragraph");
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(rendered.contains("editing context"));
        assert!(rendered.contains("Architecture, v2"));
        assert!(!rendered.contains("type a command"));
        let plain = crate::renderer::render_plain_app(&app, 80);
        assert!(plain.contains("Architecture, v2"));
        assert!(plain.contains("second paragraph"));
        assert!(plain.contains("Ctrl+S"));
    }
}
