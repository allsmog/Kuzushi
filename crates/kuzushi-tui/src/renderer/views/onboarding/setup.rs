use super::*;
use crate::app::SetupEditor;
use crate::ui_view_models::{setup_readiness_model, SetupReadinessRow, SetupReadinessTone};

pub(crate) fn setup_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let model = setup_readiness_model(app);
    let width = area.width as usize;
    let mut lines = vec![divider("SETUP · READY THE MAP RUN", area.width)];
    lines.push(muted(&fit(
        "One readiness check. Model and credentials are required only by the selected plan.",
        width,
    )));
    lines.push(blank());
    lines.extend(setup_readiness_lines(
        app,
        &model.rows,
        width,
        area.width < 72,
    ));
    lines.extend(setup_editor_lines(app, width));
    lines.push(blank());
    lines.push(setup_summary_line(&model, width));
    lines
}

fn setup_readiness_lines(
    app: &ShellApp,
    rows: &[SetupReadinessRow],
    width: usize,
    compact: bool,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        lines.push(setup_row_line(
            row,
            index == app.router.setup().cursor(),
            width,
            compact,
        ));
        if !compact && index == app.router.setup().cursor() {
            lines.extend(
                wrap_text(&format!("    {}", row.detail), width)
                    .into_iter()
                    .map(|line| muted(&line)),
            );
        }
    }
    lines
}

fn setup_editor_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    if app.router.setup().editor() != Some(SetupEditor::Budget) {
        return Vec::new();
    }
    let mut lines = vec![blank(), setup_budget_editor_line(app, width)];
    if let Some(error) = app.router.setup().budget_error() {
        lines.push(styled(&fit(&format!(" ! {error}"), width), theme::danger()));
    }
    lines
}

fn setup_summary_line(
    model: &crate::ui_view_models::SetupReadinessModel,
    width: usize,
) -> Line<'static> {
    if model.can_start {
        styled(
            &fit(
                &format!(
                    " READY · {} Map task(s) · s Start Map · Enter edits the selected row",
                    model.selected_tasks
                ),
                width,
            ),
            theme::success(),
        )
    } else {
        styled(
            &fit(
                " BLOCKED · resolve the first highlighted readiness row",
                width,
            ),
            theme::warn(),
        )
    }
}

fn setup_row_line(
    row: &SetupReadinessRow,
    selected: bool,
    width: usize,
    compact: bool,
) -> Line<'static> {
    let glyph = match row.tone {
        SetupReadinessTone::Ready => "✓",
        SetupReadinessTone::Optional => "·",
        SetupReadinessTone::Blocked => "!",
        SetupReadinessTone::Action => " ",
    };
    let body = if compact {
        format!("{glyph} {:<12} {} · {}", row.label, row.status, row.detail)
    } else {
        format!("{glyph} {:<14} {:<16}", row.label, row.status)
    };
    selection_band(&body, selected, width)
}

fn setup_budget_editor_line(app: &ShellApp, width: usize) -> Line<'static> {
    let draft = app.router.setup().budget_draft();
    let value = if draft.is_empty() { "<unset>" } else { draft };
    styled(
        &fit(
            &format!(
                " Budget USD: {value}  · type amount · Enter save · Delete unset · Esc cancel"
            ),
            width,
        ),
        theme::accent(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{V2Config, WorkspaceTarget};

    #[test]
    fn setup_projection_stays_readable_at_compact_and_wide_sizes() {
        let target = tempfile::tempdir().unwrap();
        std::fs::write(
            target.path().join("Cargo.toml"),
            "[package]\nname='fixture'\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.open_setup();

        for area in [Rect::new(0, 0, 40, 12), Rect::new(0, 0, 120, 36)] {
            let text = setup_lines(&app, area)
                .into_iter()
                .map(|line| line.to_string())
                .collect::<Vec<_>>()
                .join("\n");
            assert!(text.contains("SETUP"));
            assert!(text.contains("Map plan"));
            assert!(text.contains("Start Map"));
            assert!(!text.contains("組 map"));
        }
    }

    #[test]
    fn selected_start_action_has_one_cursor_marker() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.open_setup();
        app.router.setup_mut().set_cursor(6);

        let text = setup_lines(&app, Rect::new(0, 0, 60, 20))
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("▸   Start Map"), "{text}");
        assert!(!text.contains("▸ ▸ Start Map"), "{text}");
    }

    #[test]
    fn unselected_start_action_does_not_look_selected() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.open_setup();

        let text = setup_lines(&app, Rect::new(0, 0, 60, 20))
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert_eq!(text.matches('▸').count(), 1, "{text}");
    }
}
