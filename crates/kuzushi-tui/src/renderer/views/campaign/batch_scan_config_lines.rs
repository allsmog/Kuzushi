use super::*;
use crate::app::{BatchScanConfig, BatchScanConfigRow};
use crate::ui_view_models::study_config::{study_detail_lines, study_row_value};

pub(super) fn append_study_engines(lines: &mut Vec<Line<'static>>, app: &ShellApp, area: Rect) {
    use crate::ui_view_models::study_engines::{engine_detail, engine_line, engine_rows};
    lines.push(divider("CHOOSE DISCOVERY ENGINES", area.width));
    let selected = app.study_engine_picker().map_or(0, |picker| picker.cursor);
    lines.extend(
        engine_rows(app).iter().enumerate().map(|(index, row)| {
            Line::styled(engine_line(row, index == selected), theme::primary())
        }),
    );
    lines.extend(
        engine_detail(app, area.width as usize)
            .into_iter()
            .map(|line| Line::styled(line, theme::primary())),
    );
    lines.push(Line::styled(
        crate::ui_view_models::study_engines::engine_apply_controls(app),
        theme::muted(),
    ));
}

pub(super) fn append_study_context(lines: &mut Vec<Line<'static>>, app: &ShellApp, area: Rect) {
    use crate::ui_view_models::study_context::{context_catalog, context_detail_lines};
    if app
        .study_context_picker()
        .is_some_and(|picker| picker.diagram_visible)
    {
        lines.extend(
            crate::ui_view_models::study_context::diagram::diagram_plain_lines(
                app,
                area.width as usize,
            )
            .into_iter()
            .map(|line| Line::styled(line, theme::primary())),
        );
        return;
    }
    lines.push(divider("CHOOSE STUDY CONTEXT", area.width));
    lines.extend(
        context_catalog(app)
            .rows
            .into_iter()
            .map(|row| Line::styled(row.label, theme::heading())),
    );
    lines.extend(
        context_detail_lines(app, area.width as usize)
            .into_iter()
            .map(|line| Line::styled(line, theme::primary())),
    );
}

/// Exhaustive plain projection uses the same rows and explanations as the TUI.
pub(super) fn append_batch_scan_config(
    lines: &mut Vec<Line<'static>>,
    config: &BatchScanConfig,
    area: Rect,
) {
    lines.push(divider("PLAN A STUDY", area.width));
    let mut projection = config.clone();
    for (index, row) in BatchScanConfigRow::ALL.iter().enumerate() {
        projection.cursor = index;
        let title = format!("{}: {}", row.label(), study_row_value(config, *row));
        lines.extend(
            wrap_text(&title, area.width as usize)
                .into_iter()
                .map(|line| Line::styled(line, theme::heading())),
        );
        lines.extend(
            study_detail_lines(&projection, area.width as usize)
                .into_iter()
                .map(|line| Line::styled(line, theme::primary())),
        );
        lines.push(blank());
        projection.notice = None;
    }
}
