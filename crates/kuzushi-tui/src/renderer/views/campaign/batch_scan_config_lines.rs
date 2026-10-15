use super::*;
use crate::app::{BatchScanConfig, BatchScanConfigRow};
use crate::ui_view_models::study_config::{
    study_allowance_summary, study_detail_lines, study_row_value, study_surface_title,
};

pub(super) fn append_scope_context(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    area: Rect,
) -> bool {
    let Some(config) = app.scope_context_config() else {
        return false;
    };
    lines.push(divider("SCOPE CONTEXT", area.width));
    lines.extend(
        crate::ui_view_models::scope_context::rows(config)
            .into_iter()
            .map(Line::from),
    );
    lines.extend(
        crate::ui_view_models::scope_context::detail(config, area.width as usize)
            .into_iter()
            .map(Line::from),
    );
    lines.extend(
        crate::ui_view_models::scope_context::controls(area.width)
            .into_iter()
            .map(Line::from),
    );
    true
}

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
    if append_context_subview(lines, app, area) {
        return;
    }
    lines.push(divider(
        crate::ui_view_models::study_context::context_header_title(app).trim(),
        area.width,
    ));
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
    if let Some(controls) = app.study_context_picker().and_then(|picker| {
        crate::ui_view_models::study_context::context_text_controls(picker.text_view, area.width)
    }) {
        lines.push(Line::styled(controls, theme::muted()));
    }
}

fn append_context_subview(lines: &mut Vec<Line<'static>>, app: &ShellApp, area: Rect) -> bool {
    if let Some(comparison) = app
        .study_context_picker()
        .and_then(|picker| picker.comparison.as_ref())
    {
        lines.extend(
            crate::ui_view_models::study_context::comparison_lines(comparison, area.width as usize)
                .into_iter()
                .map(Line::from),
        );
        return true;
    }
    if app
        .study_context_picker()
        .is_some_and(|picker| picker.actions_selected.is_some())
    {
        lines.extend(
            crate::ui_view_models::study_context::context_action_lines(app)
                .into_iter()
                .map(|line| Line::styled(line, theme::primary())),
        );
        return true;
    }
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
        return true;
    }
    false
}

/// Exhaustive plain projection uses the same rows and explanations as the TUI.
pub(super) fn append_batch_scan_config(
    lines: &mut Vec<Line<'static>>,
    config: &BatchScanConfig,
    area: Rect,
) {
    if config.detail_reader_scroll.is_some() {
        append_study_reader(lines, config, area);
        return;
    }
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
        append_study_row_details(lines, &projection, area.width as usize);
        lines.push(blank());
        projection.notice = None;
    }
}

fn append_study_row_details(
    lines: &mut Vec<Line<'static>>,
    config: &BatchScanConfig,
    width: usize,
) {
    if config.selected_row() != BatchScanConfigRow::Context {
        lines.extend(
            study_detail_lines(config, width)
                .into_iter()
                .map(Line::from),
        );
        return;
    }
    let mut projection = config.clone();
    projection.source_view.selected = crate::app::StudySourceView::Overview;
    for _ in 0..4 {
        lines.extend(
            study_detail_lines(&projection, width)
                .into_iter()
                .map(Line::from),
        );
        projection.source_view.selected = projection.source_view.selected.next(false);
    }
}

fn append_study_reader(lines: &mut Vec<Line<'static>>, config: &BatchScanConfig, area: Rect) {
    lines.push(divider(study_surface_title(config), area.width));
    lines.push(Line::from(study_allowance_summary(
        config,
        area.width as usize,
    )));
    lines.extend(
        study_detail_lines(config, area.width as usize)
            .into_iter()
            .map(Line::from),
    );
}
