use super::*;
use crate::ui_view_models::{study_config::study_config_area, study_context::comparison};

pub(super) struct NavigationLimits {
    count: usize,
    page: usize,
    max_scroll: usize,
}

pub(super) fn limits(app: &ShellApp, context: &StudyContextComparison) -> NavigationLimits {
    let viewport = app.viewport();
    let layout = comparison::layout(study_config_area(viewport.columns, viewport.rows));
    let page = usize::from(layout.detail.height).max(1);
    NavigationLimits {
        count: comparison::entries(context, context.view).len(),
        page,
        max_scroll: comparison::selected_lines(context, layout.detail.width as usize)
            .len()
            .saturating_sub(page),
    }
}

pub(super) fn update(
    picker: &mut super::super::StudyContextPicker,
    code: KeyCode,
    limits: NavigationLimits,
) {
    if matches!(code, KeyCode::Esc | KeyCode::Char('q')) {
        picker.comparison = None;
        return;
    }
    let comparison = picker.comparison.as_mut().unwrap();
    match code {
        KeyCode::Tab => cycle_view(comparison, 1),
        KeyCode::BackTab => cycle_view(comparison, 3),
        _ => update_cursor(comparison, code, limits),
    }
}

fn cycle_view(comparison: &mut StudyContextComparison, step: usize) {
    comparison.view = ContextComparisonView::ALL[(comparison.view.index() + step) % 4];
}

fn update_cursor(context: &mut StudyContextComparison, code: KeyCode, limits: NavigationLimits) {
    let cursor = &mut context.cursors[context.view.index()];
    let selected = cursor.selected;
    match code {
        KeyCode::Up | KeyCode::Char('k') => cursor.selected = selected.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => {
            cursor.selected = selected
                .saturating_add(1)
                .min(limits.count.saturating_sub(1))
        }
        KeyCode::PageUp => {
            cursor.scroll = cursor
                .scroll
                .min(limits.max_scroll)
                .saturating_sub(limits.page)
        }
        KeyCode::PageDown => {
            cursor.scroll = cursor
                .scroll
                .saturating_add(limits.page)
                .min(limits.max_scroll)
        }
        KeyCode::Home => cursor.scroll = 0,
        KeyCode::End => cursor.scroll = limits.max_scroll,
        _ => {}
    }
    if selected != cursor.selected {
        cursor.scroll = 0;
    }
}
