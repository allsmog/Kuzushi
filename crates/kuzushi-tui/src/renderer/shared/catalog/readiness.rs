use super::*;
use crate::ui_view_models::CatalogModel;

/// Keep a recovery command together when it fits on one row. Short readers
/// may use two rows instead of truncating the remedy behind its state label.
pub(in crate::renderer) fn catalog_readiness_lines(
    model: &CatalogModel,
    width: usize,
) -> Vec<Line<'static>> {
    let Some(action) = model.selected_action.as_ref() else {
        return Vec::new();
    };
    let width = width.max(1);
    let readiness = &action.readiness;
    let combined = format!("{} · {}", readiness.label, readiness.next);
    let text = if display_width(&combined) <= width || display_width(&readiness.next) > width {
        wrap_text(&combined, width)
    } else {
        vec![readiness.label.to_string(), readiness.next.clone()]
    };
    text.into_iter()
        .map(|row| Line::styled(row, theme::muted()))
        .collect()
}
