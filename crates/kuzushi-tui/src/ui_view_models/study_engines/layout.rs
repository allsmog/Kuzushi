use super::super::study_config::{study_config_area, study_config_layout, StudyConfigLayout};
use std::ops::Range;

/// A stacked engine list can use half the body when the terminal is tall.
/// Compact layouts retain their existing detail and control space.
pub(crate) fn engine_layout(columns: u16, rows: u16, count: usize) -> StudyConfigLayout {
    let mut layout = study_config_layout(study_config_area(columns, rows));
    if layout.list.x != layout.detail.x {
        return layout;
    }
    let shared_height = layout.list.height.saturating_add(layout.detail.height);
    let list_limit = (shared_height / 2).max(layout.list.height);
    layout.list.height = (count.min(u16::MAX as usize) as u16).min(list_limit);
    layout.detail.y = layout.list.bottom().saturating_add(1);
    layout.detail.height = shared_height.saturating_sub(layout.list.height);
    layout
}

pub(crate) fn engine_window(count: usize, cursor: usize, height: usize) -> Range<usize> {
    let cursor = cursor.min(count.saturating_sub(1));
    let start = cursor.saturating_sub(height.saturating_sub(1));
    start..start.saturating_add(height).min(count)
}

#[cfg(test)]
mod tests;
