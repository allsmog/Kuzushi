//! Pinned identity and visible wrapped-line range for the read-only scope document.
use super::{paths, ScopeReviewState};
use crate::app::{selected_scope, ScopeBranch, ScopeTreeRow};
use crate::renderer::shared::text::fit;
use ratatui::layout::Rect;
use unicode_width::UnicodeWidthStr;

pub(crate) fn scope_reader_heading(
    state: &ScopeReviewState,
    total_lines: usize,
    area: Rect,
) -> Option<String> {
    state.detail_reader.open.then(|| {
        let position = line_range(
            state.detail_reader.scroll,
            total_lines,
            area.height as usize,
        );
        reading_heading(&subject(state), &position, area.width as usize)
    })
}

fn reading_heading(subject: &str, position: &str, width: usize) -> String {
    let suffix_width = position.width().saturating_add(3);
    if width <= suffix_width {
        return fit(position, width);
    }
    format!("{} · {position}", fit(subject, width - suffix_width))
}

fn line_range(scroll: usize, total: usize, rows: usize) -> String {
    let count = total.min(rows);
    if count == 0 {
        return format!("0/{total}");
    }
    let offset = scroll.min(total - count);
    format!("{}-{}/{total}", offset + 1, offset + count)
}

fn subject(state: &ScopeReviewState) -> String {
    if let Some(path) = state.selected_file() {
        return format!("File: {}", paths::display_path(&path));
    }
    selected_scope(state).map_or_else(
        || category_subject(state).into(),
        |scope| scope.name.clone(),
    )
}

fn category_subject(state: &ScopeReviewState) -> &'static str {
    match state.selected_row() {
        Some(ScopeTreeRow::Branch(branch)) => branch_subject(&branch),
        Some(ScopeTreeRow::Page { .. }) => "Membership page",
        _ => "Scope details",
    }
}

fn branch_subject(branch: &ScopeBranch) -> &'static str {
    match branch {
        ScopeBranch::Uncovered => "Uncovered files",
        ScopeBranch::Excluded => "Excluded files",
        ScopeBranch::Overlap => "Overlapping files",
        ScopeBranch::Scope(_) => "Boundary unavailable",
    }
}

#[cfg(test)]
mod tests;
