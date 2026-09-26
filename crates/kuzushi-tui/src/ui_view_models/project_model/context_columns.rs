//! One width-aware column projection for the project-context receipt.
//!
//! `ProjectModelRow` already carries `state` and `action`; before this
//! projection existed the Ratatui pane dropped both and plain output printed
//! only `state`, so the two surfaces disagreed about the same row. Every
//! consumer now asks for the same table and renders the same segments, so a
//! wide terminal shows the state and the next action the model already knows.

use super::{ProjectModel, ProjectModelOrigin, ProjectModelRow};
use crate::renderer::shared::text::{display_width, fit, wrap_text};

/// The one-column rule drawn between cells. Plain output folds it (and the
/// action marker) to ASCII in `sanitize_for_plain_output`, so both surfaces
/// keep the same column positions without a second rule constant here.
pub(crate) const CONTEXT_COLUMN_RULE: &str = "│";

/// Narrowest summary worth keeping. Below it the state and action columns
/// are costing more than they explain, so the row collapses back to the
/// historical `glyph section  summary` shape rather than shredding the
/// summary into fragments.
const MIN_SUMMARY_COLUMNS: usize = 32;
/// Section width in the collapsed row, matching the historical `{:<14}`.
const COLLAPSED_SECTION_COLUMNS: usize = 14;
/// `glyph`, its trailing space, and the single space before the summary.
const COLLAPSED_FIXED_COLUMNS: usize = 3;
/// `glyph` + space, two ` │ ` rules, and the ` │ ▸ ` action rule.
const WIDE_FIXED_COLUMNS: usize = 13;
const ACTION_MARKER: &str = "▸ ";
/// A wrapped summary keeps at most this many lines; the last one is fitted
/// with an ellipsis so one verbose row cannot crowd out its siblings.
const MAX_SUMMARY_LINES: usize = 3;

/// Which column a rendered segment belongs to, so each surface can style it
/// without re-deriving the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectContextCell {
    Origin,
    Section,
    Rule,
    State,
    Summary,
    Action,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectContextSegment {
    pub(crate) cell: ProjectContextCell,
    pub(crate) text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectContextRow {
    pub(crate) origin: ProjectModelOrigin,
    pub(crate) section: String,
    pub(crate) state: String,
    pub(crate) summary: String,
    /// The summary word-wrapped to the summary column, each line padded to it.
    /// Surfaces with vertical room render these instead of the one fitted
    /// `summary` line, so the text is not cut short by an ellipsis.
    pub(crate) summary_lines: Vec<String>,
    /// `None` in the collapsed layout, where there is no room for the column.
    pub(crate) action: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectContextTable {
    pub(crate) section_w: usize,
    pub(crate) state_w: usize,
    pub(crate) summary_w: usize,
    /// `0` when the rows collapsed to the two-column shape, which is also
    /// the signal that no row carries a state or action cell.
    pub(crate) action_w: usize,
    pub(crate) rows: Vec<ProjectContextRow>,
}

impl ProjectContextRow {
    /// The ordered, already-fitted segments of this row.
    pub(crate) fn segments(&self) -> Vec<ProjectContextSegment> {
        self.segments_with_summary(&self.summary)
    }

    /// The row with its summary wrapped: the first line carries every cell,
    /// continuation lines carry only the rest of the summary, aligned under it.
    pub(crate) fn wrapped_segments(&self) -> Vec<Vec<ProjectContextSegment>> {
        let (first, rest) = self
            .summary_lines
            .split_first()
            .map_or((self.summary.as_str(), &[][..]), |(first, rest)| {
                (first.as_str(), rest)
            });
        std::iter::once(self.segments_with_summary(first))
            .chain(rest.iter().map(|chunk| self.continuation_segments(chunk)))
            .collect()
    }

    fn segments_with_summary(&self, summary: &str) -> Vec<ProjectContextSegment> {
        let mut segments = vec![
            segment(
                ProjectContextCell::Origin,
                format!("{} ", self.origin.glyph()),
            ),
            segment(ProjectContextCell::Section, self.section.clone()),
        ];
        let Some(action) = self.action.as_deref() else {
            segments.push(segment(ProjectContextCell::Rule, " ".to_string()));
            segments.push(segment(ProjectContextCell::Summary, summary.to_string()));
            return segments;
        };
        segments.extend([
            rule_segment(""),
            segment(ProjectContextCell::State, self.state.clone()),
            rule_segment(""),
            segment(ProjectContextCell::Summary, summary.to_string()),
            rule_segment(ACTION_MARKER),
            segment(ProjectContextCell::Action, action.to_string()),
        ]);
        segments
    }

    fn continuation_segments(&self, chunk: &str) -> Vec<ProjectContextSegment> {
        let origin = blank_like(&format!("{} ", self.origin.glyph()));
        let mut segments = vec![
            segment(ProjectContextCell::Origin, origin),
            segment(ProjectContextCell::Section, blank_like(&self.section)),
        ];
        let Some(action) = self.action.as_deref() else {
            segments.push(segment(ProjectContextCell::Rule, " ".to_string()));
            segments.push(segment(ProjectContextCell::Summary, chunk.to_string()));
            return segments;
        };
        segments.extend([
            rule_segment(""),
            segment(ProjectContextCell::State, blank_like(&self.state)),
            rule_segment(""),
            segment(ProjectContextCell::Summary, chunk.to_string()),
            rule_segment(&blank_like(ACTION_MARKER)),
            segment(ProjectContextCell::Action, blank_like(action)),
        ]);
        segments
    }

    /// The row as one line of text, for line-based surfaces.
    pub(crate) fn text(&self) -> String {
        self.segments()
            .into_iter()
            .map(|segment| segment.text)
            .collect::<String>()
            .trim_end()
            .to_string()
    }
}

/// Project `model`'s rows into aligned columns for `usable_width` columns of
/// content (the pane width minus its border).
pub(crate) fn project_context_columns(
    model: &ProjectModel,
    usable_width: usize,
) -> ProjectContextTable {
    let widths = context_column_widths(&model.rows, usable_width);
    let rows = model
        .rows
        .iter()
        .map(|row| context_row(row, widths))
        .collect::<Vec<_>>();
    ProjectContextTable {
        section_w: widths.section,
        state_w: widths.state,
        summary_w: widths.summary,
        action_w: widths.action,
        rows,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ColumnWidths {
    section: usize,
    state: usize,
    summary: usize,
    action: usize,
}

fn context_column_widths(rows: &[ProjectModelRow], usable_width: usize) -> ColumnWidths {
    wide_column_widths(rows, usable_width).unwrap_or_else(|| collapsed_column_widths(usable_width))
}

/// The four-column layout, or `None` when the summary would be squeezed below
/// `MIN_SUMMARY_COLUMNS`. State and action are sized to their widest value so
/// neither is ever truncated into an ellipsis.
fn wide_column_widths(rows: &[ProjectModelRow], usable_width: usize) -> Option<ColumnWidths> {
    let section = widest(rows.iter().map(|row| row.section));
    let state = widest(rows.iter().map(|row| row.state));
    let action = widest(rows.iter().map(|row| row.action));
    let summary = usable_width.saturating_sub(WIDE_FIXED_COLUMNS + section + state + action);
    (summary >= MIN_SUMMARY_COLUMNS).then_some(ColumnWidths {
        section,
        state,
        summary,
        action,
    })
}

fn collapsed_column_widths(usable_width: usize) -> ColumnWidths {
    ColumnWidths {
        section: COLLAPSED_SECTION_COLUMNS,
        state: 0,
        summary: usable_width.saturating_sub(COLLAPSED_SECTION_COLUMNS + COLLAPSED_FIXED_COLUMNS),
        action: 0,
    }
}

fn context_row(row: &ProjectModelRow, widths: ColumnWidths) -> ProjectContextRow {
    ProjectContextRow {
        origin: row.origin,
        section: pad(row.section, widths.section),
        state: pad(row.state, widths.state),
        summary: pad(&row.summary, widths.summary),
        summary_lines: wrapped_summary(&row.summary, widths.summary),
        action: (widths.action > 0).then(|| pad(row.action, widths.action)),
    }
}

fn widest<'a>(values: impl Iterator<Item = &'a str>) -> usize {
    values.map(display_width).max().unwrap_or_default()
}

/// Fit into `width` and right-pad to it, so the following rule lines up.
fn pad(value: &str, width: usize) -> String {
    let fitted = fit(value, width);
    let padding = width.saturating_sub(display_width(&fitted));
    format!("{fitted}{}", " ".repeat(padding))
}

fn wrapped_summary(summary: &str, width: usize) -> Vec<String> {
    let lines = wrap_text(summary, width);
    if lines.len() <= MAX_SUMMARY_LINES {
        return lines.iter().map(|line| pad(line, width)).collect();
    }
    let (kept, overflow) = lines.split_at(MAX_SUMMARY_LINES - 1);
    kept.iter()
        .map(|line| pad(line, width))
        .chain(std::iter::once(pad(&overflow.join(" "), width)))
        .collect()
}

fn blank_like(text: &str) -> String {
    " ".repeat(display_width(text))
}

fn segment(cell: ProjectContextCell, text: String) -> ProjectContextSegment {
    ProjectContextSegment { cell, text }
}

fn rule_segment(trailing: &str) -> ProjectContextSegment {
    segment(
        ProjectContextCell::Rule,
        format!(" {CONTEXT_COLUMN_RULE} {trailing}"),
    )
}

#[cfg(test)]
mod tests;
