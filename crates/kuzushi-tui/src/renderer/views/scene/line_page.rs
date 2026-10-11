//! Row geometry for the gallery's line pages.
//!
//! A line page projects a model into rows — a dependency, a ranked file, a
//! module's risk. A row whose value is too long for the canvas wraps onto
//! several display lines, so the display lines a page occupies depend on the
//! canvas it was built for while the rows the model holds do not. The
//! position label therefore counts rows: Map's embedded canvas, the
//! full-frame zoom, and a resized terminal all state the same total for the
//! same projection.

use ratatui::prelude::Line;

/// A line page's rows, each carrying the display lines its value wrapped into
/// at the width the page was built for.
#[derive(Debug, Default)]
pub(super) struct LinePageRows {
    rows: Vec<Vec<Line<'static>>>,
}

/// Which way a page key moves a line page's window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PageDirection {
    Up,
    Down,
}

/// The rows a canvas shows, and the label naming them. Measured in rows, not
/// display lines, so the total it states is the projection's own size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LinePageWindow {
    pub(super) lines: Vec<Line<'static>>,
    pub(super) position_label: String,
}

impl LinePageRows {
    /// Rows that each occupy one display line, for a page whose builder fits
    /// every value to the width instead of wrapping it.
    pub(super) fn from_lines(lines: Vec<Line<'static>>) -> Self {
        Self {
            rows: lines.into_iter().map(|line| vec![line]).collect(),
        }
    }

    /// One row per logical document line, each wrapped to `width`. For a page
    /// whose builder states every value as one line and lets the canvas wrap
    /// it, so a value that wraps stays one row at every width.
    pub(super) fn from_document_lines(lines: Vec<Line<'static>>, width: usize) -> Self {
        let width = width.min(u16::MAX as usize) as u16;
        let mut rows = Self::default();
        for line in lines {
            rows.push_wrapped(crate::renderer::shared::text::wrap_document_lines(
                vec![line],
                width,
            ));
        }
        rows
    }

    /// One row, drawn as the display lines its value wrapped into. A value
    /// that wrapped to nothing is no row at all.
    pub(super) fn push_wrapped(&mut self, lines: Vec<Line<'static>>) {
        if !lines.is_empty() {
            self.rows.push(lines);
        }
    }

    /// One row that fits a single display line.
    pub(super) fn push(&mut self, line: Line<'static>) {
        self.rows.push(vec![line]);
    }

    /// The rows the projection holds — the total the position label names.
    pub(super) fn len(&self) -> usize {
        self.rows.len()
    }

    /// Every row's display lines, for the unwindowed and plain projections.
    pub(super) fn into_lines(self) -> Vec<Line<'static>> {
        self.rows.into_iter().flatten().collect()
    }

    /// The window a canvas of `visible` display lines shows at `scroll` rows
    /// in. `None` means the page fits its canvas and states no position.
    pub(super) fn window(&self, visible: u16, scroll: usize) -> Option<LinePageWindow> {
        let capacity = self.window_capacity(visible)?;
        let start = scroll.min(self.last_window_start(capacity));
        let end = self.rows_fitting(start, capacity);
        Some(LinePageWindow {
            // Clipped in the one case where a single row is taller than the
            // canvas: the row is shown and the clip is disclosed, never
            // dropped for a blank canvas.
            lines: self.rows[start..end]
                .iter()
                .flatten()
                .take(capacity.max(1))
                .cloned()
                .collect(),
            position_label: position_label(start, end, self.len()),
        })
    }

    fn display_len(&self) -> usize {
        self.rows.iter().map(|row| row_height(row)).sum()
    }

    /// How far a page key moves the scroll offset so the next window starts
    /// on the row after the current window's last row (`Down`) or ends on the
    /// row before its first row (`Up`): consecutive pages neither skip nor
    /// repeat a row, and an offset past the end pages back from the last
    /// window rather than from the overshoot.
    pub(super) fn page_step(&self, visible: u16, scroll: usize, direction: PageDirection) -> usize {
        let Some(capacity) = self.window_capacity(visible) else {
            return 0;
        };
        let last = self.last_window_start(capacity);
        let start = scroll.min(last);
        match direction {
            PageDirection::Down => self
                .rows_fitting(start, capacity)
                .min(last)
                .saturating_sub(scroll),
            PageDirection::Up => {
                scroll.saturating_sub(self.window_start_ending_at(start, capacity))
            }
        }
    }

    /// The display lines a canvas of `visible` lines gives its rows, or `None`
    /// when the page fits and states no position. Ratatui clips a `Paragraph`
    /// without a word, so an overflowing canvas spends its last display line
    /// stating which rows it is showing.
    fn window_capacity(&self, visible: u16) -> Option<usize> {
        let visible = visible as usize;
        if visible == 0 || self.display_len() <= visible {
            return None;
        }
        Some(visible - 1)
    }

    /// The furthest a canvas of `capacity` display lines scrolls and still
    /// ends on the last row, so scrolling past the end shows the final rows
    /// rather than an empty canvas.
    fn last_window_start(&self, capacity: usize) -> usize {
        self.window_start_ending_at(self.rows.len(), capacity)
    }

    /// The first row of the fullest window of `capacity` display lines whose
    /// last row is the one before `end`. At least one row when `end > 0`.
    fn window_start_ending_at(&self, end: usize, capacity: usize) -> usize {
        let mut start = end;
        let mut used = 0;
        while start > 0 {
            let height = row_height(&self.rows[start - 1]);
            if start < end && used + height > capacity {
                break;
            }
            used += height;
            start -= 1;
        }
        start
    }

    /// The rows a canvas of `capacity` display lines holds from `start`. A row
    /// taller than the whole canvas still counts as shown; the window clips
    /// it rather than leaving the canvas blank.
    fn rows_fitting(&self, start: usize, capacity: usize) -> usize {
        let mut end = start;
        let mut used = 0;
        while end < self.rows.len() {
            let height = row_height(&self.rows[end]);
            if end > start && used + height > capacity {
                break;
            }
            used += height;
            end += 1;
        }
        end
    }
}

fn row_height(row: &[Line<'static>]) -> usize {
    row.len().max(1)
}

fn position_label(start: usize, end: usize, total: usize) -> String {
    if end == start + 1 {
        return format!(" row {}/{total}", start + 1);
    }
    format!(" rows {}-{}/{total}", start + 1, end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_that_fits_its_canvas_states_no_position() {
        assert!(single_line_rows(24).window(24, 0).is_none());
        assert!(single_line_rows(9).window(0, 0).is_none());
    }

    #[test]
    fn an_overflowing_page_reserves_its_last_display_line_for_the_position() {
        let window = single_line_rows(2657).window(20, 0).expect("overflowing");

        assert_eq!(window.position_label, " rows 1-19/2657");
    }

    /// The defect this guards: the total came from the display lines the
    /// canvas wrapped the page into, so one component tree read
    /// `rows 1-10/2731` embedded in Map, `rows 1-25/2732` in the full-frame
    /// zoom, and `rows 1-4/2737` at 80 columns. A row's height is a property
    /// of the canvas; the total is a property of the projection.
    #[test]
    fn the_total_counts_rows_not_the_display_lines_they_wrapped_into() {
        let mut wrapped = LinePageRows::default();
        for _ in 0..40 {
            wrapped.push_wrapped(vec![blank_line(), blank_line(), blank_line()]);
        }

        assert_eq!(wrapped.len(), 40);
        for visible in [6, 12, 25] {
            let window = wrapped.window(visible, 0).expect("overflowing");
            assert!(
                window.position_label.ends_with("/40"),
                "visible={visible} {}",
                window.position_label
            );
        }
    }

    #[test]
    fn a_window_shows_whole_rows_and_never_more_than_its_canvas_holds() {
        let mut rows = LinePageRows::default();
        for _ in 0..10 {
            rows.push_wrapped(vec![blank_line(), blank_line()]);
        }

        let window = rows.window(8, 0).expect("overflowing");

        assert_eq!(window.position_label, " rows 1-3/10");
        assert_eq!(window.lines.len(), 6);
    }

    #[test]
    fn scrolling_past_the_end_lands_on_the_last_rows_not_an_empty_canvas() {
        let window = single_line_rows(2657)
            .window(20, usize::MAX)
            .expect("overflowing");

        assert_eq!(window.position_label, " rows 2639-2657/2657");
    }

    #[test]
    fn a_single_display_line_canvas_spends_it_on_the_position() {
        let window = single_line_rows(40).window(1, 7).expect("overflowing");

        assert_eq!(window.position_label, " row 8/40");
    }

    #[test]
    fn a_row_taller_than_the_canvas_is_clipped_rather_than_skipped() {
        let mut rows = LinePageRows::default();
        rows.push_wrapped(vec![blank_line(), blank_line(), blank_line(), blank_line()]);
        rows.push(blank_line());

        let window = rows.window(3, 0).expect("overflowing");

        assert_eq!(window.position_label, " row 1/2");
        assert_eq!(window.lines.len(), 2);
    }

    #[test]
    fn a_value_that_wrapped_to_nothing_is_no_row() {
        let mut rows = LinePageRows::default();
        rows.push_wrapped(Vec::new());

        assert_eq!(rows.len(), 0);
    }

    #[test]
    fn a_document_line_that_wraps_is_still_one_row() {
        let lines = vec![
            Line::from("a value long enough to wrap at a narrow canvas width"),
            Line::from(String::new()),
            Line::from("short"),
        ];

        let narrow = LinePageRows::from_document_lines(lines.clone(), 12);
        let wide = LinePageRows::from_document_lines(lines, 120);

        assert_eq!(narrow.len(), 3);
        assert_eq!(wide.len(), 3);
        assert!(narrow.display_len() > wide.display_len());
    }

    /// Paging moves by the rows a window actually shows, so wrapped rows
    /// neither get skipped going down nor repeated going back up.
    #[test]
    fn consecutive_pages_down_and_up_are_contiguous_over_wrapped_rows() {
        let rows = mixed_height_rows(30);
        let visible = 7;
        let last = rows.last_window_start(visible as usize - 1);
        let mut scroll = 0;
        let mut starts = vec![0];
        while scroll < last {
            let window_end = rows.rows_fitting(scroll, visible as usize - 1);
            scroll += rows.page_step(visible, scroll, PageDirection::Down);
            assert!(scroll <= window_end, "skipped rows before {scroll}");
            if scroll < last {
                assert_eq!(
                    scroll, window_end,
                    "next window must start after the last shown row"
                );
            }
            starts.push(scroll);
        }
        assert_eq!(rows.page_step(visible, scroll, PageDirection::Down), 0);
        while scroll > 0 {
            let previous = scroll - rows.page_step(visible, scroll, PageDirection::Up);
            assert!(previous < scroll);
            assert!(
                rows.rows_fitting(previous, visible as usize - 1) >= scroll,
                "skipped going up"
            );
            scroll = previous;
        }
        assert!(
            starts.len() > 2,
            "fixture must span several pages: {starts:?}"
        );
    }

    #[test]
    fn paging_up_from_an_overshoot_lands_on_the_window_before_the_last() {
        let rows = single_line_rows(40);

        let step = rows.page_step(10, usize::MAX, PageDirection::Up);

        assert_eq!(usize::MAX - step, 40 - 9 - 9);
    }

    #[test]
    fn a_page_that_fits_does_not_move() {
        assert_eq!(single_line_rows(5).page_step(10, 0, PageDirection::Down), 0);
        assert_eq!(single_line_rows(5).page_step(10, 3, PageDirection::Up), 0);
    }

    fn mixed_height_rows(count: usize) -> LinePageRows {
        let mut rows = LinePageRows::default();
        for index in 0..count {
            rows.push_wrapped(vec![blank_line(); 1 + index % 3]);
        }
        rows
    }

    fn single_line_rows(count: usize) -> LinePageRows {
        LinePageRows::from_lines((0..count).map(|_| blank_line()).collect())
    }

    fn blank_line() -> Line<'static> {
        Line::from(String::new())
    }
}
