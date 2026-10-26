//! Page wrapped input by display rows without splitting a grapheme or losing text.
use super::*;

impl FieldEditor {
    pub(crate) fn page_visual_rows(&mut self, rows: isize, columns: usize) {
        let starts = visual_row_starts(self.text(), columns.max(1));
        let current = starts
            .partition_point(|start| *start <= self.cursor())
            .saturating_sub(1);
        let next = current.saturating_add_signed(rows).min(starts.len() - 1);
        self.buffer.set_cursor(starts[next]);
    }
}

fn visual_row_starts(text: &str, width: usize) -> Vec<usize> {
    let mut starts = vec![0];
    let (mut column, mut offset) = (0, 0);
    for grapheme in text.graphemes(true) {
        append_row_start(&mut starts, &mut column, offset, grapheme, width);
        offset += grapheme.chars().count();
    }
    // The renderer places an end-of-input caret on the next row at exact width.
    if column == width {
        starts.push(offset);
    }
    starts
}

fn append_row_start(
    starts: &mut Vec<usize>,
    column: &mut usize,
    offset: usize,
    grapheme: &str,
    width: usize,
) {
    if matches!(grapheme, "\n" | "\r\n") {
        starts.push(offset + grapheme.chars().count());
        *column = 0;
        return;
    }
    let cells = display_cells(grapheme, width);
    if *column > 0 && *column + cells > width {
        starts.push(offset);
        *column = 0;
    }
    *column += cells;
}

fn display_cells(grapheme: &str, width: usize) -> usize {
    if grapheme == "\t" || grapheme.chars().any(char::is_control) || grapheme.width() > width {
        1
    } else {
        grapheme.width()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    #[test]
    fn compact_single_line_input_pages_by_display_rows_without_changing_text() {
        let mut field = FieldEditor::new("abcdefghij");
        field.handle_key(KeyEvent::new(KeyCode::Home, KeyModifiers::CONTROL));
        field.page_visual_rows(1, 4);
        assert_eq!(field.cursor(), 4);
        field.page_visual_rows(1, 4);
        assert_eq!(field.cursor(), 8);
        field.page_visual_rows(-1, 4);
        assert_eq!(field.cursor(), 4);
        assert_eq!(field.text(), "abcdefghij");
    }

    #[test]
    fn unicode_tabs_controls_and_exact_width_keep_a_whole_grapheme_cursor() {
        for text in ["abcdefgh", "e\u{301}界👩‍💻\tend\u{1b}", "abc\r\ndefg\n", ""] {
            for width in [1, 2, 4, 8] {
                let mut field = FieldEditor::new(text);
                field.handle_key(KeyEvent::new(KeyCode::Home, KeyModifiers::CONTROL));
                let mut boundaries = vec![0];
                let mut offset = 0;
                for grapheme in text.graphemes(true) {
                    offset += grapheme.chars().count();
                    boundaries.push(offset);
                }
                for _ in 0..20 {
                    field.page_visual_rows(1, width);
                    assert!(
                        boundaries.contains(&field.cursor()),
                        "{text:?} width {width}"
                    );
                }
                field.page_visual_rows(-100, width);
                assert_eq!(field.cursor(), 0);
                assert_eq!(field.text(), text);
            }
        }
    }
}
