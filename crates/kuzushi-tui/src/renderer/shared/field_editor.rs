use crate::app::FieldEditor;
use crate::theme;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use unicode_width::UnicodeWidthChar;

/// Keep the editing cursor in view without discarding any draft text. The
/// same projection is used by terminal and plain rendering.
pub(in crate::renderer) fn field_editor_lines(
    field: &FieldEditor,
    width: usize,
    height: usize,
) -> Vec<Line<'static>> {
    if width == 0 || height == 0 {
        return Vec::new();
    }
    let (rows, cursor_row) = field_rows(field, width);
    let start = cursor_row
        .saturating_sub(height / 2)
        .min(rows.len().saturating_sub(height));
    rows.into_iter().skip(start).take(height).collect()
}

fn field_rows(field: &FieldEditor, width: usize) -> (Vec<Line<'static>>, usize) {
    let mut rows = vec![Line::default()];
    let mut columns = 0;
    let mut cursor_row = 0;
    for (index, ch) in field
        .text()
        .chars()
        .chain(std::iter::once('\n'))
        .enumerate()
    {
        let cursor = index == field.cursor();
        append_field_character(&mut rows, &mut columns, ch, cursor, width);
        if cursor {
            cursor_row = rows.len() - 1;
        }
        if ch == '\n' {
            rows.push(Line::default());
            columns = 0;
        }
    }
    rows.pop();
    (rows, cursor_row)
}

fn append_field_character(
    rows: &mut Vec<Line<'static>>,
    columns: &mut usize,
    ch: char,
    cursor: bool,
    width: usize,
) {
    if ch == '\n' && !cursor {
        return;
    }
    let text = field_character(ch, width);
    let cells: usize = text.chars().map(|ch| ch.width().unwrap_or(0)).sum();
    if *columns > 0 && *columns + cells > width {
        rows.push(Line::default());
        *columns = 0;
    }
    let style = if cursor {
        theme::accent().add_modifier(Modifier::REVERSED)
    } else {
        theme::primary()
    };
    append_field_span(rows, Span::styled(text, style));
    *columns += cells;
}

fn append_field_span(rows: &mut Vec<Line<'static>>, span: Span<'static>) {
    if let Some(line) = rows.last_mut() {
        line.spans.push(span);
    } else {
        rows.push(Line::from(span));
    }
}

fn field_character(ch: char, width: usize) -> String {
    match ch {
        '\n' => " ".into(),
        '\t' => "⇥".into(),
        ch if ch.is_control() || ch.width().unwrap_or(0) > width => "�".into(),
        ch => ch.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    #[test]
    fn long_multiline_drafts_keep_the_cursor_visible_at_narrow_widths() {
        let mut field = FieldEditor::new("first\nsecond\nArchitecture, v2.md");
        for width in [10, 20, 80] {
            let lines = field_editor_lines(&field, width, 3);
            assert!(lines.len() <= 3);
            assert!(lines
                .iter()
                .flat_map(|line| &line.spans)
                .any(|span| span.style.add_modifier.contains(Modifier::REVERSED)));
            assert!(lines.iter().all(|line| line.width() <= width));
        }
        field.handle_key(KeyEvent::new(KeyCode::Home, KeyModifiers::CONTROL));
        assert!(field_editor_lines(&field, 20, 2)[0]
            .to_string()
            .starts_with("first"));
    }

    #[test]
    fn wrapping_preserves_unicode_and_empty_fields_have_a_cursor() {
        let field = FieldEditor::new("東京, v2");
        let text = field_editor_lines(&field, 4, 8)
            .iter()
            .map(ToString::to_string)
            .collect::<String>();
        assert_eq!(text.trim_end(), field.text());
        assert_eq!(
            field_editor_lines(&FieldEditor::default(), 4, 1)[0].width(),
            1
        );
        assert!(field_editor_lines(&field, 1, 8)
            .iter()
            .all(|line| line.width() <= 1));
    }
}
