use super::*;
use crate::app::PasteInspection;
use unicode_segmentation::UnicodeSegmentation;

pub(super) fn render(frame: &mut Frame<'_>, app: &ShellApp) -> bool {
    let Some(inspection) = app.editor().paste_inspection() else {
        return false;
    };
    let sections = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(1),
        Constraint::Length(3),
    ])
    .split(frame.area());
    let heading = vec![
        Line::styled(inspection.title(), theme::heading()),
        Line::from(format!(
            "Line {} · Column {}",
            inspection.line + 1,
            inspection.column + 1
        )),
    ];
    frame.render_widget(Paragraph::new(heading), sections[0]);
    let rows = inspection
        .text()
        .split('\n')
        .skip(inspection.line)
        .take(sections[1].height as usize)
        .map(|line| Line::raw(crop(line, inspection.column, sections[1].width as usize)))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(rows), sections[1]);
    frame.render_widget(Paragraph::new(
        "↑/↓ lines · ←/→ cols · Home/End\nEnter expand · Del remove · Esc cancel\nCtrl+_ undo after close · escaped text"
    ).style(theme::subtle()), sections[2]);
    true
}

fn crop(text: &str, start: usize, width: usize) -> String {
    let mut skipped = 0;
    text.graphemes(true)
        .map(visible_grapheme)
        .skip_while(|grapheme| {
            skipped += display_width(grapheme);
            skipped <= start
        })
        .scan(0, |used, grapheme| {
            *used += display_width(&grapheme);
            (*used <= width).then_some(grapheme)
        })
        .collect()
}

fn visible_grapheme(grapheme: &str) -> String {
    if grapheme.chars().any(char::is_control) {
        grapheme.chars().flat_map(char::escape_debug).collect()
    } else {
        grapheme.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;
    use ratatui::{backend::TestBackend, Terminal};

    #[test]
    fn paste_inspector_displays_original_lines_and_all_controls() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.editor_mut().insert_multiline_paste("first\nlast 👩‍💻\n");
        app.inspect_paste_at_cursor();
        let mut terminal = Terminal::new(TestBackend::new(80, 12)).unwrap();
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let buffer = format!("{:?}", terminal.backend().buffer());
        for expected in ["first", "last 👩‍💻", "expand", "remove", "cancel", "undo"] {
            assert!(buffer.contains(expected), "{buffer}");
        }
    }

    #[test]
    fn compact_paste_inspector_keeps_its_controls_readable() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.editor_mut().insert_multiline_paste("first α\nlast β\n");
        app.inspect_paste_at_cursor();
        for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal.draw(|frame| render_app(frame, &app)).unwrap();
            let text = terminal
                .backend()
                .buffer()
                .content()
                .iter()
                .map(|cell| cell.symbol())
                .collect::<String>();
            for expected in [
                "Enter", "expand", "Del", "remove", "Esc", "cancel", "Ctrl+_", "close",
            ] {
                assert!(
                    text.contains(expected),
                    "{width}x{height}: missing {expected}: {text}"
                );
            }
        }
    }

    #[test]
    fn paste_preview_clipping_never_splits_graphemes_or_emits_controls() {
        assert_eq!(crop("a👩‍💻z", 1, 2), "👩‍💻");
        assert_eq!(crop("ae\u{301}z", 1, 1), "e\u{301}");
        assert_eq!(crop("\x1b[31m", 0, 80), "\\u{1b}[31m");
    }
}
