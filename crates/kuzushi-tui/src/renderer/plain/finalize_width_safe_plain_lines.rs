use super::*;

pub(crate) fn finalize_width_safe_plain_lines(lines: Vec<String>, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    for line in lines {
        let line = sanitize_for_plain_output(&line);
        let trimmed = line.trim_end().to_string();
        if trimmed.chars().count() <= width {
            out.push(trimmed);
        } else if should_truncate_plain_line(&trimmed) {
            out.push(sanitize_for_plain_output(&fit(&trimmed, width)));
        } else {
            out.extend(
                wrap_text(&trimmed, width)
                    .into_iter()
                    .map(|line| sanitize_for_plain_output(&line)),
            );
        }
    }
    out
}

pub(crate) fn should_truncate_plain_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }
    if line.starts_with("route:") {
        return true;
    }
    if trimmed.chars().all(|ch| {
        ch == '-' || ch == ' ' || ch == '/' || ch.is_ascii_uppercase() || ch.is_ascii_digit()
    }) {
        return true;
    }

    let padded_column_gaps = line.matches("  ").count();
    padded_column_gaps >= 3
}

pub(crate) fn sanitize_for_plain_output(value: &str) -> String {
    // Control chars (C0, DEL, C1) are dropped, not just remapped: finding
    // titles/paths/evidence originate from scanned repos and model output,
    // and plain output goes to real terminals and pipes where ESC/OSC/BEL
    // would be interpreted (OSC 52 clipboard writes, title changes, cursor
    // lies). The framed path gets the same guarantee from ratatui
    // set_stringn's `!symbol.contains(char::is_control)` filter.
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .map(box_drawing_to_ascii)
        .collect()
}

fn box_drawing_to_ascii(ch: char) -> char {
    match ch {
        // Horizontal lines (single and double weight): keep as `-`
        '\u{2500}' | '\u{2501}' | '\u{2504}' | '\u{2505}' | '\u{2508}' | '\u{2509}'
        | '\u{254c}' | '\u{254d}' | '\u{2550}' => '-',
        // Vertical lines (single and double weight)
        '\u{2502}' | '\u{2503}' | '\u{2506}' | '\u{2507}' | '\u{250a}' | '\u{250b}'
        | '\u{254e}' | '\u{254f}' | '\u{2551}' => '|',
        // Anything else in the box-drawing block: corners, joins, arrows. Use `+`.
        '\u{2500}'..='\u{257f}' => '+',
        // Terminal UI signifiers used by the TTY renderer. Plain/screen-reader
        // output should preserve meaning without relying on glyph support.
        '█' | '▌' | '▐' | '▀' | '▄' | '▁'..='▇' => '#',
        '▶' | '▸' | '➜' | '→' | '⇒' => '>',
        '◀' | '◂' | '←' | '⇐' => '<',
        '●' | '•' | '⠋'..='⣿' => '*',
        '○' | '◦' => 'o',
        '✓' | '✔' => '+',
        '✗' | '✘' | '×' => 'x',
        _ => ch,
    }
}

pub(crate) fn trim_plain_lines(mut lines: Vec<String>) -> Vec<String> {
    while lines.first().is_some_and(|line| line.trim().is_empty()) {
        lines.remove(0);
    }
    while lines.last().is_some_and(|line| line.trim().is_empty()) {
        lines.pop();
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_for_plain_output_folds_terminal_glyphs() {
        assert_eq!(
            sanitize_for_plain_output("█ ▌ ▶ ● ○ ⠿ ✓ ✗"),
            "# # > * o * + x"
        );
    }

    #[test]
    fn sanitize_for_plain_output_strips_terminal_escape_sequences() {
        // A hostile finding title trying OSC-52 clipboard write, a color
        // escape, a BEL, C1 CSI, and a carriage-return overwrite.
        let hostile = "safe\x1b]52;c;cHdu\x07 \x1b[31mred\u{9b}31m tail\rOVERWRITE";
        let cleaned = sanitize_for_plain_output(hostile);
        assert!(
            !cleaned.chars().any(char::is_control),
            "control chars survived: {cleaned:?}"
        );
        assert!(cleaned.starts_with("safe"));
        assert!(cleaned.contains("tail"));
    }

    #[test]
    fn finalize_strips_controls_even_on_width_safe_lines() {
        let lines = finalize_width_safe_plain_lines(vec!["a\x1b[2Jb".to_string()], 80);
        assert_eq!(lines, vec!["a[2Jb".to_string()]);
    }

    #[test]
    fn ratatui_buffer_drops_control_graphemes_from_untrusted_spans() {
        // The framed path relies on ratatui set_stringn filtering control
        // chars; if a ratatui upgrade relaxes that, plain-output stripping is
        // no longer sufficient and this canary must fail.
        use ratatui::buffer::Buffer;
        use ratatui::layout::Rect;
        use ratatui::style::Style;
        let mut buffer = Buffer::empty(Rect::new(0, 0, 20, 1));
        buffer.set_stringn(0, 0, "a\x1b]52;c;x\x07b", 20, Style::default());
        let row: String = (0..20)
            .map(|x| buffer[(x, 0)].symbol().to_string())
            .collect();
        assert!(
            !row.chars().any(char::is_control),
            "ratatui let control chars into cells: {row:?}"
        );
        assert!(row.starts_with("a]52;c;xb"));
    }
}
