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
    if line.starts_with("mode:") {
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
    value.chars().map(box_drawing_to_ascii).collect()
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
