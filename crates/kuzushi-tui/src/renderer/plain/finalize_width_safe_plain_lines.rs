use super::*;

pub(crate) fn finalize_width_safe_plain_lines(lines: Vec<String>, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    for line in lines {
        let line = sanitize_for_plain_output(&line);
        if line.chars().count() <= width {
            out.push(line);
        } else if should_truncate_plain_line(&line) {
            out.push(sanitize_for_plain_output(&fit(&line, width)));
        } else {
            out.extend(
                wrap_text(&line, width)
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
    value
        .chars()
        .map(|ch| match ch {
            '\u{2500}'..='\u{257f}' => '-',
            '\u{00b7}' => '|',
            _ => ch,
        })
        .collect()
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
