use super::*;

/// Longest prefix still treated as a field name in a `Key: value` line; longer
/// prefixes are prose that happens to contain a colon.
const MAX_KEY_CHARS: usize = 32;
/// Longest item name emphasised in a `Name · description` row.
const MAX_NAME_CHARS: usize = 48;

/// Style one line of a plain-text modal body so its structure reads at a
/// glance: ALL-CAPS section headings in the label colour, `Key: value` rows
/// with a dim key and a bright value, everything else as primary text.
pub(crate) fn readable_line(text: &str) -> Line<'static> {
    if is_section_heading(text) {
        return Line::styled(text.to_owned(), theme::label());
    }
    if let Some((key, value)) = field_split(text) {
        return field_line(key, value);
    }
    match named_item_split(text) {
        Some((name, rest)) => Line::from(vec![
            Span::styled(name.to_owned(), theme::heading()),
            Span::styled(format!(" · {rest}"), theme::primary()),
        ]),
        None => Line::styled(text.to_owned(), theme::primary()),
    }
}

/// `Components: 13` introduces a list, so a short list name with a bare count
/// reads as a heading; any other field keeps a dim key beside its value.
fn field_line(key: &str, value: &str) -> Line<'static> {
    let list_count =
        key.split_whitespace().count() <= 2 && value.trim().chars().all(|c| c.is_ascii_digit());
    if list_count {
        return Line::styled(format!("{key}: {value}"), theme::label());
    }
    Line::from(vec![
        Span::styled(format!("{key}:"), theme::muted()),
        Span::styled(format!(" {value}"), theme::primary()),
    ])
}

/// `GET /hello handler · Copies the name…` names an item before describing
/// it; the name stands out so a list of items scans by name.
fn named_item_split(text: &str) -> Option<(&str, &str)> {
    let (name, rest) = text.split_once(" · ")?;
    let is_name = name.chars().count() <= MAX_NAME_CHARS
        && !name.starts_with(|c: char| c.is_ascii_digit() || c.is_whitespace())
        && !name.contains(". ");
    is_name.then_some((name, rest))
}

fn is_section_heading(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.chars().filter(|c| c.is_alphabetic()).count() >= 4
        && !trimmed.chars().any(char::is_lowercase)
        && trimmed
            .chars()
            .all(|c| c.is_alphabetic() || " &/-".contains(c))
}

fn field_split(text: &str) -> Option<(&str, &str)> {
    let (key, value) = text.split_once(": ")?;
    let key_is_name = !key.is_empty()
        && key.chars().count() <= MAX_KEY_CHARS
        && key.starts_with(|c: char| c.is_alphabetic())
        && !key.contains(['"', '(', '.', ':']);
    (key_is_name && !value.trim().is_empty()).then_some((key, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span_texts(line: &Line<'_>) -> Vec<String> {
        line.spans
            .iter()
            .map(|span| span.content.to_string())
            .collect()
    }

    #[test]
    fn field_lines_split_key_from_value() {
        let line = readable_line("Total provider calls: 120");

        assert_eq!(span_texts(&line), ["Total provider calls:", " 120"]);
    }

    #[test]
    fn headings_prose_and_json_stay_whole() {
        for text in [
            "SPENDING LIMITS",
            "acme-shop is a small Express.js storefront (server.js:1-67). It runs: one process",
            "  \"model\": \"anthropic:claude-haiku-5-5\",",
            "Draft ready.",
        ] {
            assert_eq!(span_texts(&readable_line(text)), [text], "{text}");
        }
    }

    #[test]
    fn counts_head_lists_and_named_items_split_at_the_first_dot() {
        assert_eq!(
            span_texts(&readable_line("Components: 13")),
            ["Components: 13"]
        );
        assert_eq!(
            span_texts(&readable_line("Data flows: 8")),
            ["Data flows: 8"]
        );
        assert_eq!(
            span_texts(&readable_line(
                "GET /hello handler · Copies the name · into HTML"
            )),
            ["GET /hello handler", " · Copies the name · into HTML"]
        );
        let counts = "3 fixed jobs · 1 worker(s)";
        assert_eq!(span_texts(&readable_line(counts)), [counts]);
    }

    #[test]
    fn only_all_caps_rows_are_headings() {
        assert!(is_section_heading("PLAN DETAILS"));
        assert!(is_section_heading("REVIEW PLAN & ALLOWANCE"));
        assert!(!is_section_heading("Plan details"));
        assert!(!is_section_heading("F-01"));
    }
}
