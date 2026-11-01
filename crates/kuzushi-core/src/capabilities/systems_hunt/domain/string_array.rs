use super::*;
use crate::text::truncate::utf8_prefix;

/// Evidence lines are quoted scanned source, so the budget is in bytes and
/// the cut has to respect character boundaries.
const MAX_LINE_BYTES: usize = 240;

pub(crate) fn string_array(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect(),
        Some(Value::String(value)) if !value.trim().is_empty() => vec![value.trim().to_string()],
        _ => Vec::new(),
    }
}

pub(crate) fn string_record(value: Option<&Value>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    match value {
        Some(Value::Object(object)) => {
            for (key, value) in object {
                if let Some(value) = value
                    .as_str()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    out.insert(key.clone(), value.to_string());
                }
            }
        }
        Some(Value::Array(items)) => {
            for item in items {
                let Some(object) = item.as_object() else {
                    continue;
                };
                let key = string_field(object.get("field"));
                let value = string_field(object.get("value"));
                if !key.is_empty() && !value.is_empty() {
                    out.insert(key, value);
                }
            }
        }
        _ => {}
    }
    out
}

pub(crate) fn sanitize_rule_segment(value: &str) -> String {
    let mut out = value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>();
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    out.trim_matches('-').to_string()
}

pub(crate) fn trim_line(line: &str) -> String {
    let trimmed = line.trim();
    if trimmed.len() <= MAX_LINE_BYTES {
        trimmed.to_string()
    } else {
        format!("{}...", utf8_prefix(trimmed, MAX_LINE_BYTES))
    }
}

#[cfg(test)]
pub(crate) fn empty_context() -> SystemsContextOutput {
    SystemsContextOutput {
        surfaces: Vec::new(),
        surface_packs: Vec::new(),
        metadata: SystemsContextMetadata {
            codeql_available: false,
            codeql_db_path: None,
            bash_probing_used: false,
            systems_source_files: 1,
            inspection: None,
        },
    }
}

#[cfg(test)]
mod trim_line_tests {
    use super::{trim_line, MAX_LINE_BYTES};

    #[test]
    fn a_long_ascii_line_is_cut_at_the_byte_budget() {
        let line = "a".repeat(MAX_LINE_BYTES + 10);
        assert_eq!(
            trim_line(&line),
            format!("{}...", "a".repeat(MAX_LINE_BYTES))
        );
    }

    #[test]
    fn a_multi_byte_character_straddling_the_budget_is_dropped_not_split() {
        // Byte 240 lands inside the first three-byte character, which is
        // exactly where `&line[..240]` used to panic on a scanned source line.
        let line = format!("{}\u{65e5}\u{672c}\u{8a9e}", "x".repeat(MAX_LINE_BYTES - 2));
        assert!(line.len() > MAX_LINE_BYTES);
        assert_eq!(
            trim_line(&line),
            format!("{}...", "x".repeat(MAX_LINE_BYTES - 2))
        );
    }

    #[test]
    fn every_offset_of_a_multi_byte_run_survives_the_budget() {
        for pad in 0..8 {
            let line = format!(
                "{}{}",
                "x".repeat(MAX_LINE_BYTES - pad),
                "\u{1f512}".repeat(4)
            );
            let trimmed = trim_line(&line);
            assert!(trimmed.ends_with("..."));
            assert!(line.starts_with(trimmed.trim_end_matches('.')));
        }
    }
}
