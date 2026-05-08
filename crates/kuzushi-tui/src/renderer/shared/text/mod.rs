pub(in crate::renderer) use super::*;

pub(crate) fn join_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(", ")
    }
}

pub(crate) fn join_segments(values: &[String]) -> String {
    values
        .iter()
        .filter(|value| !value.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join(theme::STATUS_SEPARATOR)
}

pub(crate) fn compact_target_path(value: &str) -> String {
    let trimmed = value.trim_end_matches('/');
    let name = trimmed
        .rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or(trimmed);
    if name.is_empty() {
        "target:/".to_string()
    } else {
        format!("./{name}")
    }
}

pub(crate) fn short(value: &str) -> String {
    value.chars().take(8).collect()
}

pub(crate) fn short_sentence(value: &str, max_chars: usize) -> String {
    let first = value.split('.').next().unwrap_or(value).trim();
    fit(first, max_chars)
}

/// Compact dollar-amount format for the header. Sub-cent values keep four
/// decimals (e.g. "$0.0042"); larger values drop to two so a long-running
/// session doesn't read "$12.4567" and waste header cells.
pub(crate) fn format_session_cost(usd: f64) -> String {
    if usd < 0.01 {
        format!("${usd:.4}")
    } else if usd < 100.0 {
        format!("${usd:.2}")
    } else {
        format!("${usd:.0}")
    }
}

pub(crate) fn fit(value: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    if max_chars <= 3 {
        return value.chars().take(max_chars).collect();
    }
    let mut truncated = value
        .chars()
        .take(max_chars.saturating_sub(3))
        .collect::<String>();
    truncated.push_str("...");
    truncated
}

pub(crate) fn wrap_text(value: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![String::new()];
    }

    let mut lines = Vec::new();
    for raw_line in value.lines() {
        let mut current = String::new();
        for word in raw_line.split_whitespace() {
            let mut pending = word.to_string();
            while !pending.is_empty() {
                let pending_len = pending.chars().count();
                let current_len = current.chars().count();
                if current_len == 0 {
                    if pending_len <= width {
                        current = pending;
                        break;
                    }
                    let (head, tail) = split_at_char_count(&pending, width);
                    lines.push(head);
                    pending = tail;
                } else if current_len + 1 + pending_len <= width {
                    current.push(' ');
                    current.push_str(&pending);
                    break;
                } else {
                    lines.push(current);
                    current = String::new();
                }
            }
        }
        if !current.is_empty() {
            lines.push(current);
        } else if raw_line.is_empty() {
            lines.push(String::new());
        }
    }

    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

pub(crate) fn split_at_char_count(value: &str, count: usize) -> (String, String) {
    if count == 0 {
        return (String::new(), value.to_string());
    }
    let split_index = value
        .char_indices()
        .nth(count)
        .map(|(index, _)| index)
        .unwrap_or(value.len());
    (
        value[..split_index].to_string(),
        value[split_index..].to_string(),
    )
}

pub(crate) fn pad(value: &str, width: usize) -> String {
    let value = fit(value, width);
    let padding = width.saturating_sub(value.chars().count());
    format!("{value}{}", " ".repeat(padding))
}

pub(crate) fn value_width(area: Rect, used: usize) -> usize {
    (area.width as usize).saturating_sub(used).max(12)
}
