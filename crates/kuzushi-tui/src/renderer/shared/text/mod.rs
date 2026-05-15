pub(in crate::renderer) use super::*;
pub(crate) use crate::ui_view_models::{compact_target_path, format_session_cost};

pub(crate) fn join_segments(values: &[String]) -> String {
    values
        .iter()
        .filter(|value| !value.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join(theme::STATUS_SEPARATOR)
}

pub(crate) fn short(value: &str) -> String {
    value.chars().take(8).collect()
}

pub(crate) fn short_sentence(value: &str, max_chars: usize) -> String {
    let first = value.split('.').next().unwrap_or(value).trim();
    fit(first, max_chars)
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

    let mut lines = wrap_text_lines(value, width);
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

fn wrap_text_lines(value: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for raw_line in value.lines() {
        lines.extend(wrap_line(raw_line, width));
    }
    lines
}

fn wrap_line(raw_line: &str, width: usize) -> Vec<String> {
    if raw_line.is_empty() {
        return vec![String::new()];
    }
    let mut state = WrapLineState::new(width);
    for word in raw_line.split_whitespace() {
        state.push_word(word);
    }
    state.finish()
}

struct WrapLineState {
    lines: Vec<String>,
    current: String,
    width: usize,
}

impl WrapLineState {
    fn new(width: usize) -> Self {
        Self {
            lines: Vec::new(),
            current: String::new(),
            width,
        }
    }

    fn push_word(&mut self, word: &str) {
        let mut pending = word.to_string();
        while !pending.is_empty() {
            pending = self.push_pending(pending);
        }
    }

    fn push_pending(&mut self, pending: String) -> String {
        if self.current.is_empty() {
            return self.start_or_split(pending);
        }
        if fits_with_space(&self.current, &pending, self.width) {
            self.current.push(' ');
            self.current.push_str(&pending);
            return String::new();
        }
        self.flush_current();
        pending
    }

    fn start_or_split(&mut self, pending: String) -> String {
        if pending.chars().count() <= self.width {
            self.current = pending;
            return String::new();
        }
        let (head, tail) = split_at_char_count(&pending, self.width);
        self.lines.push(head);
        tail
    }

    fn flush_current(&mut self) {
        self.lines.push(std::mem::take(&mut self.current));
    }

    fn finish(mut self) -> Vec<String> {
        if !self.current.is_empty() {
            self.lines.push(self.current);
        }
        self.lines
    }
}

fn fits_with_space(current: &str, pending: &str, width: usize) -> bool {
    current.chars().count() + 1 + pending.chars().count() <= width
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
