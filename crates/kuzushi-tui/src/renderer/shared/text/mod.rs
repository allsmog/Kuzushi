pub(in crate::renderer) use super::*;
pub(crate) use crate::ui_view_models::format_session_cost;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub(crate) fn join_segments(values: &[String]) -> String {
    values
        .iter()
        .filter(|value| !value.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join(theme::STATUS_SEPARATOR)
}

pub(crate) fn short_sentence(value: &str, max_chars: usize) -> String {
    let first = value.split('.').next().unwrap_or(value).trim();
    fit(first, max_chars)
}

pub(crate) fn fit(value: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    if display_width(value) <= max_chars {
        return value.to_string();
    }
    if max_chars <= 3 {
        return take_columns(value, max_chars);
    }
    fit_with_ellipsis(value, max_chars)
}

/// Fit a path-like string by truncating from the LEFT, so the most useful tail
/// (`…/dir/file.rs:42`) stays visible instead of the repo-root prefix.
pub(crate) fn fit_path(value: &str, max_chars: usize) -> String {
    if max_chars == 0 || display_width(value) <= max_chars {
        return value.to_string();
    }
    if max_chars <= 3 {
        return take_tail_columns(value, max_chars);
    }
    let tail = take_tail_columns(value, max_chars - 1);
    format!("…{tail}")
}

fn fit_with_ellipsis(value: &str, max_chars: usize) -> String {
    let budget = max_chars.saturating_sub(3);
    let head = take_columns(value, budget);
    if let Some(clean) = clean_sentence_break(&head, budget) {
        return clean;
    }
    let trimmed = trim_to_word_boundary(&head);
    let trimmed = trimmed.trim_end_matches('.');
    format!("{trimmed}...")
}

fn clean_sentence_break(head: &str, budget: usize) -> Option<String> {
    let total = head.chars().count();
    if total < 16 {
        return None;
    }
    let min_keep = (budget * 6 / 10).max(1);
    let mut chars_seen = 0usize;
    let mut last_break: Option<usize> = None;
    let mut prev: Option<char> = None;
    for (idx, ch) in head.char_indices() {
        chars_seen += 1;
        if matches!(prev, Some('.') | Some('!') | Some('?')) && ch == ' ' && chars_seen > min_keep {
            last_break = Some(idx);
        }
        prev = Some(ch);
    }
    last_break.map(|byte| head[..byte].trim_end().to_string())
}

fn trim_to_word_boundary(head: &str) -> &str {
    // Only honor word boundaries on space/tab — hyphens and slashes are
    // load-bearing inside identifiers (run-ids, paths, module names).
    // Never trim past 70% of the head — short labels would otherwise
    // collapse to a single character + ellipsis.
    let total = head.chars().count();
    if total == 0 {
        return head;
    }
    let min_keep = (total * 7 / 10).max(1);
    last_word_boundary_after(head, min_keep)
        .map(|byte| head[..byte].trim_end_matches([' ', ',']))
        .unwrap_or(head)
}

fn last_word_boundary_after(head: &str, min_keep: usize) -> Option<usize> {
    let mut chars_seen = 0usize;
    let mut boundary = None;
    for (idx, ch) in head.char_indices() {
        chars_seen += 1;
        if matches!(ch, ' ' | '\t' | ',') && chars_seen > min_keep {
            boundary = Some(idx);
        }
    }
    boundary
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
        if display_width(&pending) <= self.width {
            self.current = pending;
            return String::new();
        }
        let (head, tail) = split_at_width(&pending, self.width);
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
    display_width(current) + 1 + display_width(pending) <= width
}

pub(crate) fn pad(value: &str, width: usize) -> String {
    let value = fit(value, width);
    let padding = width.saturating_sub(display_width(&value));
    format!("{value}{}", " ".repeat(padding))
}

pub(crate) fn value_width(area: Rect, used: usize) -> usize {
    (area.width as usize).saturating_sub(used).max(12)
}

pub(crate) fn display_width(value: &str) -> usize {
    UnicodeWidthStr::width(value)
}

fn char_display_width(ch: char) -> usize {
    UnicodeWidthChar::width(ch).unwrap_or(0)
}

pub(crate) fn take_columns(value: &str, max_columns: usize) -> String {
    let mut width = 0usize;
    let mut out = String::new();
    for ch in value.chars() {
        let next = width + char_display_width(ch);
        if next > max_columns {
            break;
        }
        out.push(ch);
        width = next;
    }
    out
}

pub(crate) fn take_tail_columns(value: &str, max_columns: usize) -> String {
    let mut width = 0usize;
    let mut chars = Vec::new();
    for ch in value.chars().rev() {
        let next = width + char_display_width(ch);
        if next > max_columns {
            break;
        }
        chars.push(ch);
        width = next;
    }
    chars.into_iter().rev().collect()
}

fn split_at_width(value: &str, width: usize) -> (String, String) {
    if width == 0 {
        return (String::new(), value.to_string());
    }
    let mut used = 0usize;
    for (index, ch) in value.char_indices() {
        let next = used + char_display_width(ch);
        if next > width {
            return (value[..index].to_string(), value[index..].to_string());
        }
        used = next;
    }
    (value.to_string(), String::new())
}

#[cfg(test)]
mod fit_path_tests {
    use super::{display_width, fit, fit_path, pad, wrap_text};

    #[test]
    fn keeps_full_path_when_it_fits() {
        assert_eq!(fit_path("src/a.rs:10", 20), "src/a.rs:10");
    }

    #[test]
    fn truncates_from_the_left_keeping_the_tail() {
        let got = fit_path("crates/core/src/scan/engines/secret_scan/file.rs:13", 24);
        assert_eq!(display_width(&got), 24);
        assert!(got.starts_with('…'));
        assert!(got.ends_with("file.rs:13"), "kept the useful tail: {got}");
    }

    #[test]
    fn fit_and_pad_count_display_columns() {
        let got = fit("ab日本cd", 6);
        assert_eq!(display_width(&got), 5);
        assert_eq!(got, "ab...");

        let padded = pad("界", 4);
        assert_eq!(display_width(&padded), 4);
    }

    #[test]
    fn wrap_text_splits_wide_words_on_columns() {
        let lines = wrap_text("ab日本cd", 4);
        assert!(lines.iter().all(|line| display_width(line) <= 4));
        assert_eq!(lines, vec!["ab日", "本cd"]);
    }
}
