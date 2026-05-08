pub(in crate::renderer) use super::*;

#[derive(Debug)]
pub(crate) struct PromptSegments {
    pub(crate) prompt: String,
    pub(crate) before_cursor: String,
    pub(crate) cursor_text: String,
    pub(crate) after_cursor: String,
}

pub(crate) fn prompt_segments(
    prompt: &str,
    input: &str,
    cursor_index: usize,
    columns: usize,
    cursor_glyph: &str,
) -> PromptSegments {
    let width = columns.max(1);
    let min_editor_width = 2.min(width);
    let fitted_prompt = fit_prompt(prompt, width.saturating_sub(min_editor_width));
    let editor_width = width.saturating_sub(fitted_prompt.chars().count()).max(1);

    let input_chars = input.chars().collect::<Vec<_>>();
    let cursor = cursor_index.min(input_chars.len());
    let mut visual_chars = input_chars.clone();
    let cursor_text = if cursor < visual_chars.len() {
        visual_chars[cursor].to_string()
    } else {
        visual_chars.push(cursor_glyph.chars().next().unwrap_or(' '));
        cursor_glyph.to_string()
    };

    let visual_len = visual_chars.len();
    let start = prompt_window_start(visual_len, cursor, editor_width);
    let end = (start + editor_width).min(visual_len);
    let visible = &visual_chars[start..end];
    let visible_cursor = cursor
        .saturating_sub(start)
        .min(visible.len().saturating_sub(1));

    PromptSegments {
        prompt: fitted_prompt,
        before_cursor: visible[..visible_cursor].iter().collect(),
        cursor_text,
        after_cursor: visible[visible_cursor.saturating_add(1)..].iter().collect(),
    }
}

pub(crate) fn fit_prompt(prompt: &str, max_columns: usize) -> String {
    if max_columns == 0 {
        return String::new();
    }
    if prompt.chars().count() <= max_columns {
        return prompt.to_string();
    }
    fit_truncated_prompt(prompt, max_columns)
}

fn fit_truncated_prompt(prompt: &str, max_columns: usize) -> String {
    let suffix = prompt_truncation_suffix(prompt);
    let Some(body_columns) = prompt_body_columns(max_columns, suffix) else {
        return prompt.chars().take(max_columns).collect();
    };
    format!(
        "{}...{}",
        truncated_prompt_body(prompt, body_columns),
        suffix
    )
}

fn prompt_truncation_suffix(prompt: &str) -> &str {
    if prompt.ends_with("> ") {
        "> "
    } else {
        ""
    }
}

fn prompt_body_columns(max_columns: usize, suffix: &str) -> Option<usize> {
    if max_columns <= 4 {
        return None;
    }
    let body_columns = max_columns.saturating_sub(suffix.chars().count());
    (body_columns > 3).then_some(body_columns)
}

fn truncated_prompt_body(prompt: &str, body_columns: usize) -> String {
    prompt
        .chars()
        .take(body_columns.saturating_sub(3))
        .collect()
}

pub(crate) fn prompt_window_start(line_len: usize, cursor_index: usize, width: usize) -> usize {
    if line_len <= width {
        return 0;
    }
    let max_start = line_len.saturating_sub(width);
    let cursor_margin = width.saturating_sub(1) / 2;
    max_start.min(cursor_index.saturating_sub(cursor_margin))
}
