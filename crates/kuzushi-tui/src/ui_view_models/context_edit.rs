//! Context edit projection uses captured draft text, never a store or active model.
use crate::app::{ContextEditDraft, ContextEditMode};
use crate::renderer::shared::text::wrap_text;

pub(crate) fn context_edit_title(mode: ContextEditMode) -> &'static str {
    match mode {
        ContextEditMode::Fields | ContextEditMode::Writing => "EDIT CONTEXT COPY",
        ContextEditMode::Review => "REVIEW CONTEXT CHANGES",
        ContextEditMode::Saving => "SAVING CONTEXT COPY",
        ContextEditMode::Discard => "DISCARD CONTEXT DRAFT",
    }
}

pub(crate) fn context_edit_controls(mode: ContextEditMode) -> [&'static str; 2] {
    if mode == ContextEditMode::Writing {
        return ["Enter newline · Ctrl+S review", "Esc back (keep draft)"];
    }
    if mode == ContextEditMode::Fields {
        return [
            "↑↓ Enter edit · r review · g regen",
            "d discard · Esc back (keep draft)",
        ];
    }
    context_read_controls(mode)
}

fn context_read_controls(mode: ContextEditMode) -> [&'static str; 2] {
    match mode {
        ContextEditMode::Review => ["Enter save copy · PgUp/Dn read", "Esc edits · d discard"],
        ContextEditMode::Discard => ["Enter discard this draft", "Esc keep draft"],
        _ => ["Saving copy · Esc back", "Ctrl+C cancel · draft kept"],
    }
}

pub(crate) fn context_edit_review_lines(draft: &ContextEditDraft, width: usize) -> Vec<String> {
    let mut text = vec![
        format!("Copy name: {}", draft.entries[0].text()),
        "Saving creates a separate inactive revision. Select it for work only after inspection."
            .into(),
    ];
    for entry in draft.entries.iter().skip(1).filter(|entry| entry.changed()) {
        text.extend([String::new(), entry.label.clone(), "Before:".into()]);
        text.extend(edit_value_lines(&entry.original, "- "));
        text.push("After:".into());
        text.extend(edit_value_lines(entry.text(), "+ "));
    }
    text.into_iter()
        .flat_map(|line| wrap_text(&line, width))
        .collect()
}

fn edit_value_lines(text: &str, prefix: &str) -> Vec<String> {
    if text.is_empty() {
        return vec![format!("{prefix}<empty>")];
    }
    text.lines().map(|line| format!("{prefix}{line}")).collect()
}

pub(crate) fn context_edit_plain_lines(draft: &ContextEditDraft, width: usize) -> Vec<String> {
    let mut text = vec![
        context_edit_title(draft.mode).into(),
        "Inactive copy · no model calls".into(),
    ];
    text.extend(draft.notice.iter().cloned());
    text.extend(context_edit_body_lines(draft, width));
    text.extend(context_edit_controls(draft.mode).map(str::to_owned));
    text
}

fn context_edit_body_lines(draft: &ContextEditDraft, width: usize) -> Vec<String> {
    match draft.mode {
        ContextEditMode::Fields => draft
            .entries
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                format!(
                    "{} {}",
                    if index == draft.cursor { "▸" } else { " " },
                    entry.label
                )
            })
            .flat_map(|line| wrap_text(&line, width))
            .collect(),
        ContextEditMode::Writing => selected_context_text_lines(draft, width),
        _ => context_edit_review_lines(draft, width),
    }
}

fn selected_context_text_lines(draft: &ContextEditDraft, width: usize) -> Vec<String> {
    let entry = &draft.entries[draft.cursor];
    let mut text = vec![entry.label.clone()];
    text.extend(entry.text().lines().map(str::to_owned));
    let cursor = entry
        .editor
        .as_ref()
        .map_or(0, crate::app::FieldEditor::cursor);
    text.push(format!("Cursor: {cursor} characters"));
    text.into_iter()
        .flat_map(|line| wrap_text(&line, width))
        .collect()
}
