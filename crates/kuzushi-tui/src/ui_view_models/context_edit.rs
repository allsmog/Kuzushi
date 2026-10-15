//! Context edit projection uses captured draft text, never a store or active model.
use crate::app::{ContextDraftRecovery, ContextEditDraft, ContextEditMode};
use crate::renderer::shared::text::wrap_text;

pub(crate) fn context_edit_title(mode: ContextEditMode) -> &'static str {
    if mode == ContextEditMode::Recovery {
        return "RECOVER CONTEXT DRAFT";
    }
    context_copy_title(mode)
}

fn context_copy_title(mode: ContextEditMode) -> &'static str {
    match mode {
        ContextEditMode::Fields | ContextEditMode::Writing | ContextEditMode::Recovery => {
            "EDIT CONTEXT COPY"
        }
        ContextEditMode::Review => "REVIEW CONTEXT CHANGES",
        ContextEditMode::Saving => "SAVING CONTEXT COPY",
        ContextEditMode::Discard => "DISCARD CONTEXT DRAFT",
    }
}

pub(crate) fn context_edit_controls(mode: ContextEditMode) -> [&'static str; 2] {
    if mode == ContextEditMode::Recovery {
        return ["↑↓ choose · Enter recover/retry", "n new draft · Esc back"];
    }
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

pub(crate) fn context_draft_controls(draft: &ContextEditDraft) -> [&'static str; 2] {
    if draft.mode != ContextEditMode::Recovery {
        return context_edit_controls(draft.mode);
    }
    recovery_controls(&draft.recovery)
}

fn recovery_controls(recovery: &ContextDraftRecovery) -> [&'static str; 2] {
    match recovery {
        ContextDraftRecovery::Choices { .. } => {
            ["↑↓ choose · Enter recover", "n new draft · Esc back"]
        }
        ContextDraftRecovery::Failed(_) => ["Enter retry recovery", "Esc back"],
        _ => ["Loading saved drafts…", "Esc back"],
    }
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

pub(crate) fn context_edit_plain_lines(
    draft: &ContextEditDraft,
    width: usize,
    checkpoint: Option<String>,
) -> Vec<String> {
    let mut text = vec![
        context_edit_title(draft.mode).into(),
        "Inactive copy · no model calls".into(),
    ];
    text.extend(draft.notice.iter().cloned());
    text.extend(checkpoint);
    text.extend(context_edit_body_lines(draft, width));
    text.extend(context_draft_controls(draft).map(str::to_owned));
    text
}

fn context_edit_body_lines(draft: &ContextEditDraft, width: usize) -> Vec<String> {
    if draft.mode == ContextEditMode::Recovery {
        return context_recovery_lines(draft, width, 128);
    }
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

pub(crate) fn context_recovery_lines(
    draft: &ContextEditDraft,
    width: usize,
    rows: usize,
) -> Vec<String> {
    match &draft.recovery {
        ContextDraftRecovery::Loading => wrap_text("Loading private checkpoints. No work starts.", width),
        ContextDraftRecovery::Failed(error) => wrap_text(&format!("Saved drafts unavailable: {error}. Original checkpoints are retained. Enter retries; Esc returns."), width),
        ContextDraftRecovery::Choices { drafts, cursor } => recovery_choices(draft, drafts, *cursor, width, rows),
        ContextDraftRecovery::None => Vec::new(),
    }
}

fn recovery_choices(
    draft: &ContextEditDraft,
    drafts: &[kuzushi_core::session_transcript::RecoveredContextDraft],
    cursor: usize,
    width: usize,
    rows: usize,
) -> Vec<String> {
    let count = rows.saturating_sub(4).max(1);
    let start = cursor.saturating_sub(count.saturating_sub(1));
    let mut lines = vec![format!(
        "{} saved {} · exact context",
        drafts.len(),
        plural(drafts.len(), "draft", "drafts")
    )];
    for (index, saved) in drafts.iter().enumerate().skip(start).take(count) {
        let snapshot = saved.record.snapshot.as_ref().unwrap();
        let name: String = snapshot
            .name
            .text
            .chars()
            .map(|ch| if ch.is_control() { ' ' } else { ch })
            .collect();
        lines.push(recovery_row(
            &name,
            snapshot.fields.len(),
            index == cursor,
            width,
        ));
    }
    append_recovery_preview(&mut lines, draft, &drafts[cursor], width);
    lines
}

fn recovery_row(name: &str, fields: usize, selected: bool, width: usize) -> String {
    use unicode_width::UnicodeWidthStr;
    let marker = if selected { "▸" } else { " " };
    let suffix = format!(" · {fields} {}", plural(fields, "field", "fields"));
    let name_width = width.saturating_sub(2 + suffix.width());
    let name = crate::renderer::shared::text::fit_path(name, name_width);
    format!("{marker} {name}{suffix}")
}

fn plural<'a>(count: usize, singular: &'a str, multiple: &'a str) -> &'a str {
    if count == 1 {
        singular
    } else {
        multiple
    }
}

fn append_recovery_preview(
    lines: &mut Vec<String>,
    draft: &ContextEditDraft,
    saved: &kuzushi_core::session_transcript::RecoveredContextDraft,
    width: usize,
) {
    let snapshot = saved.record.snapshot.as_ref().unwrap();
    if let Some(field) = snapshot
        .fields
        .iter()
        .find(|f| Some(&f.pointer) == snapshot.selected_pointer.as_ref())
    {
        let label = draft
            .entries
            .iter()
            .find(|e| e.pointer.as_ref() == Some(&field.pointer))
            .map_or("Saved field", |e| e.label.as_str());
        lines.extend(wrap_text(
            &format!("{label} · cursor {}", field.cursor),
            width,
        ));
        lines.extend(
            field
                .text
                .as_deref()
                .unwrap_or("")
                .lines()
                .take(2)
                .flat_map(|line| wrap_text(line, width))
                .take(2),
        );
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
