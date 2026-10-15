use super::*;
use crate::app::{ContextEditDraft, ContextEditMode, FieldEditor};
use kuzushi_core::session_transcript::{
    ContextDraftField, ContextDraftMode, ContextDraftSnapshot, DraftText,
};

pub(super) fn snapshot(draft: &ContextEditDraft) -> ContextDraftSnapshot {
    let name = &draft.entries[0];
    ContextDraftSnapshot {
        name: DraftText {
            text: name.text().into(),
            cursor: name.editor.as_ref().map_or(0, FieldEditor::cursor),
        },
        fields: draft.entries.iter().filter_map(field).collect(),
        selected_pointer: draft.entries[draft.cursor].pointer.clone(),
        scroll: draft.scroll,
        mode: saved_mode(draft.mode),
        origin_hashes: draft.checkpoint_origins.clone(),
    }
}

fn field(entry: &crate::app::ContextEditEntry) -> Option<ContextDraftField> {
    Some(ContextDraftField {
        pointer: entry.pointer.clone()?,
        text: entry.changed().then(|| entry.text().to_owned()),
        cursor: entry.editor.as_ref()?.cursor(),
    })
}

fn saved_mode(mode: ContextEditMode) -> ContextDraftMode {
    [
        (ContextEditMode::Writing, ContextDraftMode::Writing),
        (ContextEditMode::Review, ContextDraftMode::Review),
        (ContextEditMode::Saving, ContextDraftMode::Saving),
        (ContextEditMode::Discard, ContextDraftMode::Discard),
    ]
    .into_iter()
    .find_map(|(key, value)| (key == mode).then_some(value))
    .unwrap_or(ContextDraftMode::Fields)
}

pub(super) fn restore(
    draft: &ContextEditDraft,
    recovered: &RecoveredContextDraft,
) -> anyhow::Result<ContextEditDraft> {
    anyhow::ensure!(
        recovered.record.source == draft.reference,
        "Saved draft belongs to another context revision"
    );
    let snapshot = recovered
        .record
        .snapshot
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Saved draft is already resolved"))?;
    let mut next = draft.clone();
    set_editor(
        &mut next.entries[0],
        &snapshot.name.text,
        snapshot.name.cursor,
    )?;
    for field in &snapshot.fields {
        restore_field(&mut next, field)?;
    }
    next.cursor = next
        .entries
        .iter()
        .position(|entry| entry.pointer == snapshot.selected_pointer)
        .ok_or_else(|| anyhow::anyhow!("Saved field is missing from the inspected context"))?;
    next.scroll = snapshot.scroll;
    next.mode = restored_mode(snapshot.mode);
    next.checkpoint_origins = snapshot.origin_hashes.clone();
    next.checkpoint_origins.push(recovered.record_hash.clone());
    next.checkpoint_origins.sort();
    next.checkpoint_origins.dedup();
    next.recovery = Default::default();
    next.notice = Some("Recovered local draft. Review the context catalog before saving another copy. No context was accepted or work approved.".into());
    Ok(next)
}

fn restore_field(draft: &mut ContextEditDraft, field: &ContextDraftField) -> anyhow::Result<()> {
    let entry = draft
        .entries
        .iter_mut()
        .find(|entry| entry.pointer.as_deref() == Some(&field.pointer))
        .ok_or_else(|| anyhow::anyhow!("Saved field is missing from the inspected context"))?;
    let text = field.text.as_ref().unwrap_or(&entry.original).clone();
    set_editor(entry, &text, field.cursor)
}

fn set_editor(
    entry: &mut crate::app::ContextEditEntry,
    text: &str,
    cursor: usize,
) -> anyhow::Result<()> {
    let mut editor = FieldEditor::new(text);
    editor.restore_cursor(cursor)?;
    entry.editor = Some(editor);
    Ok(())
}

fn restored_mode(mode: ContextDraftMode) -> ContextEditMode {
    match mode {
        ContextDraftMode::Writing => ContextEditMode::Writing,
        ContextDraftMode::Review | ContextDraftMode::Saving => ContextEditMode::Review,
        _ => ContextEditMode::Fields,
    }
}
